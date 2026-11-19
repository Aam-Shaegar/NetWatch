package store

import (
	"context"
	"encoding/json"
)

// PipelineStatus combines durable queue health with the last observations for the active target.
// It reports receipt and event ages separately so that replay or delayed delivery cannot look live.
func (s *Store) PipelineStatus(ctx context.Context, model, policy string) (json.RawMessage, error) {
	var metrics json.RawMessage
	err := s.Pool.QueryRow(ctx, `WITH snapshot AS (SELECT statement_timestamp() AS at)
 SELECT jsonb_build_object(
 'observed_at',snapshot.at,
 'target',jsonb_build_object('model_id',$1::text,'policy_version',$2::text),
 'capture',(SELECT jsonb_build_object('sensor_id',sensor_id,'received_at',received_at,
   'receipt_age_s',extract(epoch FROM snapshot.at-received_at),
   'event_age_s',extract(epoch FROM snapshot.at)-window_end_ns/1e9,
   'quality',payload->'quality','feature_set_version',payload->>'feature_set_version')
  FROM feature_windows ORDER BY received_at DESC,event_id DESC LIMIT 1),
 'prediction',(SELECT jsonb_build_object('status',payload->>'status',
   'unavailable_reason',coalesce(payload->>'unavailable_reason',payload->>'reason'),
   'processed_at',processed_at,'age_s',extract(epoch FROM snapshot.at-processed_at))
  FROM predictions WHERE model_id=$1 AND policy_version=$2 ORDER BY processed_at DESC,event_id DESC LIMIT 1),
 'usable_prediction',(SELECT jsonb_build_object('processed_at',p.processed_at,
   'event_age_s',extract(epoch FROM snapshot.at)-w.window_end_ns/1e9,
   'processing_delay_s',extract(epoch FROM p.processed_at)-w.window_end_ns/1e9)
  FROM predictions p JOIN feature_windows w USING(event_id) WHERE p.model_id=$1 AND p.policy_version=$2
   AND p.payload->>'status' IN ('normal','anomalous') ORDER BY p.processed_at DESC,p.event_id DESC LIMIT 1),
 'inference',(SELECT jsonb_build_object('queued',count(*),'retrying',count(*) FILTER (WHERE last_error IS NOT NULL),
   'oldest_age_s',extract(epoch FROM snapshot.at-min(created_at))) FROM inference_jobs WHERE status<>'done'),
 'assessment',(SELECT jsonb_build_object('queued',count(*) FILTER (WHERE status IN ('pending','leased')),
   'retrying',count(*) FILTER (WHERE status='pending' AND last_error IS NOT NULL),
   'failed',count(*) FILTER (WHERE status='failed'),
   'oldest_age_s',extract(epoch FROM snapshot.at-min(received_at) FILTER (WHERE status IN ('pending','leased'))))
  FROM assessment_jobs WHERE status<>'done'),
 'projection_pending',(SELECT count(*) FROM incident_queue),
 'projection_oldest_age_s',(SELECT extract(epoch FROM snapshot.at-min(j.created_at))
  FROM incident_queue q JOIN inference_jobs j USING(event_id,model_id,policy_version)),
 'projection_gaps',(SELECT coalesce(sum((state->>'Missing')::bigint),0) FROM incident_streams)) FROM snapshot`, model, policy).Scan(&metrics)
	return metrics, err
}
