package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/incidents"
)

// Project advances a bounded prefix of one stream. A row lock serializes workers.
// An earlier admitted job without a prediction blocks only its own stream.
func (s *Store) Project(ctx context.Context) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	var sid int64
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT s.stream_id,s.state FROM incident_streams s JOIN LATERAL
 (SELECT event_id,model_id,policy_version,start_ns FROM incident_queue WHERE stream_id=s.stream_id ORDER BY start_ns,event_id LIMIT 1) q ON true
 JOIN predictions p ON (p.event_id,p.model_id,p.policy_version)=(q.event_id,q.model_id,q.policy_version) ORDER BY q.start_ns,s.stream_id FOR UPDATE OF s SKIP LOCKED LIMIT 1`).Scan(&sid, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state incidents.State
	if err = json.Unmarshal(raw, &state); err != nil {
		return false, err
	}
	rows, err := tx.Query(ctx, `SELECT q.event_id,q.start_ns,w.window_end_ns,p.payload->>'status',(p.payload->>'score')::float8,(p.payload->>'threshold')::float8
 FROM incident_queue q JOIN feature_windows w USING(event_id) LEFT JOIN predictions p USING(event_id,model_id,policy_version)
 WHERE stream_id=$1 ORDER BY q.start_ns,q.event_id LIMIT 128`, sid)
	if err != nil {
		return false, err
	}
	var points []incidents.Point
	for rows.Next() {
		var p incidents.Point
		var status *string
		if err = rows.Scan(&p.ID, &p.Start, &p.End, &status, &p.Score, &p.Threshold); err != nil {
			rows.Close()
			return false, err
		}
		if status == nil {
			break
		}
		p.Status = *status
		points = append(points, p)
	}
	rows.Close()
	if rows.Err() != nil {
		return false, rows.Err()
	}
	link := func(id int64, event, kind string) error {
		_, e := tx.Exec(ctx, "INSERT INTO incident_events VALUES($1,$2,$3)", id, event, kind)
		return e
	}
	for _, p := range points {
		c := state.Observe(p)
		if c.Kind == "opened" {
			first := c.Open[0].Start
			for _, v := range c.Open {
				if v.Signal() {
					first = v.Start
					break
				}
			}
			err = tx.QueryRow(ctx, `INSERT INTO incidents(stream_id,first_ns,detected_ns,last_ns) VALUES($1,$2,$3,$3) RETURNING id`, sid, first, p.End).Scan(&state.Active)
			if err != nil {
				return false, err
			}
			for _, v := range c.Open {
				kind := "observed"
				if v.Signal() {
					kind = "signal"
				}
				if v.ID == p.ID {
					kind = "opened"
				}
				if err = link(state.Active, v.ID, kind); err != nil {
					return false, err
				}
			}
		} else if c.Kind != "" {
			if err = link(state.Active, p.ID, c.Kind); err != nil {
				return false, err
			}
			_, err = tx.Exec(ctx, `UPDATE incidents SET last_ns=$2,closed_ns=CASE WHEN $3 THEN $2::bigint ELSE NULL END WHERE id=$1`, state.Active, p.End, c.Kind == "closed")
			if err != nil {
				return false, err
			}
			if c.Kind == "closed" {
				state.Active = 0
			}
		}
		if _, err = tx.Exec(ctx, "DELETE FROM incident_queue WHERE stream_id=$1 AND event_id=$2", sid, p.ID); err != nil {
			return false, err
		}
	}
	raw, err = json.Marshal(state)
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "UPDATE incident_streams SET state=$2 WHERE stream_id=$1", sid, raw); err != nil {
		return false, err
	}
	return len(points) > 0, tx.Commit(ctx)
}

type IncidentFilter struct {
	Entity, Model       string
	From, Until, Before int64
}

const incidentFields = `jsonb_build_object('id',i.id::text,'sensor',s.sensor_id,'epoch',s.epoch,'entity',s.entity_id,
 'entity_type',s.entity_type,'model',s.model_id,'policy',s.policy_version,'first_ns',i.first_ns::text,
 'detected_ns',i.detected_ns::text,'detected_at',i.detected_at,'last_ns',i.last_ns::text,'closed_ns',i.closed_ns::text,
 'ack_at',i.ack_at,'ack_by',i.ack_by)`

func (s *Store) IncidentList(ctx context.Context, f IncidentFilter) ([]json.RawMessage, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+incidentFields+` FROM incidents i JOIN incident_streams s USING(stream_id)
 WHERE ($1='' OR s.entity_id=$1) AND ($2='' OR s.model_id=$2) AND i.detected_ns >= $3
 AND ($4::bigint=0 OR i.detected_ns<$4) AND ($5::bigint=0 OR i.id<$5) ORDER BY i.id DESC LIMIT 51`, f.Entity, f.Model, f.From, f.Until, f.Before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
}

// JournalStatus reports pipeline-wide work, independently of the incident filters.
func (s *Store) JournalStatus(ctx context.Context) (pending, retrying bool, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM incident_queue),
 EXISTS(SELECT FROM inference_jobs WHERE status <> 'done' AND last_error IS NOT NULL AND last_error <> '')`).Scan(&pending, &retrying)
	return
}

func (s *Store) Incident(ctx context.Context, id, after int64) (map[string]any, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var header json.RawMessage
	if err = tx.QueryRow(ctx, "SELECT "+incidentFields+" FROM incidents i JOIN incident_streams s USING(stream_id) WHERE i.id=$1", id).Scan(&header); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT jsonb_build_object('event',w.event_id,'kind',e.kind,'start_ns',w.window_start_ns::text,
 'end_ns',w.window_end_ns::text,'features',w.payload->'features','quality',w.payload->'quality','prediction',p.payload)
 FROM incidents i JOIN incident_streams s USING(stream_id) JOIN incident_events e ON e.incident_id=i.id
 JOIN feature_windows w USING(event_id) JOIN predictions p ON p.event_id=e.event_id AND p.model_id=s.model_id AND p.policy_version=s.policy_version
 WHERE i.id=$1 AND w.window_start_ns>$2 ORDER BY w.window_start_ns LIMIT 201`, id, after)
	if err != nil {
		return nil, err
	}
	events, err := pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
	if err != nil {
		return nil, err
	}
	more := len(events) > 200
	if more {
		events = events[:200]
	}
	return map[string]any{"schema_version": 1, "feature_set_version": "traffic-v1", "rule": "two_of_three_close_three_at_95pct", "incident": header, "events": events, "more": more}, tx.Commit(ctx)
}
func (s *Store) AckIncident(ctx context.Context, id int64, actor string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE incidents SET ack_by=COALESCE(ack_by,$2),ack_at=COALESCE(ack_at,clock_timestamp()) WHERE id=$1`, id, actor)
	if err == nil && tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}
