package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/catalog"
	"netwatch.local/netwatch/internal/contract"
)

// RegisterCatalogPolicy binds a policy ID to an immutable ruleset configuration.
func (s *Store) RegisterCatalogPolicy(ctx context.Context, version string, rules map[string]catalog.RuleSetting) error {
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO catalog_policy_settings(policy_version,rules) VALUES($1,$2)
 ON CONFLICT DO NOTHING`, version, raw); err != nil {
		return err
	}
	var matches bool
	if err := s.Pool.QueryRow(ctx, `SELECT rules=$2::jsonb FROM catalog_policy_settings WHERE policy_version=$1`,
		version, raw).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("catalog policy rules differ from the registered policy version")
	}
	return nil
}

func (s *Store) CatalogHistory(ctx context.Context, w contract.Window) ([]contract.Window, error) {
	start, err := strconv.ParseInt(w.WindowStartNS, 10, 64)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT payload FROM feature_windows
 WHERE sensor_id=$1 AND window_end_ns>$2 AND window_end_ns<=$3
 AND payload->>'capture_epoch'=$4 AND payload->>'entity_id'=$5 AND payload->>'entity_type'='host'
 AND payload->>'feature_set_version'=$6 AND payload->'quality'->>'coverage'='complete'
 AND payload->'quality'->>'capture_dropped'='0' AND payload->'quality'->>'late_packets'='0'
 AND payload->'quality'->>'state_evictions'='0'
 ORDER BY window_end_ns DESC,event_id DESC LIMIT $7`, w.SensorID, start-int64(catalog.HistoryAge), start,
		w.CaptureEpoch, w.EntityID, catalog.FeatureSet, catalog.HistoryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var history []contract.Window
	for rows.Next() {
		var window contract.Window
		if err := rows.Scan(&window); err != nil {
			return nil, err
		}
		history = append(history, window)
	}
	return history, rows.Err()
}

func (s *Store) CatalogGatePassed(ctx context.Context, j Job) (bool, error) {
	var passed bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM catalog_decisions
 WHERE event_id=$1 AND model_id=$2 AND policy_version=$3 AND status='no_match')`,
		j.EventID, j.ModelID, j.PolicyVersion).Scan(&passed)
	return passed, err
}

// CatalogTemporalHistory freezes the causal input of a pending ML decision. Ingress may
// deliver older windows during an outage; a retry must use the same sample as the first call.
func (s *Store) CatalogTemporalHistory(ctx context.Context, j Job, w contract.Window) (json.RawMessage, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var snapshot json.RawMessage
	err = tx.QueryRow(ctx, `SELECT d.payload->'history' FROM inference_jobs j
 JOIN catalog_decisions d USING(event_id,model_id,policy_version)
 WHERE j.event_id=$1 AND j.model_id=$2 AND j.policy_version=$3 AND d.status='no_match'
 AND j.status='leased' AND j.lease_token=$4 AND j.lease_until>clock_timestamp() FOR UPDATE OF j`,
		j.EventID, j.ModelID, j.PolicyVersion, j.Token).Scan(&snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLeaseLost
	}
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		snapshot, err = temporalPredecessors(ctx, tx, w)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `UPDATE catalog_decisions SET payload=jsonb_set(payload,'{history}',$4::jsonb)
 WHERE event_id=$1 AND model_id=$2 AND policy_version=$3`, j.EventID, j.ModelID, j.PolicyVersion, snapshot)
		if err != nil {
			return nil, err
		}
	}
	return snapshot, tx.Commit(ctx)
}

func temporalPredecessors(ctx context.Context, tx pgx.Tx, w contract.Window) (json.RawMessage, error) {
	const step = int64(5 * time.Second)
	const limit = 5 // The sixth window is the observation being scored.
	start, err := strconv.ParseInt(w.WindowStartNS, 10, 64)
	if err != nil {
		return nil, err
	}
	// Read original observations, including rule matches and quality failures, regardless
	// of which worker has already completed their jobs. One extra row detects an
	// ambiguous oldest slot (two different event IDs at the same time).
	rows, err := tx.Query(ctx, `SELECT window_start_ns,window_end_ns,payload FROM feature_windows
 WHERE sensor_id=$1 AND window_end_ns>$2 AND window_end_ns<=$3 AND payload->>'capture_epoch'=$4
 AND payload->>'entity_type'=$5 AND payload->>'entity_id'=$6 AND payload->>'feature_set_version'=$7
 ORDER BY window_end_ns DESC,event_id DESC LIMIT $8`, w.SensorID, start-limit*step, start,
		w.CaptureEpoch, w.EntityType, w.EntityID, w.FeatureSetVersion, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type measurement struct {
		start, end int64
		payload    json.RawMessage
	}
	var prior []measurement
	for rows.Next() {
		var previous measurement
		if err := rows.Scan(&previous.start, &previous.end, &previous.payload); err != nil {
			return nil, err
		}
		prior = append(prior, previous)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	history := make([]json.RawMessage, 0, limit)
	for i, previous := range prior {
		if len(history) == limit || previous.end != start || previous.start != start-step ||
			(i+1 < len(prior) && prior[i+1].end > previous.start) {
			break
		}
		history = append(history, previous.payload)
		start = previous.start
	}
	slices.Reverse(history)
	return json.Marshal(history)
}

// RecordCatalog binds the rule decision and the final ML result to the same leased job.
// A saved no-match survives inference outages without rerunning rules against a changed baseline.
func (s *Store) RecordCatalog(ctx context.Context, j Job, w contract.Window, decision catalog.Decision, details json.RawMessage) error {
	if decision.EventID != j.EventID || w.EventID != j.EventID || w.FeatureSetVersion != catalog.FeatureSet {
		return fmt.Errorf("catalog decision identity mismatch")
	}
	if decision.Status == catalog.Incident && (decision.AttackType == nil ||
		(!catalog.KnownType(*decision.AttackType) && (*decision.AttackType != catalog.Unknown || decision.Source != "ml")) ||
		(decision.Source != "rules" && decision.Source != "ml") || decision.DetectorVersion == "") {
		return fmt.Errorf("invalid incident decision")
	}
	if decision.Status != catalog.Incident && decision.AttackType != nil {
		return fmt.Errorf("unexpected attack type")
	}
	raw, err := json.Marshal(struct {
		catalog.Decision
		Details json.RawMessage `json:"details,omitempty"`
	}{decision, details})
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT event_id FROM inference_jobs
 WHERE event_id=$1 AND model_id=$2 AND policy_version=$3 AND status='leased' AND lease_token=$4
 AND lease_until>clock_timestamp() FOR UPDATE`, j.EventID, j.ModelID, j.PolicyVersion, j.Token).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	var incident *int64
	if decision.Status == catalog.Incident {
		id, err := projectCatalogIncident(ctx, tx, j, w, decision)
		if err != nil {
			return err
		}
		incident = &id
	}
	var saved int64
	if decision.Source == "ml" {
		tag, err := tx.Exec(ctx, `UPDATE catalog_decisions SET status=$4,payload=$5,incident_id=$6,decided_at=clock_timestamp()
 WHERE event_id=$1 AND model_id=$2 AND policy_version=$3 AND status='no_match'`,
			j.EventID, j.ModelID, j.PolicyVersion, decision.Status, raw, incident)
		if err != nil {
			return err
		}
		saved = tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx, `INSERT INTO catalog_decisions(event_id,model_id,policy_version,status,payload,incident_id)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, j.EventID, j.ModelID, j.PolicyVersion, decision.Status, raw, incident)
		if err != nil {
			return err
		}
		saved = tag.RowsAffected()
	}
	if saved != 1 {
		return ErrConflict
	}
	if decision.Status != catalog.NoMatch {
		if _, err := tx.Exec(ctx, `UPDATE inference_jobs SET status='done',lease_token=NULL,lease_until=NULL,last_error=NULL,
 updated_at=clock_timestamp() WHERE event_id=$1 AND model_id=$2 AND policy_version=$3`,
			j.EventID, j.ModelID, j.PolicyVersion); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func projectCatalogIncident(ctx context.Context, tx pgx.Tx, j Job, w contract.Window, d catalog.Decision) (int64, error) {
	keyParts, _ := json.Marshal([]string{w.SensorID, w.CaptureEpoch, w.EntityType, w.EntityID, *d.AttackType, d.Source, d.DetectorVersion, j.PolicyVersion})
	key := string(keyParts)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,712743))`, key); err != nil {
		return 0, err
	}
	start, startErr := strconv.ParseInt(w.WindowStartNS, 10, 64)
	end, endErr := strconv.ParseInt(w.WindowEndNS, 10, 64)
	if startErr != nil || endErr != nil || start < 0 || end <= start {
		return 0, fmt.Errorf("invalid incident interval")
	}
	const gap = int64(5 * time.Second)
	cutoff := min(end, math.MaxInt64-gap) + gap
	rows, err := tx.Query(ctx, `SELECT id,first_ns,last_ns FROM catalog_incidents
 WHERE stream_key=$1 AND first_ns<=$2 AND last_ns>=$3 ORDER BY id FOR UPDATE`, key, cutoff, start-gap)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id, first, last int64
		if err := rows.Scan(&id, &first, &last); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
		start, end = min(start, first), max(end, last)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		var id int64
		err := tx.QueryRow(ctx, `INSERT INTO catalog_incidents(stream_key,sensor_id,entity_id,attack_type,source,detector_version,first_ns,last_ns)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, key, w.SensorID, w.EntityID, *d.AttackType, d.Source, d.DetectorVersion, start, end).Scan(&id)
		return id, err
	}
	if _, err := tx.Exec(ctx, `UPDATE catalog_incidents SET first_ns=$2,last_ns=$3,updated_at=clock_timestamp() WHERE id=$1`,
		ids[0], start, end); err != nil {
		return 0, err
	}
	if len(ids) > 1 {
		if _, err := tx.Exec(ctx, `UPDATE catalog_decisions SET incident_id=$1 WHERE incident_id=ANY($2)`, ids[0], ids[1:]); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM catalog_incidents WHERE id=ANY($1)`, ids[1:]); err != nil {
			return 0, err
		}
	}
	return ids[0], nil
}

func (s *Store) CatalogIncidents(ctx context.Context) (json.RawMessage, error) {
	var result json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'total',(SELECT count(*) FROM catalog_incidents),
 'by_type',COALESCE((SELECT jsonb_object_agg(attack_type,n) FROM (SELECT attack_type,count(*) n FROM catalog_incidents GROUP BY attack_type) t),'{}'::jsonb),
 'by_source',COALESCE((SELECT jsonb_object_agg(source,n) FROM (SELECT source,count(*) n FROM catalog_incidents GROUP BY source) s),'{}'::jsonb),
 'incidents',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',id,'type',attack_type,'source',source,'sensor_id',sensor_id,
  'entity_id',entity_id,'first_ns',first_ns::text,'last_ns',last_ns::text,'detector_version',detector_version) ORDER BY last_ns DESC,id DESC)
  FROM (SELECT * FROM catalog_incidents ORDER BY last_ns DESC,id DESC LIMIT 20) recent),'[]'::jsonb))`).Scan(&result)
	return result, err
}
