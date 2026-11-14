// Package store owns transactional ingestion and fenced inference jobs in PostgreSQL.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/transport"
	"netwatch.local/netwatch/migrations"
)

var ErrConflict = errors.New("event or batch identity conflicts with stored content")
var ErrLeaseLost = errors.New("job lease is no longer owned")

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	c, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration")
	}
	c.MaxConns = 10
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("database pool unavailable")
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unavailable")
	}
	return &Store{pool}, nil
}
func (s *Store) Close() { s.Pool.Close() }
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(674328611)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version bigint PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	for index, file := range migrationFiles {
		sql, err := migrations.Files.ReadFile(file)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(sql)
		sum := hex.EncodeToString(hash[:])
		var stored string
		err = tx.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, index+1).Scan(&stored)
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err = tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)`, index+1, sum); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if stored != sum {
			return fmt.Errorf("applied migration checksum differs")
		}
	}
	return tx.Commit(ctx)
}

var migrationFiles = []string{"000001_pipeline.up.sql", "000002_incidents.up.sql"}

func (s *Store) Ready(ctx context.Context) error {
	for i, file := range migrationFiles {
		sql, err := migrations.Files.ReadFile(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(sql)
		var ok bool
		if err = s.Pool.QueryRow(ctx, `SELECT checksum=$2 FROM schema_migrations WHERE version=$1`, i+1, hex.EncodeToString(sum[:])).Scan(&ok); err != nil || !ok {
			return fmt.Errorf("database schema not ready")
		}
	}
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT bool_and(to_regclass(name) IS NOT NULL) FROM unnest(ARRAY['feature_windows','inference_jobs','ingestion_batches','predictions','incidents','incident_queue','incident_events','incident_streams']) name`).Scan(&ok)
	if err != nil || !ok {
		return fmt.Errorf("database schema not ready")
	}
	return nil
}

// Ingest commits receipt, new windows and their jobs together; duplicates do not reschedule.
func (s *Store) Ingest(ctx context.Context, b transport.Batch, sensor, model, policy string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
		return err
	}
	ids := make([]string, 0, len(b.Windows))
	windows := make(map[string]json.RawMessage, len(b.Windows))
	for _, raw := range b.Windows {
		var w contract.Window
		if err = json.Unmarshal(raw, &w); err != nil {
			return err
		}
		ids = append(ids, w.EventID)
		windows[w.EventID] = raw
	}
	loss, err := json.Marshal(b.QueueLoss)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO ingestion_batches(sensor_id,batch_id,event_ids,queue_loss) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, sensor, b.BatchID, ids, loss); err != nil {
		return err
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT event_ids=$3 AND queue_loss=$4::jsonb FROM ingestion_batches WHERE sensor_id=$1 AND batch_id=$2`, sensor, b.BatchID, ids, loss).Scan(&same); err != nil {
		return err
	}
	if !same {
		return ErrConflict
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		raw := windows[id]
		var w contract.Window
		json.Unmarshal(raw, &w)
		start, _ := strconv.ParseInt(w.WindowStartNS, 10, 64)
		end, _ := strconv.ParseInt(w.WindowEndNS, 10, 64)
		inserted, e := tx.Exec(ctx, `INSERT INTO feature_windows(event_id,sensor_id,window_start_ns,window_end_ns,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, id, sensor, start, end, raw)
		if e != nil {
			return e
		}
		if e = tx.QueryRow(ctx, `SELECT sensor_id=$2 AND payload=$3::jsonb FROM feature_windows WHERE event_id=$1`, id, sensor, raw).Scan(&same); e != nil {
			return e
		}
		if !same {
			return ErrConflict
		}
		if inserted.RowsAffected() == 1 {
			if _, e = tx.Exec(ctx, `INSERT INTO inference_jobs(event_id,model_id,policy_version) VALUES($1,$2,$3)`, id, model, policy); e != nil {
				return e
			}
		}
	}
	return tx.Commit(ctx)
}

type Job struct {
	EventID       string
	ModelID       string
	PolicyVersion string
	Token         string
	Attempts      int64
	Window        json.RawMessage
}

func (s *Store) Claim(ctx context.Context, lease time.Duration, oldest bool) (*Job, error) {
	if lease < time.Millisecond || lease > time.Hour {
		return nil, fmt.Errorf("invalid lease duration")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	order := "w.window_end_ns DESC,j.created_at,j.event_id"
	if oldest {
		order = "j.created_at,j.event_id"
	}
	sql := `WITH candidate AS (
 SELECT j.event_id,j.model_id,j.policy_version FROM inference_jobs j JOIN feature_windows w USING(event_id)
 WHERE (j.status='pending' AND j.available_at<=clock_timestamp()) OR (j.status='leased' AND j.lease_until<=clock_timestamp())
 ORDER BY ` + order + ` FOR UPDATE OF j SKIP LOCKED LIMIT 1)
 UPDATE inference_jobs j SET status='leased',lease_token=$1,lease_until=clock_timestamp()+($2 * interval '1 millisecond'),attempts=attempts+1,updated_at=clock_timestamp()
 FROM candidate c,feature_windows w WHERE j.event_id=c.event_id AND j.model_id=c.model_id AND j.policy_version=c.policy_version AND w.event_id=j.event_id
 RETURNING j.event_id,j.model_id,j.policy_version,j.lease_token,j.attempts,w.payload`
	var job Job
	err := s.Pool.QueryRow(ctx, sql, hex.EncodeToString(token[:]), lease.Milliseconds()).Scan(&job.EventID, &job.ModelID, &job.PolicyVersion, &job.Token, &job.Attempts, &job.Window)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}
func (s *Store) Finish(ctx context.Context, j Job, p contract.Prediction) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err = contract.Validate("prediction", raw); err != nil {
		return err
	}
	if p.EventID != j.EventID || p.ModelID != j.ModelID {
		return fmt.Errorf("prediction identity mismatch")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SET LOCAL synchronous_commit=on`); err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT event_id FROM inference_jobs WHERE event_id=$1 AND model_id=$2 AND policy_version=$3 AND status='leased' AND lease_token=$4 AND lease_until>clock_timestamp() FOR UPDATE`, j.EventID, j.ModelID, j.PolicyVersion, j.Token).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO predictions(event_id,model_id,policy_version,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, j.EventID, j.ModelID, j.PolicyVersion, raw); err != nil {
		return err
	}
	var same bool
	if err = tx.QueryRow(ctx, `SELECT payload=$4::jsonb FROM predictions WHERE event_id=$1 AND model_id=$2 AND policy_version=$3`, j.EventID, j.ModelID, j.PolicyVersion, raw).Scan(&same); err != nil {
		return err
	}
	if !same {
		return ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE inference_jobs SET status='done',lease_token=NULL,lease_until=NULL,last_error=NULL,updated_at=clock_timestamp() WHERE event_id=$1 AND model_id=$2 AND policy_version=$3`, j.EventID, j.ModelID, j.PolicyVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Retry(ctx context.Context, j Job, delay time.Duration, reason string) error {
	if delay < 0 || delay > time.Hour {
		return fmt.Errorf("invalid retry delay")
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE inference_jobs SET status='pending',lease_token=NULL,lease_until=NULL,available_at=clock_timestamp()+($5 * interval '1 millisecond'),last_error=$6,updated_at=clock_timestamp() WHERE event_id=$1 AND model_id=$2 AND policy_version=$3 AND status='leased' AND lease_token=$4 AND lease_until>clock_timestamp()`, j.EventID, j.ModelID, j.PolicyVersion, j.Token, delay.Milliseconds(), reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (s *Store) Window(ctx context.Context, sensor, id string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT payload FROM feature_windows WHERE sensor_id=$1 AND event_id=$2`, sensor, id).Scan(&raw)
	return raw, err
}
func (s *Store) Predictions(ctx context.Context, sensor, id string) ([]json.RawMessage, error) {
	rows, err := s.Pool.Query(ctx, `SELECT jsonb_build_object('prediction',p.payload,'policy_version',p.policy_version,'processed_at',p.processed_at) FROM predictions p JOIN feature_windows w USING(event_id) WHERE w.sensor_id=$1 AND p.event_id=$2 ORDER BY p.processed_at DESC,p.model_id LIMIT 100`, sensor, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
