package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type AssessmentJob struct {
	ID          int64
	Sensor      string
	Observation []byte
	Token       string
	Attempts    int
}

func (s *Store) EnqueueAssessment(ctx context.Context, sensor string, observation []byte) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `INSERT INTO assessment_jobs(sensor,observation,identity)
 VALUES($1,$2::jsonb,sha256(convert_to(jsonb_build_array($1::text,$2::jsonb)::text,'UTF8')))
 ON CONFLICT(identity) DO UPDATE SET identity=EXCLUDED.identity RETURNING id::text`, sensor, observation).Scan(&id)
	return id, err
}

func (s *Store) AssessmentStatus(ctx context.Context, sensor string, id int64) (json.RawMessage, error) {
	var value json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT jsonb_build_object('job_id',j.id::text,'status',j.status,'attempts',j.attempts,
 'last_error',j.last_error,'observation_id',j.observation_id::text,'assessment',o.assessment)
 FROM assessment_jobs j LEFT JOIN security_observations o ON o.id=j.observation_id WHERE j.id=$1 AND j.sensor=$2`, id, sensor).Scan(&value)
	return value, err
}

func (s *Store) ClaimAssessment(ctx context.Context, lease time.Duration) (*AssessmentJob, error) {
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	sql := `WITH next AS (
  SELECT id FROM assessment_jobs
  WHERE (status='pending' AND available_at<=clock_timestamp()) OR (status='leased' AND lease_until<=clock_timestamp())
  ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1
 )
 UPDATE assessment_jobs AS j SET status='leased',attempts=attempts+1,lease_token=$1,
 lease_until=clock_timestamp()+($2 * interval '1 millisecond')
 FROM next WHERE j.id=next.id RETURNING j.id,j.sensor,j.observation,j.lease_token,j.attempts`
	var job AssessmentJob
	err := s.Pool.QueryRow(ctx, sql, hex.EncodeToString(token[:]), lease.Milliseconds()).Scan(&job.ID, &job.Sensor, &job.Observation, &job.Token, &job.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (s *Store) FinishAssessment(ctx context.Context, job AssessmentJob, result []byte) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var id int64
	err = tx.QueryRow(ctx, `SELECT id FROM assessment_jobs WHERE id=$1 AND status='leased' AND lease_token=$2 AND lease_until>clock_timestamp() FOR UPDATE`, job.ID, job.Token).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	observationID, err := saveAssessment(ctx, tx, job.Sensor, job.Observation, result)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE assessment_jobs SET status='done', observation_id=$2::text::bigint, lease_token=NULL,
 lease_until=NULL,last_error=NULL WHERE id=$1`, id, observationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RetryAssessment(ctx context.Context, job AssessmentJob, delay time.Duration, reason string, terminal bool) error {
	status := "pending"
	if terminal {
		status = "failed"
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE assessment_jobs SET status=$3, lease_token=NULL, lease_until=NULL, last_error=$4,
 available_at=clock_timestamp()+($5 * interval '1 millisecond')
 WHERE id=$1 AND status='leased' AND lease_token=$2 AND lease_until>clock_timestamp()`, job.ID, job.Token, status, reason, delay.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}
