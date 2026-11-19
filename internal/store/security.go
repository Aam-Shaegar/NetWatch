package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

func (s *Store) SaveAssessment(ctx context.Context, sensor string, observation, assessment []byte) (string, error) {
	return saveAssessment(ctx, s.Pool, sensor, observation, assessment)
}

type assessmentWriter interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func saveAssessment(ctx context.Context, db assessmentWriter, sensor string, observation, assessment []byte) (string, error) {
	var id string
	// PostgreSQL normalizes object order before hashing. A new ruleset may
	// reassess the same input while retries of that ruleset keep their receipt.
	err := db.QueryRow(ctx, `INSERT INTO security_observations(sensor,observation,assessment,identity)
 VALUES($1,$2::jsonb,$3::jsonb,sha256(convert_to(jsonb_build_array($1::text,$2::jsonb,$3::jsonb->>'ruleset')::text,'UTF8')))
 ON CONFLICT(identity) DO UPDATE SET identity=EXCLUDED.identity WHERE security_observations.assessment=EXCLUDED.assessment RETURNING id::text`, sensor, observation, assessment).Scan(&id)
	return id, err
}
func (s *Store) Assessments(ctx context.Context, before int64, entity string) ([]json.RawMessage, error) {
	rows, err := s.Pool.Query(ctx, `SELECT jsonb_build_object('id',id::text,'sensor',sensor,'observation',observation,'assessment',assessment)
 FROM security_observations WHERE ($1::bigint=0 OR id<$1) AND ($2='' OR observation->>'entity'=$2) ORDER BY id DESC LIMIT 51`, before, entity)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
}
