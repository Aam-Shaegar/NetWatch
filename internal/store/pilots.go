package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	pilotNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	ErrPilotName     = errors.New("invalid pilot name")
)

//go:embed pilot_report.sql
var pilotReportSQL string

func ValidPilotName(name string) bool {
	return pilotNamePattern.MatchString(name)
}

type pilotPeriod struct {
	Name      string    `json:"name"`
	StartedAt time.Time `json:"started_at"`
	EndsAt    time.Time `json:"ends_at"`
	Model     string    `json:"model_id"`
	Policy    string    `json:"policy_version"`
}

const selectPilot = `SELECT name,started_at,model_id,policy_version,statement_timestamp()
                     FROM pilots WHERE name=$1`

func readPilot(row pgx.Row) (pilotPeriod, time.Time, error) {
	var p pilotPeriod
	var now time.Time
	err := row.Scan(&p.Name, &p.StartedAt, &p.Model, &p.Policy, &now)
	p.StartedAt = p.StartedAt.UTC()
	p.EndsAt = p.StartedAt.Add(7 * 24 * time.Hour)
	return p, now.UTC(), err
}

// StartPilot preserves the original target and observation period on retry.
// The separate SELECT sees the winning insertion after a concurrent conflict.
func (s *Store) StartPilot(ctx context.Context, name, model, policy string) (json.RawMessage, error) {
	if !ValidPilotName(name) {
		return nil, ErrPilotName
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO pilots(name,model_id,policy_version)
		VALUES ($1,$2,$3) ON CONFLICT (name) DO NOTHING`, name, model, policy)
	if err != nil {
		return nil, err
	}
	p, _, err := readPilot(s.Pool.QueryRow(ctx, selectPilot, name))
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func (s *Store) PilotReport(ctx context.Context, name string) (json.RawMessage, error) {
	if !ValidPilotName(name) {
		return nil, ErrPilotName
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	p, now, err := readPilot(tx.QueryRow(ctx, selectPilot, name))
	if err != nil {
		return nil, err
	}
	report := struct {
		pilotPeriod
		AsOf     time.Time       `json:"as_of"`
		Complete bool            `json:"complete"`
		Sensors  json.RawMessage `json:"sensors"`
		Analyzer json.RawMessage `json:"analyzer"`
	}{pilotPeriod: p, AsOf: now, Complete: !now.Before(p.EndsAt)}
	if report.Complete {
		report.AsOf = p.EndsAt
	}
	err = tx.QueryRow(ctx, pilotReportSQL, p.StartedAt, report.AsOf, p.Model, p.Policy, p.Name).Scan(&report.Sensors, &report.Analyzer)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}
