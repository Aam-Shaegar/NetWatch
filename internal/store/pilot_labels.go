package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrPilotLabel = errors.New("invalid pilot reference interval")

type PilotLabel struct {
	ID       string    `json:"id"`
	SensorID string    `json:"sensor_id"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Type     string    `json:"type"`
}

func (s *Store) AddPilotLabel(ctx context.Context, name, actor string, label PilotLabel) error {
	if !ValidPilotName(name) || !ValidPilotName(label.ID) || !sensorIDPattern.MatchString(label.SensorID) || !label.Start.Before(label.End) {
		return ErrPilotLabel
	}
	switch label.Type {
	case "normal", "tcp_port_scan", "udp_flood", "icmp_flood", "unknown":
	default:
		return ErrPilotLabel
	}
	// PostgreSQL stores timestamps to microseconds. Reject a narrower interval
	// rather than silently changing its boundaries or making retries disagree.
	if label.Start.Nanosecond()%1000 != 0 || label.End.Nanosecond()%1000 != 0 {
		return ErrPilotLabel
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var first, last time.Time
		// Serialize labels for one pilot to prevent concurrent overlapping entries.
		if err := tx.QueryRow(ctx, `SELECT greatest(p.started_at,s.registered_at),
		    least(statement_timestamp(),p.started_at+interval '168 hours',s.revoked_at)
		    FROM pilots p JOIN registered_sensors s ON s.id=$2 WHERE p.name=$1
		    FOR UPDATE OF p`, name, label.SensorID).Scan(&first, &last); err != nil {
			return err
		}
		if label.Start.Before(first) || label.End.After(last) {
			return ErrPilotLabel
		}
		var same bool
		err := tx.QueryRow(ctx, `SELECT id=$3 AND starts_at=$4 AND ends_at=$5 AND kind=$6
		    FROM pilot_labels WHERE pilot_name=$1 AND sensor_id=$2
		    AND (id=$3 OR (starts_at<$5 AND ends_at>$4)) LIMIT 1`,
			name, label.SensorID, label.ID, label.Start, label.End, label.Type).Scan(&same)
		if err == nil {
			if same {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pilot_labels(pilot_name,sensor_id,id,starts_at,ends_at,kind,operator_id)
		    VALUES($1,$2,$3,$4,$5,$6,$7)`, name, label.SensorID, label.ID, label.Start, label.End, label.Type, actor)
		return err
	})
}
