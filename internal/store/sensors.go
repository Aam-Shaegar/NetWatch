package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/spool"
)

var (
	ErrSensorInput   = errors.New("invalid sensor identifier or action")
	ErrSensorState   = errors.New("action is unavailable for the current sensor state")
	ErrSensorUnknown = errors.New("sensor, registration code, or credential is invalid")
	sensorIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type RegisteredSensor struct {
	ID         string      `json:"id"`
	State      string      `json:"state"`
	LastSeenAt *time.Time  `json:"last_seen_at"`
	QueueLoss  *spool.Loss `json:"queue_loss,omitempty"`
}

type SensorRegistration struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) ListSensors(ctx context.Context) ([]RegisteredSensor, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, state, last_seen_at, queue_loss FROM registered_sensors
		UNION ALL
		SELECT sensor_id, 'pending', NULL, NULL FROM sensor_registrations
		WHERE consumed_at IS NULL AND expires_at > clock_timestamp()
		ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RegisteredSensor, 0)
	for rows.Next() {
		var sensor RegisteredSensor
		if err := rows.Scan(&sensor.ID, &sensor.State, &sensor.LastSeenAt, &sensor.QueueLoss); err != nil {
			return nil, err
		}
		result = append(result, sensor)
	}
	return result, rows.Err()
}

func (s *Store) CreateSensorRegistration(ctx context.Context, id string) (SensorRegistration, error) {
	if !sensorIDPattern.MatchString(id) {
		return SensorRegistration{}, ErrSensorInput
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return SensorRegistration{}, err
	}
	code := hex.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(code))
	registration := SensorRegistration{ID: id, Code: code}
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO sensor_registrations(sensor_id, code_hash, expires_at)
		VALUES ($1, $2, clock_timestamp() + interval '15 minutes')
		ON CONFLICT (sensor_id) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at
		WHERE sensor_registrations.consumed_at IS NULL
		  AND sensor_registrations.expires_at <= clock_timestamp()
		RETURNING expires_at`, id, hash[:]).Scan(&registration.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SensorRegistration{}, ErrSensorState
	}
	if err != nil {
		return SensorRegistration{}, err
	}
	return registration, nil
}

// EnrollSensor consumes an invitation and installs the credential in one
// transaction. A client that loses its response recovers by authenticating
// with the same separately generated credential via Contact.
func (s *Store) EnrollSensor(ctx context.Context, codeHash, credentialHash [32]byte) (RegisteredSensor, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return RegisteredSensor{}, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit=on"); err != nil {
		return RegisteredSensor{}, err
	}
	var id string
	err = tx.QueryRow(ctx, `
		UPDATE sensor_registrations SET consumed_at=clock_timestamp()
		WHERE code_hash=$1 AND consumed_at IS NULL AND expires_at > clock_timestamp()
		RETURNING sensor_id`, codeHash[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return RegisteredSensor{}, ErrSensorUnknown
	}
	if err != nil {
		return RegisteredSensor{}, err
	}
	sensor := RegisteredSensor{ID: id, State: "active"}
	if err = tx.QueryRow(ctx, `
		INSERT INTO registered_sensors(id, token_hash) VALUES ($1,$2)
		RETURNING last_seen_at`, id, credentialHash[:]).Scan(&sensor.LastSeenAt); err != nil {
		return RegisteredSensor{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return RegisteredSensor{}, err
	}
	return sensor, nil
}

func (s *Store) ContactSensor(ctx context.Context, credentialHash [32]byte, loss *spool.Loss) (RegisteredSensor, error) {
	var sensor RegisteredSensor
	var raw []byte
	if loss != nil {
		var err error
		raw, err = json.Marshal(loss)
		if err != nil {
			return sensor, err
		}
	}
	err := s.Pool.QueryRow(ctx, `
		UPDATE registered_sensors SET last_seen_at=clock_timestamp(), queue_loss=COALESCE($2::jsonb,queue_loss)
		WHERE token_hash=$1 AND state <> 'revoked'
		RETURNING id,state,last_seen_at,queue_loss`, credentialHash[:], raw).Scan(
		&sensor.ID, &sensor.State, &sensor.LastSeenAt, &sensor.QueueLoss)
	if errors.Is(err, pgx.ErrNoRows) {
		return sensor, ErrSensorUnknown
	}
	return sensor, err
}

func (s *Store) SetSensorState(ctx context.Context, id, action string) error {
	states := map[string]string{"pause": "paused", "resume": "active", "revoke": "revoked"}
	target, ok := states[action]
	if !ok || !sensorIDPattern.MatchString(id) {
		return ErrSensorInput
	}
	if action == "revoke" {
		// Cancel an outstanding code or revoke a registered sensor. An
		// already consumed code remains unusable after revocation.
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.Background())
		registration, err := tx.Exec(ctx, `
			UPDATE sensor_registrations SET expires_at=clock_timestamp()
			WHERE sensor_id=$1 AND consumed_at IS NULL AND expires_at > clock_timestamp()`, id)
		if err != nil {
			return err
		}
		sensor, err := tx.Exec(ctx, "UPDATE registered_sensors SET state='revoked' WHERE id=$1", id)
		if err != nil {
			return err
		}
		if registration.RowsAffected() == 0 && sensor.RowsAffected() == 0 {
			return ErrSensorUnknown
		}
		return tx.Commit(ctx)
	}
	tag, err := s.Pool.Exec(ctx, "UPDATE registered_sensors SET state=$2 WHERE id=$1 AND state <> 'revoked'", id, target)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err = s.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM registered_sensors WHERE id=$1)", id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrSensorState
		}
		return ErrSensorUnknown
	}
	return nil
}
