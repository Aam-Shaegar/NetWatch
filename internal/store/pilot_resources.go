package store

import (
	"context"
	"math"
)

// SaveSensorResources records at most one sample per sensor per UTC minute,
// using database time so a sensor's clock cannot move its samples into another pilot.
func (s *Store) SaveSensorResources(ctx context.Context, sensorID string, cpuPct float64, rssBytes int64) error {
	if rssBytes <= 0 || math.IsNaN(cpuPct) || cpuPct < 0 || cpuPct > 6553600 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO sensor_resource_samples(sensor_id, sampled_at, cpu_pct, rss_bytes)
		SELECT id, statement_timestamp(), $2, $3 FROM registered_sensors
		WHERE id=$1 AND state <> 'revoked'
		  AND EXISTS (SELECT 1 FROM pilots WHERE started_at <= statement_timestamp()
		              AND started_at > statement_timestamp() - interval '168 hours')
		ON CONFLICT DO NOTHING`, sensorID, cpuPct, rssBytes)
	return err
}
