package store

import "context"

// SamplePilotHealth records shared analyzer metrics only while a pilot is running.
// The minute key also deduplicates samples from concurrent API instances.
func (s *Store) SamplePilotHealth(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO pilot_analyzer_samples
	    (pilot_name,minute_utc,sampled_at,queued_jobs,database_bytes)
	    SELECT name, floor(extract(epoch FROM statement_timestamp()) / 60)::bigint,
	           statement_timestamp(), (SELECT count(*) FROM inference_jobs WHERE status='pending') +
	           (SELECT count(*) FROM inference_jobs WHERE status='leased'),
	           pg_database_size(current_database())
	    FROM pilots WHERE started_at<=statement_timestamp()
	      AND started_at>statement_timestamp()-interval '168 hours'
	    ON CONFLICT DO NOTHING`)
	return err
}
