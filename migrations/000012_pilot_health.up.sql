CREATE TABLE pilot_analyzer_samples (
    pilot_name text NOT NULL REFERENCES pilots(name),
    minute_utc bigint NOT NULL,
    sampled_at timestamptz NOT NULL,
    queued_jobs bigint NOT NULL,
    database_bytes bigint NOT NULL,
    PRIMARY KEY (pilot_name, minute_utc)
);

CREATE FUNCTION pilot_analyzer_summary(trial text, cutoff timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object('samples', count(*), 'peak_queue', max(queued_jobs),
        'database_growth_bytes', CASE WHEN count(*) >= 2 THEN
            (array_agg(database_bytes ORDER BY sampled_at DESC))[1] -
            (array_agg(database_bytes ORDER BY sampled_at))[1] END)
    FROM pilot_analyzer_samples WHERE pilot_name=trial AND sampled_at <= cutoff
$$;
