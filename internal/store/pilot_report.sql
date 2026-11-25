-- One sensor has one expected slot per fully elapsed, aligned five-second
-- interval. Restarts can produce separate event IDs for the same slot.
WITH roster AS (
    SELECT id, greatest(registered_at, $1::timestamptz) AS begins_at,
           least(revoked_at, $2::timestamptz) AS stops_at
    FROM registered_sensors
    WHERE registered_at <= $2::timestamptz AND (revoked_at IS NULL OR revoked_at > $1::timestamptz)
), bounds AS (
    SELECT id, begins_at, stops_at,
           ceil(extract(epoch FROM begins_at) / 5)::bigint * 5000000000 AS first_ns,
           floor(extract(epoch FROM stops_at) / 5)::bigint * 5000000000 AS end_ns
    FROM roster
), sensors AS (
    SELECT *, greatest(0, (end_ns - first_ns) / 5000000000) AS expected_slots
    FROM bounds
), report AS (
    SELECT s.id AS sensor_id, s.expected_slots, stats.*,
           round(100.0 * stats.usable_slots / nullif(s.expected_slots, 0), 2) AS coverage_pct,
           resources.*, pilot_reference_summary($5::text, s.id, s.stops_at) AS reference
    FROM sensors s
    CROSS JOIN LATERAL (
        WITH observations AS (
            SELECT w.window_start_ns, d.status, d.incident_id,
                   extract(epoch FROM d.decided_at) - w.window_end_ns / 1e9 AS delay_s
            FROM feature_windows w
            LEFT JOIN catalog_decisions d ON d.event_id = w.event_id
                AND d.model_id = $3 AND d.policy_version = $4
            WHERE w.sensor_id = s.id
                AND w.window_end_ns > s.first_ns AND w.window_end_ns <= s.end_ns
                AND w.window_end_ns - w.window_start_ns = 5000000000
                AND w.window_start_ns % 5000000000 = 0
                AND w.payload->>'feature_set_version' = 'traffic-v3'
                AND w.payload->>'entity_type' = 'host'
        ), incidents AS (
            SELECT i.attack_type, i.source FROM catalog_incidents i
            JOIN (SELECT DISTINCT incident_id FROM observations WHERE incident_id IS NOT NULL) used
              ON used.incident_id = i.id
        )
        SELECT count(*) AS received_windows,
               count(DISTINCT window_start_ns) AS received_slots,
               count(DISTINCT window_start_ns) FILTER (WHERE status IN ('normal','incident')) AS usable_slots,
               count(*) FILTER (WHERE status = 'insufficient_data') AS insufficient_windows,
               count(*) FILTER (WHERE status IS NULL OR status = 'no_match') AS unresolved_windows,
               count(*) FILTER (WHERE status = 'incident') AS alert_windows,
               percentile_cont(0.95) WITHIN GROUP (ORDER BY delay_s)
                   FILTER (WHERE status IN ('normal','incident')) AS p95_delay_s,
               (SELECT count(*) FROM incidents) AS incidents,
               coalesce((SELECT jsonb_object_agg(attack_type,n) FROM
                   (SELECT attack_type,count(*) n FROM incidents GROUP BY attack_type) t), '{}'::jsonb) AS by_type,
               coalesce((SELECT jsonb_object_agg(source,n) FROM
                   (SELECT source,count(*) n FROM incidents GROUP BY source) t), '{}'::jsonb) AS by_source
        FROM observations
    ) stats
    CROSS JOIN LATERAL (
        SELECT count(*) AS resource_samples, avg(cpu_pct) AS mean_cpu_pct, max(rss_bytes) AS peak_rss_bytes
        FROM sensor_resource_samples
        WHERE sensor_id = s.id AND sampled_at >= s.begins_at AND sampled_at < s.stops_at
    ) resources
)
SELECT coalesce(jsonb_agg(to_jsonb(report) ORDER BY sensor_id), '[]'::jsonb),
       pilot_analyzer_summary($5::text, $2::timestamptz)
FROM report
