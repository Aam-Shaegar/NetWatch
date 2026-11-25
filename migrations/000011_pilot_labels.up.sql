CREATE TABLE pilot_labels (
    pilot_name text NOT NULL REFERENCES pilots(name),
    sensor_id text NOT NULL REFERENCES registered_sensors(id),
    id text NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
    kind text NOT NULL CHECK (kind IN ('normal','tcp_port_scan','udp_flood','icmp_flood','unknown')),
    operator_id text NOT NULL,
    PRIMARY KEY (pilot_name, sensor_id, id)
);

-- Count an episode once even if several decisions or capture epochs overlap it.
-- For normal exposure, only fully covered five-second slots with a usable
-- decision qualify. A boundary-spanning incident needs manual review.
CREATE FUNCTION pilot_reference_summary(trial text, sensor text, cutoff timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
    WITH labels AS (
        SELECT l.id, l.kind, (extract(epoch FROM l.starts_at)*1e9)::bigint lo,
               (extract(epoch FROM l.ends_at)*1e9)::bigint hi, p.model_id, p.policy_version,
               (extract(epoch FROM greatest(p.started_at,s.registered_at))*1e9)::bigint pilot_lo,
               (extract(epoch FROM cutoff)*1e9)::bigint pilot_hi
        FROM pilot_labels l JOIN pilots p ON p.name=l.pilot_name
        JOIN registered_sensors s ON s.id=l.sensor_id
        WHERE l.pilot_name=trial AND l.sensor_id=sensor AND l.ends_at <= cutoff
    ), hits AS (
        SELECT l.id, l.kind, w.window_start_ns, d.status, i.id AS incident, i.attack_type,
               w.window_start_ns>=l.lo AND w.window_end_ns<=l.hi AS inside,
               i.first_ns>=l.lo AND i.last_ns<=l.hi AS incident_inside
        FROM labels l JOIN feature_windows w ON w.sensor_id=sensor
          AND w.window_end_ns>l.lo AND w.window_end_ns<l.hi+5000000000
          AND w.window_end_ns-w.window_start_ns=5000000000 AND w.window_start_ns%5000000000=0
          AND w.window_start_ns<l.hi AND w.window_start_ns>=l.pilot_lo AND w.window_end_ns<=l.pilot_hi
          AND w.window_end_ns-w.window_start_ns=5000000000 AND w.window_start_ns%5000000000=0
          AND w.payload->>'feature_set_version'='traffic-v3' AND w.payload->>'entity_type'='host'
        JOIN catalog_decisions d ON d.event_id=w.event_id AND d.model_id=l.model_id AND d.policy_version=l.policy_version
        LEFT JOIN catalog_incidents i ON i.id=d.incident_id
        WHERE d.status IN ('normal','incident')
          AND NOT EXISTS (SELECT FROM labels other WHERE other.id<>l.id
              AND other.lo<w.window_end_ns AND other.hi>w.window_start_ns)
    ), episodes AS (
        SELECT l.id, l.kind, bool_or(h.incident IS NOT NULL) AS detected,
               coalesce(bool_or(h.attack_type=l.kind),false) AS correct
        FROM labels l LEFT JOIN hits h USING(id) WHERE l.kind<>'normal' GROUP BY l.id,l.kind
    ), types AS (
        SELECT kind, count(*) AS total, count(*) FILTER (WHERE detected) AS detected,
               count(*) FILTER (WHERE correct) AS correct FROM episodes GROUP BY kind
    ), normal AS (
        SELECT count(DISTINCT window_start_ns) FILTER (WHERE inside) AS slots,
               count(DISTINCT incident) FILTER (WHERE inside AND incident_inside) AS false_incidents
        FROM hits WHERE kind='normal'
    )
    SELECT CASE WHEN EXISTS(SELECT FROM labels) THEN jsonb_build_object(
        'attack_episodes',(SELECT count(*) FROM episodes),
        'detected_episodes',(SELECT count(*) FROM episodes WHERE detected),
        'correctly_typed_episodes',(SELECT count(*) FROM episodes WHERE correct),
        'by_type',coalesce((SELECT jsonb_object_agg(kind,to_jsonb(types)-'kind') FROM types),'{}'::jsonb),
        'normal_slots',slots,'false_incidents',false_incidents,
        'false_per_100h',round(72000.0*false_incidents/nullif(slots,0),3)) END FROM normal
$$;
