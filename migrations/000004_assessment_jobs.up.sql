CREATE TABLE assessment_jobs (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sensor text NOT NULL,
 observation jsonb NOT NULL CHECK (jsonb_typeof(observation)='object'),
 identity bytea NOT NULL UNIQUE,
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','done','failed')),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text,
 lease_until timestamptz,
 attempts int NOT NULL DEFAULT 0,
 observation_id bigint REFERENCES security_observations(id),
 last_error text,
 CHECK ((status='leased') = (lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
 CHECK ((status='done') = (observation_id IS NOT NULL))
);
CREATE INDEX assessment_pending ON assessment_jobs(available_at,id) WHERE status='pending';
CREATE INDEX assessment_expired ON assessment_jobs(lease_until) WHERE status='leased';

ALTER TABLE incidents ADD COLUMN last_signal_end_ns bigint;
ALTER TABLE incidents ADD COLUMN closed_at timestamptz;
UPDATE incidents i SET last_signal_end_ns = q.signal_end
FROM (
 SELECT e.incident_id, max(w.window_end_ns) AS signal_end
 FROM incident_events e JOIN feature_windows w USING(event_id)
 JOIN incidents old ON old.id=e.incident_id JOIN incident_streams stream USING(stream_id)
 JOIN predictions p ON p.event_id=e.event_id AND p.model_id=stream.model_id AND p.policy_version=stream.policy_version
 WHERE e.kind IN ('signal','opened') AND p.payload->>'status'='anomalous'
 AND (p.payload->>'score')::double precision > (p.payload->>'threshold')::double precision
 GROUP BY e.incident_id
) q WHERE i.id=q.incident_id;
