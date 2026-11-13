CREATE TABLE feature_windows (
 event_id text PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 200),
 sensor_id text NOT NULL CHECK(length(sensor_id) BETWEEN 1 AND 200),
 window_start_ns bigint NOT NULL CHECK (window_start_ns >= 0),
 window_end_ns bigint NOT NULL CHECK (window_end_ns > window_start_ns),
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX feature_windows_sensor_time ON feature_windows(sensor_id, window_end_ns DESC);
CREATE TABLE ingestion_batches (
 sensor_id text NOT NULL CHECK(length(sensor_id) BETWEEN 1 AND 200),
 batch_id text NOT NULL,
 event_ids text[] NOT NULL,
 queue_loss jsonb NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(sensor_id, batch_id)
);
CREATE TABLE inference_jobs (
 event_id text NOT NULL REFERENCES feature_windows(event_id) ON DELETE CASCADE,
 model_id text NOT NULL CHECK(length(model_id) BETWEEN 1 AND 200),
 policy_version text NOT NULL CHECK(length(policy_version) BETWEEN 1 AND 200),
 status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','done')),
 attempts bigint NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_until timestamptz,
 lease_token text,
 last_error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(event_id,model_id,policy_version),
 CHECK ((status = 'leased') = (lease_until IS NOT NULL AND lease_token IS NOT NULL)),
 CHECK ((lease_until IS NULL) = (lease_token IS NULL))
);
CREATE INDEX inference_jobs_pending ON inference_jobs(available_at,created_at) WHERE status='pending';
CREATE INDEX inference_jobs_expired ON inference_jobs(lease_until) WHERE status='leased';
CREATE TABLE predictions (
 event_id text NOT NULL,
 model_id text NOT NULL CHECK(length(model_id) BETWEEN 1 AND 200),
 policy_version text NOT NULL CHECK(length(policy_version) BETWEEN 1 AND 200),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 processed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(event_id,model_id,policy_version),
 FOREIGN KEY(event_id,model_id,policy_version) REFERENCES inference_jobs(event_id,model_id,policy_version) ON DELETE CASCADE
);
