CREATE TABLE registered_sensors (
    id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','paused','revoked')),
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    queue_loss jsonb NOT NULL DEFAULT '{"count":0}'::jsonb
);

CREATE TABLE sensor_registrations (
    sensor_id text PRIMARY KEY CHECK (sensor_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'),
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
