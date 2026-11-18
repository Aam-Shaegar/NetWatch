CREATE TABLE security_observations (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sensor text NOT NULL,
 observation jsonb NOT NULL,
 assessment jsonb NOT NULL,
 identity bytea NOT NULL UNIQUE,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX predictions_terminal_errors ON predictions(event_id) WHERE payload->>'reason' IS NOT NULL;
