CREATE TABLE pilots (
    name text PRIMARY KEY CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    model_id text NOT NULL,
    policy_version text NOT NULL
);

-- Older installations did not retain revocation times. All previously revoked
-- sensors predate the first pilot and can be excluded from its roster.
ALTER TABLE registered_sensors ADD COLUMN revoked_at timestamptz;
UPDATE registered_sensors SET revoked_at=statement_timestamp() WHERE state='revoked';

-- Stamp the existing irreversible transition at the database, including
-- revocations from older API processes during a rolling upgrade.
CREATE FUNCTION stamp_sensor_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revoked_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER sensor_revoked BEFORE INSERT OR UPDATE OF state ON registered_sensors
    FOR EACH ROW WHEN (NEW.state='revoked' AND NEW.revoked_at IS NULL)
    EXECUTE FUNCTION stamp_sensor_revocation();
