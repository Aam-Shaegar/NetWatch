DROP TABLE pilots;
DROP TRIGGER sensor_revoked ON registered_sensors;
DROP FUNCTION stamp_sensor_revocation();
ALTER TABLE registered_sensors DROP COLUMN revoked_at;
