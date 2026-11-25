CREATE TABLE sensor_resource_samples (
    sensor_id text NOT NULL REFERENCES registered_sensors(id),
    sampled_at timestamptz NOT NULL,
    cpu_pct double precision NOT NULL CHECK (cpu_pct BETWEEN 0 AND 6553600),
    rss_bytes bigint NOT NULL CHECK (rss_bytes > 0),
    PRIMARY KEY (sensor_id, sampled_at)
);
CREATE UNIQUE INDEX sensor_resource_samples_per_minute ON sensor_resource_samples
    (sensor_id, date_bin(interval '1 minute', sampled_at, timestamptz '2000-01-01 00:00:00+00'));
