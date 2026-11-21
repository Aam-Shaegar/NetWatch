CREATE TABLE catalog_policy_settings (
 policy_version text PRIMARY KEY,
 rules jsonb NOT NULL CHECK (jsonb_typeof(rules)='object')
);

CREATE TABLE catalog_incidents (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 stream_key text NOT NULL,
 sensor_id text NOT NULL,
 entity_id text NOT NULL,
 attack_type text NOT NULL CHECK (attack_type IN ('tcp_port_scan','udp_flood','icmp_flood','unknown')),
 source text NOT NULL CHECK (source IN ('rules','ml')),
 detector_version text NOT NULL,
 first_ns bigint NOT NULL,
 last_ns bigint NOT NULL CHECK (last_ns > first_ns),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX catalog_incidents_stream ON catalog_incidents(stream_key,first_ns,last_ns);
CREATE INDEX catalog_incidents_latest ON catalog_incidents(last_ns DESC,id DESC);

CREATE TABLE catalog_decisions (
 event_id text NOT NULL,
 model_id text NOT NULL,
 policy_version text NOT NULL,
 status text NOT NULL CHECK (status IN ('no_match','normal','insufficient_data','incident')),
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
 incident_id bigint REFERENCES catalog_incidents(id),
 decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(event_id,model_id,policy_version),
 FOREIGN KEY(event_id,model_id,policy_version)
  REFERENCES inference_jobs(event_id,model_id,policy_version) ON DELETE CASCADE,
 CHECK ((status='incident') = (incident_id IS NOT NULL))
);
CREATE INDEX catalog_decisions_incident ON catalog_decisions(incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX catalog_decisions_target_latest ON catalog_decisions(model_id,policy_version,decided_at DESC,event_id DESC)
 WHERE status<>'no_match';
CREATE INDEX catalog_decisions_target_usable ON catalog_decisions(model_id,policy_version,decided_at DESC,event_id DESC)
 WHERE status IN ('normal','incident');
