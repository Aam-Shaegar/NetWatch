CREATE TABLE incident_streams (
 stream_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sensor_id text NOT NULL, epoch text NOT NULL, entity_type text NOT NULL, entity_id text NOT NULL,
 model_id text NOT NULL, policy_version text NOT NULL, state jsonb NOT NULL DEFAULT '{}',
 UNIQUE(sensor_id,epoch,entity_type,entity_id,model_id,policy_version)
);
CREATE TABLE incident_queue (
 event_id text NOT NULL, model_id text NOT NULL, policy_version text NOT NULL,
 stream_id bigint NOT NULL REFERENCES incident_streams, start_ns bigint NOT NULL,
 PRIMARY KEY(event_id,model_id,policy_version),
 FOREIGN KEY(event_id,model_id,policy_version) REFERENCES inference_jobs ON DELETE CASCADE
);
CREATE INDEX incident_queue_order ON incident_queue(stream_id,start_ns,event_id);
CREATE TABLE incidents (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, stream_id bigint NOT NULL REFERENCES incident_streams,
 first_ns bigint NOT NULL, detected_ns bigint NOT NULL, last_ns bigint NOT NULL, closed_ns bigint,
 detected_at timestamptz NOT NULL DEFAULT clock_timestamp(), ack_at timestamptz, ack_by text,
 UNIQUE(stream_id,detected_ns)
);
CREATE INDEX incidents_timeline ON incidents(detected_ns DESC,id DESC);
CREATE TABLE incident_events (
 incident_id bigint NOT NULL REFERENCES incidents ON DELETE CASCADE,
 event_id text NOT NULL REFERENCES feature_windows ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('signal','opened','observed','closed','unknown')),
 PRIMARY KEY(incident_id,event_id)
);
CREATE FUNCTION incident_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE sid bigint; stamp bigint;
BEGIN
 SELECT window_start_ns INTO STRICT stamp FROM feature_windows WHERE event_id=NEW.event_id;
 INSERT INTO incident_streams(sensor_id,epoch,entity_type,entity_id,model_id,policy_version)
 SELECT sensor_id,payload->>'capture_epoch',payload->>'entity_type',payload->>'entity_id',NEW.model_id,NEW.policy_version
 FROM feature_windows WHERE event_id=NEW.event_id
 ON CONFLICT(sensor_id,epoch,entity_type,entity_id,model_id,policy_version) DO NOTHING;
 SELECT s.stream_id INTO STRICT sid FROM incident_streams s JOIN feature_windows w
 ON w.sensor_id=s.sensor_id AND w.payload->>'capture_epoch'=s.epoch AND w.payload->>'entity_type'=s.entity_type
 AND w.payload->>'entity_id'=s.entity_id WHERE w.event_id=NEW.event_id AND s.model_id=NEW.model_id AND s.policy_version=NEW.policy_version;
 INSERT INTO incident_queue VALUES(NEW.event_id,NEW.model_id,NEW.policy_version,sid,stamp);
 RETURN NEW;
END $$;
CREATE TRIGGER incident_enqueue AFTER INSERT ON inference_jobs FOR EACH ROW EXECUTE FUNCTION incident_enqueue();
INSERT INTO incident_streams(sensor_id,epoch,entity_type,entity_id,model_id,policy_version)
 SELECT DISTINCT w.sensor_id,w.payload->>'capture_epoch',w.payload->>'entity_type',w.payload->>'entity_id',j.model_id,j.policy_version
 FROM inference_jobs j JOIN feature_windows w USING(event_id);
INSERT INTO incident_queue
 SELECT j.event_id,j.model_id,j.policy_version,s.stream_id,w.window_start_ns FROM inference_jobs j
 JOIN feature_windows w USING(event_id) JOIN incident_streams s ON s.sensor_id=w.sensor_id
 AND s.epoch=w.payload->>'capture_epoch' AND s.entity_type=w.payload->>'entity_type' AND s.entity_id=w.payload->>'entity_id'
 AND s.model_id=j.model_id AND s.policy_version=j.policy_version;
