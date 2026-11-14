DROP TRIGGER incident_enqueue ON inference_jobs;
DROP FUNCTION incident_enqueue();
DROP TABLE incident_events, incidents, incident_queue, incident_streams;
