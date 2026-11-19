UPDATE incident_events SET kind='unknown' WHERE kind='gap';
ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check;
ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check
 CHECK (kind IN ('signal','opened','observed','closed','unknown'));
ALTER TABLE incidents DROP CONSTRAINT incidents_distinct_end;
ALTER TABLE incidents DROP COLUMN interrupted_ns;
