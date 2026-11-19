ALTER TABLE incidents ADD COLUMN interrupted_ns bigint;
ALTER TABLE incidents ADD CONSTRAINT incidents_distinct_end CHECK (interrupted_ns IS NULL OR closed_ns IS NULL);
ALTER TABLE incident_events DROP CONSTRAINT incident_events_kind_check;
ALTER TABLE incident_events ADD CONSTRAINT incident_events_kind_check
 CHECK (kind IN ('signal','opened','observed','closed','unknown','gap'));
