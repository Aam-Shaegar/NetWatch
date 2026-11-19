# ADR 0005 — Calibrate an Isolation Forest for a specific service

Experimental, 2026-11-19.

The laboratory bundle combines a forest with rules calibrated on the laboratory
service. Ordinary Orion traffic activated those rules even when its forest
score stayed below threshold. An artifact trained for an explicitly identified
sensor and TCP destination can learn the service's ordinary behavior using the
existing traffic-v1 window. Bind the artifact to both identifiers and calibrate
it on distinct normal captures. Keep the legacy profile readable for comparison.

Use the common Go episode policy when measuring missed episodes, timing, and
false incidents. Archived records whose original loss counters are unknown can
support exploratory comparisons if the assumption is recorded and confined to
separate copies. They cannot establish readiness under the live input contract.
The experimental profile provides anomaly scores. Attack classification and
candidate promotion require separate acceptance evidence.
