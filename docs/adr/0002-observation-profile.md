# ADR 0002 — Observe the target network namespace

Accepted 2026-11-06.

The Linux sensor captures on an interface in the target service’s network namespace. This gives it both directions of the service’s traffic. A separate container on the same Docker bridge would typically see only its own unicast traffic.

Docker Desktop runs the sensor inside its Linux VM. The laboratory uses tcpdump for independent reference captures. [Live capture setup](../runbooks/live.md)
