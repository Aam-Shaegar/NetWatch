# ADR 0006 — Version TCP connection-age features

Accepted 2026-11-19 for evaluation.

Add five optional-in-value, required-in-shape TCP age fields to traffic-v2.
Go computes them in event time using the state shared by live capture and
replay. Aggregate observed TCP incarnations with packets in each window,
using the existing bounded tracker and window limits. Expired or missed
openings are censored. Track actual observed closes separately. Capture
quality continues to determine whether a window can be scored.

The scoped Isolation Forest can fit either feature version. A serving bundle
requires the same feature version as the observation. Keep traffic-v1 for
safe rollback and previously stored windows. Compare scoped models trained
and calibrated on identical capture partitions with and without the five
additional columns. Base operating-model selection on independent incident
recall, normal exposure, false alarms and timing from the Go projector.
