# ADR 0007 — Apply persistence to incident end evidence

Experimental, 2026-11-19.

The legacy incident state machine extends an active episode after an
isolated exceedance and requires three recovery scores below 95% of
the alert threshold. On a frozen comparison trace, valid normal scores
repeatedly reset recovery. A later isolated exceedance moved the estimated
end by 20 seconds.

Policy v2 uses two observations within three contiguous windows to
confirm a new signal, for both opening an incident and extending its
estimated boundary. Three consecutive observations without a confirming
signal close it. This policy operates on predictions from the same pinned
scoring bundle, so an experiment can isolate its effect.

Unscored windows and capture-time discontinuities interrupt an active
incident. Store the interruption separately and leave the end unresolved.
Keep timeout evidence stable after delayed predictions. Evaluate changes
with both independent fault intervals and substantial normal exposure
before deployment.
