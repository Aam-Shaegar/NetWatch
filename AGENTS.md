# NetWatch development rules
Read PLAN.md, docs/status.md and docs/IMPLEMENTATION_GUIDE.md before work.
Product first; do not edit the coursework instead of implementing the current milestone.
The legacy netwatch/ Python package is retained as a reference, not the new architecture.
Go owns packet-to-feature semantics. Python owns ML preprocessing, training and serving.
contracts/*.schema.json is the structural source of truth. Semantic invariants are tested in both languages.
Keep credentials, raw captures, datasets and model weights out of Git.
Never claim model readiness from liveness. A missing model returns unavailable, not normal.
Run make test and make build for affected code; run make compose-check for Compose changes.
Live capture tests run only on the isolated lab. Do not capture arbitrary host traffic.
Record actual validation and limitations in docs/status.md and update PLAN.md at the end.
Do not mark a milestone complete just because its directories exist.

## GitHub workflow
For each successfully completed change, run the relevant tests and builds, review the staged diff and check for private data. Commit the verified work and push the project branch to origin. Verify the remote branch head, then check GitHub Actions and address failing checks. Never push local archive branches, raw data, credentials or personal coursework notes. Report any blocked push or unverified CI result explicitly.
