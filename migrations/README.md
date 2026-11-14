# Versioned PostgreSQL migrations

`000001_pipeline.up.sql` creates windows, batch receipts, leased inference jobs
and unique predictions. The matching down file drops those application tables.
`embed.go` embeds SQL into the API executable; `netwatch-api --migrate-only`
applies the migration under a transaction-scoped advisory lock and records its
SHA-256 in `schema_migrations`. Never edit an applied migration; add a new version
when the migration runner is extended. API/worker startup requires this schema.

`make server-smoke` checks application/rollback/reapplication on disposable real
PostgreSQL schemas. A production rollback destroys data and is never automatic.
See [server operations](../docs/runbooks/server.md) for configuration and guarantees.

Version 000002 adds incident streams, a durable projection queue, incidents and
their evidence. An insertion trigger queues new inference jobs in the ingestion
transaction. Migration also queues existing jobs for replay. Roll back versions
in descending order. Rolling back 000002 discards acknowledgements and history.
