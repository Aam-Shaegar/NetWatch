# Sensor and pipeline acceptance

Run `make bench` to measure aggregation of decoded packet metadata. The fixture
models 10,000 packets per event-time second, 1,000 flow keys, 100 destinations
and IP lengths of 64, 512 and 1,500 bytes. Each destination has its own engine.
This benchmark excludes libpcap, decoding, disk, HTTP and database latency.
Use `go test ./internal/window -run '^$' -bench BenchmarkServiceWindows -benchtime=500000x -cpuprofile=/tmp/netwatch.prof -o /tmp/netwatch-window.test`
and `go tool pprof -top /tmp/netwatch-window.test /tmp/netwatch.prof` for CPU profiling.

## Isolated observation and fault drills

Run `make bootstrap` and build the two local images with
`docker compose -f deploy/lab/compose.yaml build target sensor`. Use a trained
local Isolation Forest bundle as described in the [detector runbook](detector.md).
From the repository root run:

```sh
make operations ARTIFACT=artifacts/BASELINE OPERATIONS_SECONDS=180
make spool-disk-smoke
make server-smoke
```

To measure window-to-incident latency against a recorded foreground pause, run
`ml/.venv/bin/python scripts/operations.py artifacts/BASELINE --seconds 90 --pause`.
This mode uses the existing two-lane collection workload with an observed truth interval.

For a seven-day pilot set OPERATIONS_SECONDS=604800. Keep Docker, the runner
and the host running. The runner prints a unique directory under data/runs;
report.json is replaced atomically and samples.jsonl records elapsed time,
sensor VmRSS/VmHWM in KiB and cumulative prediction/incident counts. The
24-hour checkpoint requires 86,400 seconds of actual continuous samples;
inspect timestamps for gaps and inspect RSS trends. A completed pilot also
requires a finished timestamp, uninterrupted coverage, and review of incident
times against the planned pause and normal regimes. Duration alone is
insufficient. A fresh run uses a new capture epoch and directory.

Only the namespace of the dedicated HTTP target is observed. The client sends
ordinary GETs at nominal foreground rates 5, 15 and 3 requests/s in rotating
one-minute phases, with one commissioning pause and background requests.
The native bridge sends each closed JSONL window to the real loopback API and
checks its acknowledgement. Prediction latency includes the sensor watermark,
bridge polling, worker, inference and storage. Incident latency starts at the
end of the triggering window and ends at the recorded database opening time.
This setup measures one monitored service. Raw payload capture is disabled.

At shutdown the runner drains the projection queue, runs pg_dump in custom
format, restores it into a separate database and checks row counts and
ordered content hashes for every application table. It pauses only its own
disposable PostgreSQL container, checks API readiness changes to 503, resumes
it and checks readiness recovers to 200. The disk drill uses a private 1 MiB
tmpfs and checks the sensor returns ENOSPC, the prior queue survives reopening
and another append succeeds after space is freed. Migration rollback and
role checks run in the existing server and API suites.

For dependency checks run govulncheck on the current Go toolchain, `./scripts/uv audit --project ml --locked` and `npm audit` from web.
See the [measured results](operations-results.md) for the tested scope and outstanding gates.
