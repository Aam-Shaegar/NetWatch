# Durable sensor queue and HTTP delivery

## Commands

Linux with CGO/libpcap supports live capture; replay, queue and delivery also run
on macOS. Use a local filesystem with working file/directory fsync, atomic rename
and flock. Network filesystems are not an accepted durability profile.

```sh
go build -o ./bin/netwatch-sensor ./cmd/netwatch-sensor
# Live: persist each window before writing its diagnostic JSONL output.
./bin/netwatch-sensor live --interface eth0 --filter 'tcp port 8080' \
  --service 192.0.2.10:8080 --output outputs/live.jsonl \
  --spool data/spool/live --endpoint http://127.0.0.1:8081/v1/windows
# Replay keeps its atomic file-output behavior; import complete JSONL explicitly.
./bin/netwatch-sensor replay --input tests/fixtures/pcap/syn-retry.pcap \
  --host 192.0.2.10 --epoch recording-001 --output outputs/replay.jsonl
./bin/netwatch-sensor enqueue --input outputs/replay.jsonl --spool data/spool/replay
./bin/netwatch-sensor send --spool data/spool/replay \
  --endpoint http://127.0.0.1:8081/v1/windows --once
./bin/netwatch-sensor spool-status --spool data/spool/replay
```

Create `bin` and `outputs` directories before using these paths. The production
`/v1/windows` receiver is not implemented yet: it belongs to the server milestone.
The delivery tests use real local HTTP test receivers, not the health-only API.
`make live-smoke` verifies live capture, replay parity and queue recovery in Linux.
`go test -race ./internal/spool ./internal/transport ./cmd/netwatch-sensor` verifies
crash recovery, outages, ambiguous ACKs, quarantine and the replay-to-HTTP path.

Omit `--endpoint` to accumulate live windows for later sending. `send` runs until
interrupted; `--once` exits when drained but keeps retrying an unavailable server.
Only one process can own a queue. Live capture with an endpoint runs its sender
in-process; do not launch a second sender or status command against that directory.
The structured `spool_opened`, `spool_overflow`, `delivery_retry`, `delivery_ack`,
`delivery_quarantined`, `delivery_failed`, and `spool_closed` logs expose health.
A live sender's permanent failure cancels capture and leaves unsent windows intact.

The token is read from `NETWATCH_SENSOR_TOKEN`, never a command-line flag or log.
Remote endpoints require HTTPS and a token. Plain HTTP is accepted for literal
loopback addresses/localhost; `--allow-insecure-http` is an explicit isolated-lab
exception. Redirects are not followed. Sender failures do not log response bodies,
credentials or the URL. No untrusted payload appears in retry diagnostics.

## On-disk format and acknowledgment order

Segments are named by their first sequence: `00000000000000000001.seg`. Each record
has a 20-byte header: magic `NWQ1`, big-endian uint32 payload length, uint64 sequence,
and CRC32 of the first 16 header bytes plus JSON payload. Payload is a validated
window, at most 64 KiB. Sequences order local records; existing `event_id` values
remain unchanged. Event IDs derive from sensor, capture epoch, entity and window
start and remain stable across retries/replay of the same observation.

Append writes the frame and fsyncs the file; a new segment also fsyncs its directory.
Only then is Append successful. ACK atomically replaces and syncs `state.json`
before deleting fully acknowledged segments and syncing the directory. State and
quarantine records also carry CRC32 checksums. Locks prevent two writers, and a
mutex serializes producer, reader and acknowledgments inside one process.

After a crash, the queue scans bounded records, checks checksums and sequences,
restores pending windows, removes acknowledged segments and discards stale atomic
write temporary files. Only an incomplete final record in the newest segment is
truncated. A checksum failure, missing pending prefix, malformed header or damaged
closed segment stops opening the queue and preserves evidence. Recovery reports
`recovered_tail_bytes`; the run is degraded if a tail was repaired.

Crash before durable append may lose the current window. Crash after append but
before ACK replays it. Crash after server commit but before receipt/persistence of
ACK can also replay it. The receiver must enforce event-ID uniqueness and ACK only
after transaction commit. This is **at-least-once delivery**, not exactly-once HTTP.
File/directory fsync relies on the filesystem and storage device honoring it; tests
kill real processes but do not simulate physical power loss or faulty hardware.

## Bounds and loss policy

Defaults: `--spool-bytes 268435456` (256 MiB segment bytes),
`--segment-bytes 4194304` (4 MiB per segment), and
`--quarantine-bytes 16777216` (16 MiB, additionally capped at 1000 records).
Total disk usage includes those independent limits plus small metadata/lock files.
Partly acknowledged segments still count toward the segment budget until all their
records are resolved. Changing limits below existing sizes makes recovery fail.

When the queue is full, **drop newest** retains existing pending events. The loss
counter and first/latest lost event IDs and window timestamps are atomically saved.
These endpoints summarize all losses, not necessarily one continuous missing range.
Every dropped live window emits `spool_overflow` with the current last lost ID.
`spool-status` reports `degraded` and cumulative `loss`; batches carry `queue_loss`
as observation-health metadata, separate from ML features. Counters persist across
restart and are not silently reset after successful delivery.

Live capture continues after a recorded overflow. Its diagnostic JSONL may contain
windows that were dropped from the queue; it is not a delivery receipt. Import
returns a nonzero result if any windows were dropped. Imports commit line by line:
an invalid later line leaves the committed prefix on disk. Reimport can duplicate
records, so event-ID deduplication is required at the receiver. Separate directories
for live and historical imports prevent a historical backlog from blocking live.
Disk write/fsync errors stop the producer; a full physical disk may also prevent
persisting loss metadata. Capture may drop packets while synchronous disk I/O is
slow; capture loss and spool overflow are different counters.

## Wire protocol

See `contracts/batch.schema.json`, `ack.schema.json`, `rejection.schema.json` and
`contracts/openapi.yaml`. POST JSON contains schema_version=1, batch_id, windows and
queue_loss. A batch has at most 100 windows and at most 1 MiB of stored window JSON
before envelope overhead. The sender polls an empty queue every 250 ms and sends
available windows without waiting to fill the batch. Requests time out after 10 s
(`--http-timeout`). Retries use exponential full jitter from 250 ms up to 30 s.
Cancellation interrupts requests and waits.

The batch ID is SHA-256 of the serialized Batch struct with an empty batch_id.
The same frozen body/ID is reused for every attempt of that batch, also in the
Idempotency-Key header. Regrouping after a process restart may create a different
batch ID; individual event IDs remain stable. The receiver must deduplicate events
rather than relying solely on batch IDs. A batch never contains duplicate IDs.

Only HTTP 200 with the exact batch ID and the exact set of accepted_event_ids permits
ACK. Empty, malformed, oversized, missing or incorrect ACKs retain the batch and
retry. Response bodies and headers are each limited to 64 KiB. Network errors,
408, 429 and 5xx retry. Other statuses stop delivery, except a valid atomic 422:
`{"batch_id":"...","code":"invalid_window","error_index":0}`. Its indexed window
is durably quarantined before removal from delivery; remaining events are retried
with their original IDs. Invalid 422 responses and a full quarantine stop delivery.

Quarantine files remain for inspection after delivery and keep health degraded.
Stop the owner before investigating; archive the whole queue directory first.
Do not edit sequence files or state. If quarantine is full, after stopping the
owner and backing up the directory, read the acknowledged cursor from
`state.json` → `payload.ack`. Quarantine files whose numeric filename is at or
below that cursor can be archived outside the queue to release capacity; never
remove unresolved markers above it. Restart verifies the remaining metadata.
To retire cumulative loss history, drain pending data, archive the directory and
start a new one. If corruption prevents opening, preserve the directory and diagnose the
storage problem; automatic silent skipping is deliberately unsupported.
