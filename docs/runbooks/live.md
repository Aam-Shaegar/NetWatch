# Linux live sensor

The sensor captures one named interface in its own network namespace. It does not
see an entire switched network automatically. The supported initial profile is
Linux with CGO/libpcap, Ethernet or raw IP, without promiscuous mode. On Docker
Desktop the sensor runs in the Linux VM and shares the **target container's**
network namespace. It does not observe the macOS host interfaces.

## Reproducible integration check

With Docker running, from the repository root:

```sh
make live-smoke
```

The script builds the lab and sensor images, creates an internal Docker network,
finds the target's actual address, captures `eth0` with `tcp port 8080`, and sends
20 seconds of bounded HTTP traffic. It checks interface discovery, NET_RAW-only
permissions, refusal without that capability, invalid BPF rejection, idle
capture timeout, graceful SIGTERM, zero reported drops and exact equality of all
16 features in at least two complete live windows versus replay of the same PCAP.
It removes its containers/network even on failure. Artifacts are retained under
ignored `data/runs/live-*/`: JSONL, diagnostic logs, PCAP and `live-report.json`.
The PCAP contains application payload and is for this isolated lab only.

## Build and run

```sh
docker build -f deploy/sensor/Dockerfile -t netwatch-sensor:dev .
docker run --rm --network container:TARGET_CONTAINER --cap-drop ALL \
  netwatch-sensor:dev interfaces
```

Choose the interface visible in that namespace. Create an output directory and
use an explicit observed target address (replace the example values):

```sh
mkdir -p output
chmod 0770 output
docker run --rm --network container:TARGET_CONTAINER \
  --group-add "$(id -g)" --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \
  --read-only -v "$PWD/output:/output" netwatch-sensor:dev \
  live --interface eth0 --filter 'tcp port 8080' \
  --service 172.20.0.2:8080 --output /output/windows.jsonl --duration 30s
```

No host network, privileged mode or NET_ADMIN is needed. The container currently
uses UID 0 with all capabilities removed except NET_RAW; it is not a rootless
capture implementation. The output directory is group-writable (0770); the
container receives its host group through `--group-add`. The smoke test sets
`NETWATCH_OUTPUT_GID` for Compose. Artifact files remain 0600, and the test reads
them through a read-only helper mount without widening their permissions. SIGINT and
SIGTERM stop capture and flush the final partial window; the read poll is 200 ms.
Native Linux builds require a C compiler and `libpcap-dev` (`go build
./cmd/netwatch-sensor`). Non-Linux or CGO-disabled builds retain offline replay
and interface listing, but `live` returns an explicit unsupported-platform error.

`--interface`, `--filter`, and `--output` are required. `--host IP` or
`--service IP:port --protocol TCP|UDP` selects feature windows; omitting both
writes decoded packet metadata. Each invocation gets a random capture epoch,
which can be overridden with `--epoch`. Existing output files are never
replaced. `--record-pcap FILE` explicitly enables raw packet recording, off by
default. Capture reads are synchronous: downstream disk/CPU pressure can cause
kernel drops, which are reported rather than hidden.

## Time and quality

Live and replay use the same decoder, flow tracker and five-second window
engine. When a read times out, `Advance` uses the system clock minus configured
lateness to close pending windows even during silence. Capture timestamps and
the system clock must be in the same clock domain; large clock adjustments or
processing delays can produce late packets, marked as gaps. Empty windows are
not synthesized. The first and unflushed shutdown boundary windows are partial.
Only fully elapsed windows observed since capture start can become complete.

JSON diagnostics go to stderr: `live_started`, periodic `capture_stats`, and
`live_stopped` with decoded/status counts and cumulative late-packet/drop counts.
The counters are those reported by libpcap: `received` is OS-dependent and need
not equal decoded records; `dropped` indicates capture-buffer loss;
`interface_dropped` is the driver-reported counter (not supported by every
interface). Zero is not a proof of end-to-end network visibility. Every exported
live window includes cumulative `capture_dropped`; after observed capture or
interface drops, subsequent windows conservatively have `coverage: gap` until a
new capture epoch. Earlier emitted windows cannot be revised. Offline replay
cannot infer kernel drops and leaves that counter unavailable.

On a capture/statistics/write error the process exits unsuccessfully, retains
already written output for diagnosis and marks any remaining exported windows
as gaps. A crash can leave an incomplete last JSONL line. Durable delivery and
recovery are a separate transport layer; the live output is not a durable spool.
