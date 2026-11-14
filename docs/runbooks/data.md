# Data acquisition and provenance

Use both: local lab normal runs for GRU, public raw PCAP for external evaluation and later classification.
Never fit a model on contracts/examples or tests/fixtures: they are tiny correctness fixtures.
The default lab smoke is also not a training dataset: ten seconds cannot supply a GRU history.

## Public candidates checked 2026-11-06

CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
Raw PCAP plus labeled flows. Monday benign, later days mixed. Go must re-extract our features.
Official download: https://cicresearch.ca/CICDataset/CIC-IDS-2017/ currently renders a registration form plus server-error message.
CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html
Candidate for DDoS classifier, not guaranteed transfer to our network. Official download form:
https://cicresearch.ca/CICDataset/CICDDoS2019/ — same form/error at check time.
Citation is required by the published terms; retain the source paper and specific archive terms.
Improved labels/tools: https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html
Known issues prevent blindly training on original flow CSV. Improved CSV still uses another extractor.

No archive downloaded, no personal information submitted, no acquisition claimed.
Use the official form manually if needed; do not treat a guessed directory URL as an archive.
After download run scripts/register_capture.py to compute SHA256 and metadata.
Keep raw data in data/raw (ignored by Git); commit metadata/manifest after reviewing source and labels.
Do not automatically label every packet in an attack day as malicious.

## Collect and audit laboratory windows

Install the project dependencies with `make bootstrap`. Collection uses the Linux
Go sensor and an internal Docker Compose network per run. Dataset export also
requires tcpdump on the host and the Go toolchain used by NetWatch.

```sh
make collect COLLECT_ARGS="--normal-runs 20 --seconds 600 --workers 3 --seed 42"
# Substitute the collection directory printed by the command.
make dataset COLLECTION=data/runs/collection-EXAMPLE OUTPUT=data/processed/experiment-01
```

The default campaign rotates stable, ramp and flash-crowd demand over 20 independent
ten-minute runs. Each run has its own target, network, sensor epoch and client.
The flash crowd adds two concurrent visitors to the same application client namespace.
Every run includes a concurrent 32 KiB background download about every two seconds.
Two additional runs pause foreground requests during the middle third of a run of up
to 90 seconds. The background lane continues. The client records observed monotonic
scheduling boundaries as wall-clock nanoseconds for joining with packet capture time.
This scenario measures a known application interruption. A DDoS class requires its
own evidence. Changing the seed changes request jitter. Parallel labs share host
resources. Record the worker count when comparing experiments.

The runner stores configuration, source checksums, base Git revision, resolved image
IDs, achieved counts, kernel loss counters, independent target request counters,
request logs, PCAP and Go windows under data/runs. With `--use-local-images` the
runner uses the installed lab and sensor images. The lab scripts are mounted read-only
from the checkout. A completed collection publishes collection.json after all runs
succeed. A failed run keeps an incomplete manifest for diagnosis.

The exporter verifies PCAP hashes, complete request timelines, target/client counts,
the number of HTTP GET packets and directional packet counts measured with tcpdump.
Go replay must reproduce the live window IDs and all 16 features. The HTTP GET
check applies to this lab's short plaintext requests. Only windows fully inside
an observed interval and with known good capture quality enter Parquet. Boundary,
mixed and incomplete counts remain in the manifest. A gap longer than six seconds
in the roughly two-second background heartbeat excludes every intersecting window
as unobserved, including windows adjacent to VM clock jumps. Missing windows are
never imputed. Sequence consumers must require consecutive timestamps in one group. The paused foreground must
have zero main requests and the background must have transferred data during it.

Each split is a Parquet file with an explicit numeric schema. The manifest lists
the 16 model input columns. Labels, event/group IDs, time, profile and entity are
metadata. Read only feature_columns when fitting preprocessing or a model.
The existing seeded splitter assigns whole normal runs to train, validation,
calibration and test. The first fault run goes to validation and the second to
test. The builder checks unique capture hashes, event IDs and cross-split feature
vectors, including nulls, before publishing the output directory. Rebuilding
requires a new output path. Keep the collection and the resulting manifest
together to reproduce the exact partition.

`make collection-smoke` tests a short real pause, checks the windows against
PCAP and delivers them through the existing API, PostgreSQL queue and worker.
CI runs it after building the lab images via live-smoke. The training collection
uses the longer make collect campaign. All captures, request journals and Parquet
files are local Git-ignored artifacts.

## Verified external replay sample

IoT-23, CTU-Honeypot-Capture-7-1 / Somfy-01. Authors' catalog: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/ . Read all 8276 records (5087.822 seconds). Restore on another machine with `python3 scripts/fetch_sample.py`. The checked manifest records source, byte count and SHA256. Keep the raw file outside Git. Use this one IoT observation for offline compatibility and an external data point, separately from service-load experiments. Labels and deployment transfer need validation before training.

### Audit the Somfy labels

Run `python3 scripts/fetch_sample.py`, then
`./scripts/uv run --project ml --locked python scripts/audit_somfy.py`.
The registered [Zeek flow labels](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled)
contain 130 benign flows. A directional TCP/UDP endpoint and packet-time check
within 1 ms of the annotated start matched 69 of 71 UDP records and 1 of 10 TCP
records. The 49 ICMP records fall outside that transport join. The audit does not
establish labels for five-second service windows. Keep this capture external to
the supervised laboratory partitions. See the
[authors' dataset description and citation](https://www.stratosphereips.org/datasets-iot23).
