# Train and run the first detector

From a bootstrapped checkout, train on the Parquet directory produced by the collection exporter.
Use a new output directory for each experiment.

```sh
make train DATASET=data/processed/EXPERIMENT OUTPUT=artifacts/EXPERIMENT
export NETWATCH_MODEL_BUNDLE="$PWD/artifacts/EXPERIMENT/bundle.json"
export NETWATCH_MODEL_SHA256="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_sha256"])' artifacts/EXPERIMENT/report.json)"
export NETWATCH_MODEL_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["model_id"])' artifacts/EXPERIMENT/report.json)"
export NETWATCH_POLICY_VERSION=v1
make ml
```

Configure the ingestion API with the same model ID and policy before sending new windows.
Run the API and worker as described in [server setup](server.md). For an isolated end-to-end
check run the following command using the live.jsonl of a recorded service run.

```sh
./scripts/uv run --project ml --locked python scripts/detector_smoke.py artifacts/EXPERIMENT data/runs/COLLECTION/GROUP/live.jsonl
```

The loader verifies checksums, feature version, ordered columns, partition identities
and labels. Training and calibration require normal windows. The pipeline applies log1p
to all nonnegative values and imputes per-feature train medians. It divides centered
values by train interquartile ranges (unit fallback) and appends missing-value bits.
A column missing throughout training has median zero. Absolute times, identifiers and
labels are excluded from the input vector.

Fixed feature limits use the maximum absolute standardized deviation. EWMA measures
the deviation before updating with alpha 0.2 and resets to the training center at each
group, entity or time discontinuity. Both are offline comparisons. Isolation Forest
uses 100 deterministic trees, up to 256 training samples per tree and seed 42.
The deployed per-window score equals the negative sklearn score_samples. Training
checks parity against the exported JSON trees on calibration, validation and test.
The score measures unusualness on this profile. The profile covers five-second windows
of an observed destination TCP service on port 8080.

Each method sets its threshold on independent normal calibration exposure. The allowance
is floor(normal hours times one false window per hour). A score must strictly exceed
the threshold. The report lists normal exposure, false windows and detected fault windows
separately for each partition. Treat its test results as a held-out measurement for the
fixed experiment. Repeated measurements from one pause are correlated. Incident-level
rates require the incident policy in the subsequent milestone.

A completed experiment produces bundle.json and report.json. The model ID covers the
forest, preprocessing, threshold, training provenance and profile. Load only an operator-
selected local model file with its pinned SHA-256. Readiness reports success after checksum,
version and structure validation. Missing or incompatible bundles give 503. The application
accepts at most 100 windows and 2 MiB per request. Partial coverage, observation loss
or an unsupported profile produces insufficient_data with null score and threshold.
Use the report to assess release suitability separately from the ability to serve the file.
