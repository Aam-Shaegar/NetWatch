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

## GRU forecast and incident-level comparison

Use the audited capture collection corresponding to the Parquet dataset, the
trained baseline directory from the same manifest and a new output directory.

```sh
make compare DATASET=data/processed/EXPERIMENT COLLECTION=data/runs/COLLECTION BASELINE=artifacts/BASELINE OUTPUT=artifacts/FORECAST
```

The comparison writes a checksum-pinned GRU bundle and a report containing the
validation losses, selected epoch, thresholds, scoring coverage, observed normal
hours, missed events and individual event-time detection delays. Model weights
and capture data stay local. The GRU uses the previous twelve continuous
five-second windows of one stream to predict the next sixteen features. A
64-unit GRU receives the standardized measurements and missingness indicators.
The model trains on normal histories and targets with masked Huber loss, AdamW,
minibatches of 128 and seed 42 on a single CPU thread. Training restores the
lowest normal validation loss after five epochs without improvement or 50 epochs.
Absolute errors are divided by median residuals on normal validation sequences
(floor 0.01) and averaged over observed coordinates.

For evaluation, complete windows including mixed event boundaries can supply
causal history. The script verifies their capture checksums and scores all four
methods on the same timelines. Only audited normal windows contribute normal
exposure. The calibration budget is one false **window** per scored normal
hour. Incident metrics use total audited normal exposure, including GRU warmup.
Opening requires two exceedances in three continuous scored windows, closing
requires three consecutive scores at or below 95% of threshold. A fault is
detected when an incident opens during its recorded interval. Delay runs from
fault onset to the end of the triggering window. These are event-time delays;
they exclude queue and inference latency.

Selection compares the two deployable detectors on validation, prioritizing the
window budget, missed events, false incident rate, false window rate, then delay.
Fixed limits and EWMA are offline benchmarks. Test results are measured after
selection. See the [laboratory comparison](forecast-results.md).

To run the experimental model, use the same environment and startup commands as
for Isolation Forest with the GRU bundle path, checksum and model ID from its
report. The worker queries PostgreSQL for up to twelve preceding windows of the
same sensor, epoch and entity. Each request carries its own history. A short
history, discontinuity or invalid observation in that history yields warming_up.
The worker uses the observations present when it processes the job. A late
arrival does not retroactively change a completed prediction. To verify the
stored score through the worker, choose a capture with thirteen continuous
supported windows of one stream.

```sh
ml/.venv/bin/python scripts/detector_smoke.py artifacts/FORECAST data/runs/COLLECTION/GROUP/live.jsonl
```
