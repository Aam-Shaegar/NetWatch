# Train and run the anomaly detector

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
fixed experiment. Repeated measurements from one pause are correlated. For incident-level results, see the [pilot measurements](operations-results.md).

A completed experiment produces bundle.json and report.json. The model ID covers the
forest, preprocessing, threshold, training provenance and profile. Load only an operator-
selected local model file with its pinned SHA-256. Readiness reports success after checksum,
version and structure validation. Missing or incompatible bundles give 503. The application
accepts at most 100 windows and 2 MiB per request. Partial coverage, observation loss
or an unsupported profile produces insufficient_data with null score and threshold.
Use the report to assess release suitability separately from the ability to serve the file.

## Server detector

The work stack loads one artifact selected by `NETWATCH_MODEL_DIR`,
`NETWATCH_MODEL_ID` and `NETWATCH_MODEL_SHA256`. The current candidate uses a
service-bound Isolation Forest bundle, `NETWATCH_CAPTURE_FEATURE_SET=traffic-v1`
and `NETWATCH_POLICY_VERSION=v2`. The feature version selects the window input.
The policy version controls how window scores become incidents. The same
settings apply across the work stack. Model bundles are kept outside Git.
MLP was used in offline comparisons as recorded in the
[benchmark summary](../../benchmarks/detection-results.md).

## Calibrate a detector for one service

Use this experimental training path for a new service or sensor. Collect representative
normal traffic on at least two separate captures. Export the five-second
`destination_service` windows from the Go sensor as JSONL. Keep a separate set of
normal and anomalous intervals for acceptance.

Create a version 1 JSON manifest beside the window files. Set `schema_version` to
`1`, `feature_set_version` to the version of the recorded windows, and `binding` to an object with the
exact `sensor_id` and TCP `entity_id` (for example `TCP/192.0.2.10:443`).
Under `captures`, put one or more entries in each of the `train` and `calibration`
arrays. Each entry has `label: "normal"`, `windows` (relative JSONL path),
`windows_sha256`, and `source_sha256` (of the underlying capture). Each capture
must have a unique epoch, source digest, event IDs and window timestamps. Supply
only aligned, complete windows with verified zero capture drops, late packets
and state evictions.

```sh
make train DATASET=data/processed/SERVICE OUTPUT=artifacts/SERVICE
```

Fit the feature transforms and forest on the training captures. Use the calibration
captures to set the threshold at the one false window per normal hour budget.
The report records the observed calibration exposure; with less than an hour,
the calibration budget allows zero exceedances. Use longer normal controls
covering the service's operating hours to measure a deployment false-alarm rate.

The candidate uses the same serving configuration as above. The bundle binds
predictions to that exact sensor and service. A different binding or an incomplete
observation returns `insufficient_data`. Use the Go incident policy to compare
false incidents, missed episodes and start/end errors with the deployed baseline
before selecting the candidate for `make work`.

For a profile with TCP connection ages, collect with
`netwatch-sensor live --feature-set traffic-v2` alongside the regular live
options and use `traffic-v2` in the training manifest. Offline extraction
accepts the same feature-set flag. A replayed PCAP without measured loss
information retains unknown capture quality.

For deployment, pin the matching scoped bundle and set
`NETWATCH_CAPTURE_FEATURE_SET=traffic-v2` in the work environment. Verify
that the configured sensor identity and TCP service match the bundle binding.
The work stack requires ML readiness with the configured feature set.
On changing the feature set, start a new capture epoch and use a matching
artifact for that version. See the [feature definitions](../../contracts/features.md).

## Compare incident policies

The candidate incident policy is enabled with `NETWATCH_POLICY_VERSION=v2`
in the work environment. The API, worker and ML service use the same setting.
The pinned scoring artifact can be reused for this comparison. Existing
incident streams retain their policy version. Changing the configured policy
creates new streams for new observations.

`make test-acceptance` takes the policy from the verified holdout manifest.
Check the estimated end separately from closure time. An interrupted episode
has an interruption time and an unresolved end. The worker persists the
reason an input was unscored. See the [policy rules](../adr/0007-incident-evidence-and-interruption.md).

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

GRU predictions are retained for observation. They do not open incidents.
The service bundle exports the Isolation Forest score, its threshold, and
the strongest service rule separately from the final score.
Set NETWATCH_SERVICE_MODEL_ENTITIES to a comma-separated list of exact
service entity IDs to scope live inference to the intended service profile.
