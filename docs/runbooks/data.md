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

## Own training data after extractor exists

Collect stable/ramp/flash-crowd/background-transfer runs with varied seeds, targets and schedules.
Initial design: at least 20 independent normal runs of 10–30 minutes, then expand based on coverage.
Separate complete runs into train/validation/calibration/test; never random neighboring windows.
Add benign high-load runs before evaluating anomaly models. Keep class prevalence and unseen scenarios.
For each run save actual start/stop, configuration, commit, image IDs, capture quality, achieved rate and target metrics.
Keep label join separate from features. No IP/run_id/filename/absolute date in model inputs.
Do not call these quantities statistically sufficient before evaluating learning curves and uncertainty.

## Collect an independent normal run

From the project root run `python3 scripts/lab_smoke.py --profile ramp --duration 600 --rate 10 --seed 17`. Supported profiles: stable, ramp, flash-crowd. The client connects only to the lab target. Repeat with different seeds and workloads. Each run keeps PCAP, request start/end times, scenario settings, image ID, SHA256 and run/group ID in its own ignored directory under data/runs. Before training, validate capture integrity and coverage, freeze group splits, and extract windows with the same Go module used in serving.

## Verified external replay sample

IoT-23, CTU-Honeypot-Capture-7-1 / Somfy-01. Authors' catalog: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/ . Read all 8276 records (5087.822 seconds). Restore on another machine with `python3 scripts/fetch_sample.py`. The checked manifest records source, byte count and SHA256. Keep the raw file outside Git. Use this one IoT observation for offline compatibility and an external data point, separately from service-load experiments. Labels and deployment transfer need validation before training.
