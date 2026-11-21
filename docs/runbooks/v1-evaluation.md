# NetWatch v1 model training and acceptance

NetWatch extracts `traffic-v3` host windows from saved PCAP/PCAPNG with `netwatch-sensor replay`. The same Go rules used by the analyzer supply the route for each window. Models fit only on rule misses from eligible windows. A held-out family calibrates the refusal threshold and stays out of the training data. Final use of `Unknown` is measured on different held-out families.

## Data and artifact commands

```sh
make v1-data V1_MANIFEST=/path/to/manifest.json V1_DATA=data/processed/v1/development.jsonl
make v1-train V1_DATA=data/processed/v1/development.jsonl V1_MODELS=artifacts/v1
make v1-data V1_MANIFEST=/path/to/holdout.json V1_DATA=data/processed/v1/holdout.jsonl
make test-find V1_TEST_DATA=data/processed/v1/holdout.jsonl MODEL=random_forest
make test-classify V1_TEST_DATA=data/processed/v1/holdout.jsonl MODEL=mlp
make test-full V1_PIPELINE_DATA=data/processed/v1/holdout.jsonl
```

Omit `MODEL` to compare all applicable frozen candidates for each stage on the same observations. `test-full` uses the validation-selected classifier and detector. The pipeline command compares Rules with Rules plus ML on its own split. Reports print in the terminal and are saved into `outputs/v1` by default. The full test is an offline replay of the analysis logic. Its timings cover Python batch inference. The live stack needs separate throughput and resource measurements.

Keep the candidate directory in `artifacts`, the raw data and manifest in ignored `data` directories, and evaluation outputs in `outputs`. Use the reported model ID and `bundle.json` SHA-256 for `NETWATCH_MODEL_ID` and `NETWATCH_V1_MODEL_SHA256`, with `NETWATCH_V1_MODEL_BUNDLE` pointing to the approved read-only bundle. Install a matching locked environment for the approved bundle. Only approve artifacts you trust. Scikit-learn models are serialized with pickle.

## Manifest and reference labels

The JSON manifest has `schema_version: 1`, `dataset_id`, `version`, and a `captures` array. Each capture entry has these fields.

| Field | Value |
| --- | --- |
| `id` | Unique short identifier using letters, digits, `_` or `-` |
| `group` | Original environment or run identity shared by all excerpts and sensor views |
| `split` | `train`, `validation`, `test`, or a distinct `pipeline` holdout |
| `capture` | Object with `path` relative to the manifest and full `sha256` |
| `source` | Object with publisher `id`, `version`, `url`, and `terms` |
| `host` | Canonical IP of the protected destination |
| `coverage_start_ns`, `coverage_end_ns` | Verified capture bounds as Unix nanosecond strings. The end is exclusive. |
| `capture_dropped` | Measured nonnegative count, or `null` when unknown. A measured value also requires `capture_loss_reference` with its provenance. |
| `annotations` | Object with `path`, `sha256`, `reference`, `format`, and an optional `label_map` |

Supported annotation formats are `genis` for publisher ground-truth CSV, `gotham` for packet-level CSV corresponding to the exact capture and view, and `interval_csv` for reviewed source intervals keyed by `host,start_ns,end_ns,episode_id,label`. Use `interval_csv` for corrected CIC annotations after matching published intervals against the original capture. Give known types their catalogue name. Give withheld test families `unknown:<family>` with a stable lowercase family ID, and give measured normal intervals `normal`. Mixed labels and uncovered intervals remain unlabeled. Exact onset latency needs interval bounds or authoritative packet timestamps; Gotham's packet bucket metrics have window resolution.

Use [Gotham TCP scanning](https://zenodo.org/records/14502760) only where the published trace covers the one-host TCP pattern. Its [deposit metadata](https://zenodo.org/records/14502760/export/json) specifies CC BY 4.0. [GeNIS](https://zenodo.org/records/14919237) provides UDP and ICMP intervals. Cite the [GeNIS article](https://doi.org/10.1016/j.dib.2025.111487) and verify the archive rights for the intended reuse. [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) with [corrected labels](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html), [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html), and [CICIoT2023](https://www.mdpi.com/1424-8220/23/13/5941) offer additional scenario inputs. UNB requests citation of its CIC-IDS2017 paper and requires citation of the CIC-DDoS2019 dataset and paper. Whole-capture labels support scenario checks. Interval tests require a reviewed timeline. Already studied Gotham, GeNIS, Kitsune and other registered captures remain development or regression material. The importer rejects registered used capture hashes from holdouts. Record original run identity for repackaged and sliced copies since SHA-256 alone cannot connect them.

Each stage needs labeled examples from eligible rule misses. The split cannot repeat capture groups or bytes. Choose development and final test groups by original environment or run before selecting thresholds. Compile development and holdout with the same sensor binary, rules binary and `NETWATCH_DISABLED_RULES` setting. Coverage gaps and an unknown dropped-packet count stay unscored. Check coverage before planning a trial on public captures, which often omit loss evidence.

Stage 1 compares gradient boosting, Random Forest, logistic regression, MLP, and Isolation Forest. Stage 2 compares the four supervised classifiers. Isolation Forest's scalar anomaly score does not supply a multiclass posterior. Default threshold-search budgets are tunable with `V1_MAX_FPR` and `V1_MAX_UNKNOWN_ACCEPTANCE` before final evaluation. Neither default is a measured or approved release target.
