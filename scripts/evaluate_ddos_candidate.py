"""Measure false DDoS calls on a legitimate flash crowd with an offline candidate."""

import argparse
import json
from pathlib import Path
import tempfile

import numpy as np
from sklearn.linear_model import LogisticRegression

from netwatch_ml.data.dataset import read_run
from netwatch_ml.models.detector import fit_transform_parameters, matrix, transform
from netwatch_ml.training.baselines import read_partitions


def complete_service_windows(audit, name):
    with (audit / (name + ".jsonl")).open() as stream:
        windows = [json.loads(line)["window"] for line in stream]
    if any(w["entity_type"] != "destination_service" for w in windows):
        raise ValueError("expected service windows")
    return [w["features"] for w in windows if w["quality"]["coverage"] == "complete"]


def measure(dataset, audit, crowd_run, sensor):
    parts = read_partitions(dataset)
    with tempfile.TemporaryDirectory() as scratch:
        manifest, rows, _ = read_run(crowd_run, sensor, Path(scratch))
    if manifest["profile"] != "flash-crowd" or manifest["seed"] != 910:
        raise ValueError("expected the reserved legitimate flash crowd")
    if any(r["group_id"] == manifest["group_id"] for part in parts.values() for r in part):
        raise ValueError("flash crowd overlaps base dataset")
    crowd = [r for r in rows if r["label"] == "normal"]
    positive = complete_service_windows(audit, "Friday-ddos.pcap")
    external = complete_service_windows(audit, "CIC-DDoS-2019-WebDDoS.pcap")
    normal = parts["train"]
    if not positive or not external or not crowd:
        raise ValueError("empty evaluation or training group")
    x = matrix(normal + positive)
    params = fit_transform_parameters(x)
    model = LogisticRegression(class_weight="balanced", random_state=42, max_iter=2000)
    model.fit(transform(x, params), np.repeat([0, 1], [len(normal), len(positive)]))

    def calls(sample):
        return int(model.predict(transform(matrix(sample), params)).sum())

    false_calls = calls(crowd)
    return dict(training_benign_windows=len(normal), training_ddos_windows=len(positive),
                training_ddos_calls=calls(positive), external_scenario_windows=len(external),
                external_ddos_calls=calls(external), flash_crowd_windows=len(crowd),
                flash_crowd_false_ddos=false_calls, flash_crowd_false_fraction=false_calls / len(crowd),
                flash_crowd_seconds=5 * len(crowd), flash_crowd_capture_sha256=manifest["sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("dataset", "audit", "crowd_run", "sensor"):
        parser.add_argument(key, type=Path)
    args = parser.parse_args()
    print(json.dumps(measure(args.dataset, args.audit, args.crowd_run, args.sensor.resolve()), indent=2))
