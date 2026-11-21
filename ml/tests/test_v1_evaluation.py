import copy
import json
from pathlib import Path

from fastapi.testclient import TestClient
import numpy as np
import pytest

from netwatch_ml.serving.app import create_app
from netwatch_ml.v1.dataset import records
from netwatch_ml.v1.evaluation import evaluate, train_models, type_report
from netwatch_ml.v1.model import CANDIDATES, COUNTS, FEATURE_SET, TYPES

ROOT = Path(__file__).resolve().parents[2]


def test_frozen_v1_comparison_and_serving(tmp_path):
    template = json.loads((ROOT / "contracts/examples/window.valid.json").read_text())
    captures, rows = [], []
    for split_number, split in enumerate(("train", "validation", "test", "pipeline"), 1):
        captures.append({
            "id": split, "group": split, "split": split, "host": template["entity_id"],
            "capture": {"sha256": f"{split_number:064x}"},
            "source": {"id": "fixture", "version": "1", "url": "https://example.invalid", "terms": "test"},
            "annotations": {"reference": "numeric fixture"},
            "coverage_start_ns": "0", "coverage_end_ns": "1000000000000",
            "capture_dropped": 0, "capture_loss_reference": "numeric fixture",
        })
        for label_number, label in enumerate(("normal", *TYPES, "unknown")):
            for example in range(10):
                time = (label_number * 10 + example) * 5 * 10**9
                window = copy.deepcopy(template)
                window.update(event_id=f"{split}-{label}-{example}", feature_set_version=FEATURE_SET,
                              window_start_ns=str(time), window_end_ns=str(time + 5 * 10**9))
                window["features"].update(dict.fromkeys(COUNTS, 0))
                window["features"].update(in_packets=42 + label_number * 7 + example,
                                          in_ip_bytes=2000 + label_number * 101 + example)
                if label == "tcp_port_scan":
                    window["features"][COUNTS[0]] = 10
                if label == "udp_flood":
                    window["features"].update(in_udp_packets=31, in_udp_ip_bytes=1700)
                if label == "icmp_flood":
                    window["features"].update(in_icmp_packets=29, in_icmp_ip_bytes=1400)
                window["quality"]["capture_dropped"] = 0
                rows.append({"capture": split, "window": window, "label": label, "family": split if label == "unknown" else None,
                             "episode": label, "onset_ns": time,
                             "route": {"event_id": window["event_id"], "status": "no_match", "attack_type": None}})
    dataset = tmp_path / "fixture.jsonl"
    header = {"schema_version": 1, "manifest_sha256": "a" * 64,
              "manifest": {"schema_version": 1, "dataset_id": "fixture", "version": "1", "captures": captures}}
    dataset.write_text("\n".join(map(json.dumps, (header, *rows))) + "\n")
    models = tmp_path / "models"
    chosen = train_models(dataset, models, seed=42, fpr=0.1, unknown_acceptance=0.1)
    for mode in ("find", "classify"):
        result = evaluate(dataset, models, mode)
        assert set(result["results"]) == set(CANDIDATES[mode])
        assert set(evaluate(dataset, models, mode, "mlp")["results"]) == {"mlp"}
    assert evaluate(dataset, models, "pipeline")["results"]["rules_ml"]["episodes"]["positive_episodes"] == 4

    bundle = models / "bundle.json"
    approved = TestClient(create_app(v1_bundle_path=bundle, v1_checksum=chosen["bundle_sha256"]))
    unapproved = TestClient(create_app(v1_bundle_path=bundle, v1_checksum="0" * 64))
    request = {"schema_version": 1, "model_id": chosen["model_id"], "window": rows[0]["window"]}
    assert approved.get("/health/ready").json()["model_id"] == chosen["model_id"]
    assert approved.post("/v1/detect", json=request).json()["status"] in ("normal", "anomalous")
    assert unapproved.post("/v1/detect", json=request).status_code == 503
    request["window"]["quality"]["capture_dropped"] = None
    result = approved.post("/v1/detect", json=request).json()
    assert result["status"] == "insufficient_data" and result["attack_type"] is None and result["score"] is None
    request["model_id"] = "wrong-model"
    assert approved.post("/v1/detect", json=request).status_code == 409

    captures[1]["group"] = captures[0]["group"]
    with pytest.raises(ValueError, match="group appears in multiple splits"):
        records(header["manifest"])


def test_no_anomaly_reaches_stage_two():
    labels = (*TYPES, "unknown")
    empty = np.asarray([], dtype="U32")
    report = type_report(empty, empty, labels)
    assert report["samples"] == 0
    assert report["confusion_matrix"] == [[0] * len(labels)] * len(labels)
    assert report["unknown_recall"] is None
