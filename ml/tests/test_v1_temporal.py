import json
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from netwatch_ml.serving.app import create_app
from netwatch_ml.v1 import model, temporal

ROOT = Path(__file__).resolve().parents[2]
WEIGHTS = ROOT / "deploy/models/temporal-r5"


def client(**overrides):
    config = dict(v1_bundle_path=WEIGHTS / "bundle.json", v1_checksum=temporal.BASE_SHA256,
                  temporal_bundle_path=WEIGHTS / "temporal.json", expected_model_id=temporal.MODEL_ID)
    return TestClient(create_app(**(config | overrides)))


def window(index):
    sample = json.loads((ROOT / "contracts/examples/window.valid.json").read_bytes())
    sample.update(feature_set_version=model.FEATURE_SET, event_id=f"fixture-{index}",
                  window_start_ns=str(index * temporal.STEP_NS),
                  window_end_ns=str((index + 1) * temporal.STEP_NS))
    sample["quality"]["capture_dropped"] = 0
    sample["features"].update(dict.fromkeys(model.COUNTS, 0))
    sample["features"].update(
        in_packets=110, out_packets=130, in_ip_bytes=15400, out_ip_bytes=17400, active_flows=20,
        new_tcp_attempts=10, established_tcp_attempts=10, completed_flow_count=10,
        unique_destination_ports=20, in_tcp_distinct_ports_per_source_max=1, mean_packet_size=136,
        std_packet_size=221, syn_fraction=.083, mean_interarrival_seconds=.008,
        std_interarrival_seconds=.1,
    )
    return sample


def request(current, history):
    return dict(schema_version=1, model_id=temporal.MODEL_ID, window=current, history=history)


def test_frozen_temporal_prediction_and_quality_resets():
    api = client()
    prev, now = window(0), window(1)
    assert api.get("/health/ready").json()["model_id"] == temporal.MODEL_ID
    body = request(now, [prev])
    result = api.post("/v1/detect", json=body).json()
    assert (result["event_id"], result["model_id"], result["detector_stage"]) == (
        now["event_id"], temporal.MODEL_ID, "temporal")
    assert result["status"] == "anomalous" and result["attack_type"] == "unknown"
    assert result["threshold"] == 0.9978790881906234
    assert result["score"] == pytest.approx(0.9981836694063183)
    for current, history in ((now, []), (window(2), [prev])):
        assert api.post("/v1/detect", json=request(current, history)).json()["status"] == "normal"
    for key, value in (("capture_dropped", None), ("capture_dropped", 1), ("coverage", "partial"),
                       ("late_packets", 1), ("state_evictions", 1)):
        invalid = deepcopy(prev)
        invalid["quality"][key] = value
        assert api.post("/v1/detect", json=request(now, [invalid])).json()["status"] == "normal"
        assert api.post("/v1/detect", json=request(invalid, [])).json()["status"] == "insufficient_data"


def test_history_contract_and_validation_of_artifacts(tmp_path):
    api = client()
    prev, now = window(0), window(1)
    for wrong in ([window(2)], [prev, prev], [dict(prev, entity_id="192.0.2.2")],
                  [dict(prev, sensor_id="another")], [dict(prev, capture_epoch="restarted")],
                  [dict(prev, event_id=now["event_id"])], [window(i) for i in range(6)]):
        assert api.post("/v1/detect", json=request(now, wrong)).status_code == 422
    body = request(now, [])
    assert api.post("/v1/detect", json=body | {"model_id": "different"}).status_code == 409
    del body["history"]
    assert api.post("/v1/detect", json=body).status_code == 422

    manifest = tmp_path / "temporal.json"
    manifest.write_bytes((WEIGHTS / "temporal.json").read_bytes())
    (tmp_path / "rescue.pkl").write_bytes(b"wrong weights")
    assert client(temporal_bundle_path=manifest).get("/health/ready").status_code == 503
    manifest.write_bytes(b"{}")
    assert client(temporal_bundle_path=manifest).get("/health/ready").status_code == 503
    assert client(expected_model_id="different").get("/health/ready").status_code == 503
    assert client(temporal_bundle_path=None).get("/health/ready").status_code == 503
