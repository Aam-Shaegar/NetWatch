import json
import pytest

from netwatch_ml.contracts import ROOT, validate
from netwatch_ml.models.patterns import match, validate_limits


LIMITS = dict(large_upload=1000, large_response=30000, connection_surge=120, total_in_bytes=1500, total_out_bytes=60000)


@pytest.mark.parametrize(("changes", "label"), [
    (dict(in_ip_bytes=3000), "large_upload"),
    (dict(out_ip_bytes=90000), "large_response"),
    (dict(new_tcp_attempts=150), "connection_surge"),
    (dict(new_tcp_attempts=0), "persistent_exchange"),
])
def test_pattern_contract(changes, label):
    features = dict(active_flows=1, in_packets=12, out_packets=12, in_ip_bytes=500,
                    out_ip_bytes=600, new_tcp_attempts=1)
    found, ratio = match(dict(features, **changes), LIMITS)
    assert found == label and ratio > 1
    fixture = json.loads((ROOT / "contracts/examples/prediction.valid.json").read_text())
    validate("prediction", dict(fixture, classification=dict(label=label, probability=None, version="cls-"+"a"*24)))
    assert match(dict(features, active_flows=None), LIMITS) == (None, 0)
    assert match(dict(features, in_ip_bytes=1000), LIMITS)[1] < 1


def test_invalid_limit():
    with pytest.raises(ValueError):
        validate_limits(dict(LIMITS, large_upload=float("nan")))


def test_patterns_can_open_gate_when_forest_is_below_threshold(monkeypatch):
    from netwatch_ml.models import detector
    w = json.loads((ROOT / "contracts/examples/window.valid.json").read_text())
    w.update(entity_type="destination_service", entity_id="TCP/192.0.2.1:8080")
    w["features"].update(active_flows=1, new_tcp_attempts=1, in_ip_bytes=2000, out_ip_bytes=600)
    w["quality"]["capture_dropped"] = 0
    monkeypatch.setattr(detector, "forest_score", lambda x, forest: 0.1)
    payload = dict(forest={}, threshold=0.7, pattern_limits=LIMITS,
                   preprocessing=dict(median=[0] * detector.WIDTH, scale=[1] * detector.WIDTH))
    bundle = dict(model_id="if-test", classifier_version="cls-"+"a"*24, detector=payload)
    result = detector.predict_window(w, bundle)
    assert result["classification"]["label"] == "large_upload"
    assert result["score"] > result["threshold"] and result["status"] == "anomalous"
    assert result["classification"]["probability"] is None
    w["quality"]["capture_dropped"] = 2
    assert detector.predict_window(w, bundle)["status"] == "insufficient_data"

def test_background_only_does_not_mask_pause():
    features = dict(active_flows=2, in_packets=10, out_packets=12, in_ip_bytes=900,
                    out_ip_bytes=66000, new_tcp_attempts=2)
    assert match(features, dict(LIMITS, total_out_bytes=200000))[1] < 1
