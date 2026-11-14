import copy
import json

import numpy as np
import pytest
from jsonschema import ValidationError
from sklearn.ensemble import HistGradientBoostingClassifier

from netwatch_ml.contracts import ROOT, validate
from netwatch_ml.models.classifier import (
    LABELS,
    classify,
    probability,
    validate_classifier,
    version,
)
from netwatch_ml.models.detector import WIDTH
from netwatch_ml.training.classification import metrics, portable


def test_boosting_export_parity():
    rng = np.random.default_rng(12)
    x = rng.normal(size=(80, WIDTH * 2))
    model = HistGradientBoostingClassifier(
        max_iter=5, min_samples_leaf=3, random_state=42
    ).fit(x, x[:, 0] > 0)
    spec = dict(
        portable(model, "histogram"),
        labels=list(LABELS),
        sigmoid=[1.0, 0.0],
        confidence=0.8,
    )
    validate_classifier(spec)
    np.testing.assert_allclose(
        [probability(v, spec) for v in x], model.predict_proba(x)[:, 1]
    )
    invalid = copy.deepcopy(spec)
    invalid["trees"][0][0][2] = 0
    with pytest.raises(ValueError):
        validate_classifier(invalid)


def test_abstention_and_contract():
    spec = dict(
        labels=list(LABELS),
        method="logistic",
        coefficients=[0.0] * (WIDTH * 2),
        intercept=0.0,
        sigmoid=[1.0, 0.0],
        confidence=0.8,
    )
    result = classify(np.zeros(2 * WIDTH), spec, version(spec))
    assert result["label"] == "unknown" and result["probability"] is None
    fixture = json.loads(
        (ROOT / "contracts/examples/prediction.valid.json").read_text()
    )
    validate("prediction", dict(fixture, classification=result))
    with pytest.raises(ValidationError):
        validate(
            "prediction", dict(fixture, classification=dict(result, probability=0.95))
        )


def test_abstention_counts_as_miss():
    result = metrics(np.array([0, 1, 1]), np.array([0.01, 0.55, 0.99]), 0.8)
    assert result["classes"]["foreground_pause"]["recall"] == 0.5
    assert result["classes"]["foreground_pause"]["precision"] == 1
    assert sum(b["n"] for b in result["reliability"]) == 3


@pytest.mark.parametrize(("coverage", "dropped", "label"), [
    ("complete", 0, "unknown"), ("partial", 0, "insufficient_data"),
    ("complete", 1, "insufficient_data"),
])
def test_outside_profile_abstention(coverage, dropped, label):
    from netwatch_ml.models.detector import predict_window

    window = json.loads((ROOT / "contracts/examples/window.valid.json").read_text())
    window.update(entity_type="host", window_start_ns="0", window_end_ns="5000000000")
    window["quality"].update(coverage=coverage, capture_dropped=dropped, late_packets=0, state_evictions=0)
    result = predict_window(window, dict(model_id="if-test", classifier_version="cls-" + "a" * 24))
    assert result["classification"] == dict(label=label, probability=None, version="cls-" + "a" * 24)
