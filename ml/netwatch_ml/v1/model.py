"""Two-stage models for observations left unmatched by the NetWatch rules."""

import hashlib
import json
import math
import pickle
import re
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

FEATURE_SET = "traffic-v3"
TYPES = ("tcp_port_scan", "udp_flood", "icmp_flood")
LABELS = ("normal", *TYPES, "unknown")
COUNTS = (
    "in_tcp_distinct_ports_per_source_max",
    "in_udp_packets", "in_udp_ip_bytes", "in_icmp_packets", "in_icmp_ip_bytes",
)
COLUMNS = (
    "in_packets", "out_packets", "in_ip_bytes", "out_ip_bytes",
    "unique_peers", "unique_destination_ports", "active_flows", "new_tcp_attempts",
    "established_tcp_attempts", "completed_flow_count", "syn_fraction", "rst_fraction",
    "mean_packet_size", "std_packet_size", "mean_interarrival_seconds", "std_interarrival_seconds",
    *COUNTS,
)
SUPERVISED = ("gradient_boosting", "random_forest", "logistic_regression", "mlp")
CANDIDATES = {"find": (*SUPERVISED, "isolation_forest"), "classify": SUPERVISED}
VERSIONS = {"scikit_learn": sklearn.__version__, "numpy": np.__version__}
REQUIRED_SIGNALS = ("in_packets", COUNTS[0], COUNTS[1], COUNTS[3])
RATE_COLUMNS = frozenset(("in_packets", "out_packets", "in_ip_bytes", "out_ip_bytes", *COUNTS[1:]))


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False, indent=2) + "\n").encode()


def usable(window):
    quality = window["quality"]
    return (
        window["entity_type"] == "host" and window["feature_set_version"] == FEATURE_SET
        and quality["coverage"] == "complete" and quality["capture_dropped"] == 0
        and quality["late_packets"] == 0 and quality["state_evictions"] == 0
        and all(window["features"][key] is not None for key in REQUIRED_SIGNALS)
    )


def vector(window):
    seconds = (int(window["window_end_ns"]) - int(window["window_start_ns"])) / 1e9
    return [window["features"][key] / seconds if key in RATE_COLUMNS and window["features"][key] is not None
            else window["features"][key] for key in COLUMNS]


def matrix(windows):
    return np.asarray([vector(window) for window in windows], dtype=np.float64).reshape(-1, len(COLUMNS))


def make_estimator(name, seed):
    estimators = {
        "gradient_boosting": HistGradientBoostingClassifier(max_iter=100, class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(n_estimators=150, min_samples_leaf=2, class_weight="balanced", random_state=seed),
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed),
        "mlp": MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=500, random_state=seed),
        "isolation_forest": IsolationForest(n_estimators=150, random_state=seed),
    }
    return make_pipeline(SimpleImputer(strategy="median", keep_empty_features=True, add_indicator=True),
                         StandardScaler(), estimators[name])


def anomaly_scores(model, values):
    estimator = model["estimator"]
    if model["candidate"] == "isolation_forest":
        # score_samples is smaller for more anomalous points; sigmoid preserves rank.
        return 1 / (1 + np.exp(estimator.score_samples(values)))
    return estimator.predict_proba(values)[:, list(estimator.classes_).index(1)]


def classification_choices(model, values):
    estimator = model["estimator"]
    probabilities = estimator.predict_proba(values)
    indices = np.argmax(probabilities, axis=1)
    return estimator.classes_[indices], probabilities[np.arange(len(values)), indices]


def classify(model, values):
    labels, confidence = classification_choices(model, values)
    return np.where(confidence >= model["threshold"], labels, "unknown")


def predict(window, bundle):
    result = {
        "schema_version": 1, "event_id": window["event_id"], "model_id": bundle["model_id"],
        "feature_set_version": FEATURE_SET, "status": "insufficient_data", "score": None,
        "threshold": None, "attack_type": None,
    }
    if not usable(window):
        return result
    values = matrix((window,))
    detector = bundle["find"]
    score, threshold = float(anomaly_scores(detector, values)[0]), detector["threshold"]
    if not math.isfinite(score):
        raise ValueError("non-finite detector score")
    result.update(score=score, threshold=threshold, status="normal")
    if score >= threshold:
        result.update(status="anomalous", attack_type=str(classify(bundle["classify"], values)[0]))
    return result


def load_stage(directory, reference, stage):
    filename, digest = reference["file"], reference["sha256"]
    if not re.fullmatch(r"[a-z_]+\.pkl", filename) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid model reference")
    path = directory / filename
    if path.resolve().parent != directory.resolve():
        raise ValueError("model file escapes bundle directory")
    raw = path.read_bytes()
    if version(raw) != digest:
        raise ValueError("model artifact hash mismatch")
    try:
        model = pickle.loads(raw)
    except pickle.UnpicklingError as error:
        raise ValueError("model artifact cannot be loaded") from error
    if (model["candidate"] not in CANDIDATES[stage] or not math.isfinite(model["threshold"])
            or not 0 <= model["threshold"] <= math.nextafter(1.0, 2.0)):
        raise ValueError("invalid model stage")
    expected = set(TYPES) if stage == "classify" else {0, 1}
    if model["candidate"] != "isolation_forest" and set(model["estimator"].classes_) != expected:
        raise ValueError("incompatible model labels")
    return model


def load_bundle(path, checksum, expected_model_id=None):
    path = Path(path)
    raw = path.read_bytes()
    if not checksum or version(raw) != checksum:
        raise ValueError("bundle checksum mismatch")
    value = json.loads(raw)
    if (value["schema_version"] != 1 or value["feature_set"] != FEATURE_SET
            or tuple(value["columns"]) != COLUMNS or value["dependencies"] != VERSIONS
            or not re.fullmatch(r"v1-[0-9a-f]{24}", value["model_id"])
            or (expected_model_id and expected_model_id != value["model_id"])):
        raise ValueError("incompatible model bundle")
    return {"model_id": value["model_id"],
            **{stage: load_stage(path.parent, value[stage], stage) for stage in CANDIDATES}}
