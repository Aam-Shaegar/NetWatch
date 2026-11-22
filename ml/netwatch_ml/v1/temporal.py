"""Frozen 30-second detector for successive five-second host observations."""

import json
import math
import pickle
from pathlib import Path

import numpy as np

from netwatch_ml.contracts import validate
from netwatch_ml.v1 import model

MANIFEST_SHA256 = "a721ab9def3befdc68c8d3c5b599ece56395afe8fc05ed8cf318adb378f0a2ae"
BASE_SHA256 = "6e768f7714c058113221ec3af9eb5fb8b167ab53ab7809b3eafb2f393139f717"
MODEL_ID = "v1-temporal-" + MANIFEST_SHA256[:24]
THRESHOLD = 0.9978790881906234
HORIZON = 6
STEP_NS = 5_000_000_000
STREAM_FIELDS = ("sensor_id", "capture_epoch", "entity_type", "entity_id")


def load(path, base_checksum):
    manifest = Path(path)
    raw = manifest.read_bytes()
    if model.version(raw) != MANIFEST_SHA256:
        raise ValueError("unexpected temporal manifest")
    spec = json.loads(raw)
    if (base_checksum != BASE_SHA256 or spec["base_sha256"] != base_checksum
            or spec["threshold"] != THRESHOLD or spec["horizon"] != HORIZON):
        raise ValueError("incompatible temporal configuration")
    weights = manifest.with_name(spec["file"])
    if weights.resolve().parent != manifest.resolve().parent:
        raise ValueError("temporal model escapes bundle directory")
    raw = weights.read_bytes()
    if model.version(raw) != spec["model_sha256"]:
        raise ValueError("temporal model artifact hash mismatch")
    # Both the manifest and the exact bytes being deserialized are pinned.
    return pickle.loads(raw)


def validate_history(window, history):
    if not isinstance(history, list) or len(history) >= HORIZON:
        raise ValueError("expected up to five previous windows")
    ids = {window["event_id"]}
    next_start = int(window["window_start_ns"])
    for prior in reversed(history):
        validate("window", prior)
        if (any(prior[key] != window[key] for key in STREAM_FIELDS)
                or prior["event_id"] in ids or int(prior["window_end_ns"]) > next_start):
            raise ValueError("history must be chronological and belong to the same stream")
        next_start = int(prior["window_start_ns"])
        ids.add(prior["event_id"])


def window_signals(window):
    features = window["features"]

    def value(key):
        return float(features[key] or 0)

    incoming, outgoing = value("in_packets"), value("out_packets")
    packets = incoming + outgoing
    starts = value("new_tcp_attempts")
    return np.array([
        starts, starts * starts, starts > 0, value("established_tcp_attempts"),
        value("completed_flow_count"), incoming, outgoing, value("in_ip_bytes"),
        value("out_ip_bytes"), value("unique_peers"), value("in_tcp_distinct_ports_per_source_max"),
        value("rst_fraction") * packets, value("syn_fraction") * packets,
        value("in_udp_packets") + value("in_icmp_packets"), value("active_flows"),
        value("unique_destination_ports"),
    ], dtype=float)


def temporal_features(window, history):
    """Use the contiguous, usable tail. The worker supplies a validated, bounded history."""
    suffix = []
    next_start = int(window["window_end_ns"])
    for observation in (window, *reversed(history)):
        start, end = int(observation["window_start_ns"]), int(observation["window_end_ns"])
        if end != next_start or end - start != STEP_NS or not model.usable(observation):
            break
        suffix.append(window_signals(observation))
        next_start = start
    if len(suffix) < 2:
        return None

    # Feature order, activity gates and normalizers follow the fitted model.
    current = suffix[0]
    total = np.sum(suffix[::-1], axis=0)
    (starts, sum_squares, busy, established, completed, incoming, outgoing, in_bytes, out_bytes,
     peers, port_fanout, resets, syns, other_protocols, flows, dest_ports) = total
    if (busy < 2 or current[5] + current[6] == 0
            or (current[0] == 0 and current[5] <= current[13] and current[6] == 0)):
        return None
    length = len(suffix)
    packets = incoming + outgoing
    mean = starts / length
    deviation = np.sqrt(max(0, sum_squares / length - mean**2))
    return np.array([
        np.log1p(mean), busy / length, deviation / (1 + mean), established / (1 + starts),
        completed / (1 + starts), np.log1p(incoming / (1 + starts)), np.log1p(outgoing / (1 + starts)),
        np.log1p(in_bytes / (1 + incoming)), np.log1p(out_bytes / (1 + outgoing)),
        np.log1p(peers / length), port_fanout / length, resets / (1 + packets),
        syns / (1 + packets), other_protocols / (1 + incoming), np.log1p(flows / length),
        np.log1p(dest_ports / length),
    ])


def predict(window, base, history, estimator):
    result = model.predict(window, base)
    result["model_id"] = MODEL_ID
    if result["status"] != "normal":
        return result
    features = temporal_features(window, history)
    if features is not None:
        score = float(estimator.predict_proba(features.reshape(1, -1))[0, 1])
        if not math.isfinite(score):
            raise ValueError("non-finite temporal score")
        if score >= THRESHOLD:
            result.update(status="anomalous", attack_type="unknown", score=score,
                          threshold=THRESHOLD, detector_stage="temporal")
    return result
