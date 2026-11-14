"""Portable binary classifier for audited TCP/8080 service windows."""

import hashlib
import json
import math

import numpy as np

from netwatch_ml.models.detector import WIDTH

LABELS = ("benign", "foreground_pause")


def version(spec):
    raw = json.dumps(
        spec, sort_keys=True, allow_nan=False, separators=(",", ":")
    ).encode()
    return "cls-" + hashlib.sha256(raw).hexdigest()[:24]


def validate_classifier(spec):
    if spec["labels"] != list(LABELS) or not 0.5 <= spec["confidence"] <= 1:
        raise ValueError("invalid classifier taxonomy or confidence")
    params = [spec["intercept"], *spec["sigmoid"]]
    if len(spec["sigmoid"]) != 2:
        raise ValueError("invalid calibration")
    if spec["method"] == "logistic":
        if len(spec["coefficients"]) != 2 * WIDTH:
            raise ValueError("classifier width mismatch")
        params.extend(spec["coefficients"])
    elif spec["method"] == "histogram":
        if not 1 <= len(spec["trees"]) <= 256:
            raise ValueError("invalid classifier tree count")
        for tree in spec["trees"]:
            if not 1 <= len(tree) <= 511:
                raise ValueError("invalid classifier tree size")
            for i, (feature, cut, left, right, value) in enumerate(tree):
                if left != -1 or right != -1:
                    if not (
                        type(feature) is int
                        and 0 <= feature < 2 * WIDTH
                        and type(left) is int
                        and type(right) is int
                        and i < left < len(tree)
                        and i < right < len(tree)
                    ):
                        raise ValueError("invalid classifier node")
                params.extend((cut, value))
    else:
        raise ValueError("unknown classifier")
    if not all(math.isfinite(v) for v in params):
        raise ValueError("non-finite classifier parameter")


def probability(x, spec):
    raw = spec["intercept"]
    if spec["method"] == "logistic":
        raw += np.dot(x, spec["coefficients"])
    else:
        for tree in spec["trees"]:
            node = tree[0]
            while node[2] != -1:
                node = tree[node[2] if x[node[0]] <= node[1] else node[3]]
            raw += node[4]
    slope, bias = spec["sigmoid"]
    return float(1 / (1 + math.exp(-float(np.clip(slope * raw + bias, -700, 700)))))


def classify(x, spec, model_version):
    p = probability(x, spec)
    confidence = max(p, 1 - p)
    if confidence < spec["confidence"]:
        return dict(label="unknown", probability=None, version=model_version)
    return dict(
        label=LABELS[int(p >= 0.5)], probability=confidence, version=model_version
    )
