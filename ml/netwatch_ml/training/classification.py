"""Train and evaluate window classification on independent audited capture groups."""

import argparse
import json
from pathlib import Path
import tempfile

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, log_loss

from netwatch_ml.data.dataset import read_run
from netwatch_ml.models.classifier import LABELS, probability, validate_classifier
from netwatch_ml.models.detector import (
    forest_score,
    load_bundle,
    matrix,
    model_id,
    transform,
)
from netwatch_ml.training.baselines import read_partitions, sha


def collect_rows(dataset, captures, sensor):
    parts = read_partitions(dataset)
    used_ids = {r["event_id"] for rows in parts.values() for r in rows}
    used_groups = {r["group_id"] for rows in parts.values() for r in rows}
    manifest = json.loads((dataset / "manifest.json").read_text())
    hashes = {v["sha256"] for v in manifest["groups"].values()}
    # Fixed before scoring; assigning by acquisition seed keeps each run intact.
    plan = {
        810: "train",
        811: "train",
        812: "train",
        813: "validation",
        814: "calibration",
        815: "calibration",
        910: "test",
        911: "test",
    }
    received = set()
    provenance = {}
    with tempfile.TemporaryDirectory() as tmp:
        for directory in captures:
            for path in sorted(directory.glob("*/manifest.json")):
                m, rows, _ = read_run(path.parent, sensor, Path(tmp))
                seed = m["seed"]
                if (
                    seed not in plan
                    or seed in received
                    or m["sha256"] in hashes
                    or m["group_id"] in used_groups
                    or m["profile"] != ("flash-crowd" if seed == 910 else "pause")
                ):
                    raise ValueError("capture provenance or group split mismatch")
                received.add(seed)
                hashes.add(m["sha256"])
                used_groups.add(m["group_id"])
                for row in rows:
                    if row["event_id"] in used_ids:
                        raise ValueError("reused window")
                    used_ids.add(row["event_id"])
                    if row["label"] in ("normal", "foreground_pause"):
                        parts[plan[seed]].append(row)
                provenance[m["group_id"]] = dict(
                    sha256=m["sha256"], part=plan[seed], seed=seed
                )
    if received != plan.keys():
        raise ValueError("incomplete capture collection")
    return parts, provenance


def portable(model, method):
    if method == "logistic":
        return dict(
            method=method,
            intercept=model.intercept_.item(),
            coefficients=model.coef_[0].tolist(),
        )
    trees = []
    for iteration in model._predictors:
        nodes = []
        for n in iteration[0].nodes:
            leaf = n["is_leaf"]
            nodes.append(
                [
                    int(n["feature_idx"]),
                    float(n["num_threshold"]),
                    -1 if leaf else int(n["left"]),
                    -1 if leaf else int(n["right"]),
                    float(n["value"]),
                ]
            )
        trees.append(nodes)
    return dict(method=method, intercept=model._baseline_prediction.item(), trees=trees)


def metrics(y, p, threshold):
    labels = (p >= 0.5).astype(int)
    accepted = np.maximum(p, 1 - p) >= threshold
    predictions = np.where(accepted, labels, -1)
    result = {}
    for i, label in enumerate(LABELS):
        tp = int(((y == i) & (predictions == i)).sum())
        positive = int((predictions == i).sum())
        support = int((y == i).sum())
        result[label] = dict(
            support=support,
            predicted=positive,
            true_positive=tp,
            precision=tp / positive if positive else None,
            recall=tp / support if support else None,
        )
    bins = []
    for i in range(10):
        selected = np.minimum((p * 10).astype(int), 9) == i
        if selected.any():
            bins.append(
                dict(
                    bin=i,
                    n=int(selected.sum()),
                    confidence=float(p[selected].mean()),
                    fraction_pause=float(y[selected].mean()),
                )
            )
    return dict(
        n=len(y),
        classes=result,
        accepted=int(accepted.sum()),
        coverage=float(accepted.mean()) if len(y) else None,
        risk=float((predictions[accepted] != y[accepted]).mean())
        if accepted.any()
        else None,
        brier=float(np.mean((p - y) ** 2)) if len(y) else None,
        log_loss=float(log_loss(y, p, labels=[0, 1])) if len(y) else None,
        ece=sum(b["n"] * abs(b["confidence"] - b["fraction_pause"]) for b in bins)
        / len(y)
        if len(y)
        else None,
        reliability=bins,
    )


def reliability_chart(path, report):
    # Standalone SVG; a point is one nonempty probability bin, with support in its title.
    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="680" height="380" viewBox="0 0 680 380">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<g font-family="sans-serif" font-size="13" fill="#142f3b">',
    ]
    for j, (key, title) in enumerate(
        [("all", "All test windows"), ("gated", "Anomalous test windows")]
    ):
        x = 48 + j * 335
        out += [
            f'<text x="{x}" y="28">{title}</text>',
            f'<path d="M{x} 55 V305 H{x + 240}" fill="none" stroke="#555"/>',
            f'<path d="M{x} 305 L{x + 240} 65" stroke="#999" stroke-dasharray="5 4"/>',
            f'<text x="{x}" y="326">0</text><text x="{x + 238}" y="326">1</text>',
            f'<text x="{x - 18}" y="70">1</text><text x="{x + 35}" y="352">Predicted pause probability</text>',
            f'<text transform="translate({x - 24},275) rotate(-90)">Observed pause fraction</text>',
        ]
        for b in report[key]["reliability"]:
            out.append(
                f'<circle cx="{x + 240 * b["confidence"]}" cy="{305 - 240 * b["fraction_pause"]}" r="5" fill="#176a80"><title>n={b["n"]}</title></circle>'
            )
    path.write_text("".join(out) + "</g></svg>\n")


def train(dataset, baseline, captures, sensor, dest):
    if dest.exists():
        raise FileExistsError(dest)
    baseline_report = json.loads((baseline / "report.json").read_text())
    detector = load_bundle(baseline / "bundle.json", baseline_report["bundle_sha256"])[
        "detector"
    ].copy()
    if (
        detector["dataset_manifest_sha256"] != sha(dataset / "manifest.json")
        or "classifier" in detector
    ):
        raise ValueError("baseline mismatch")
    parts, provenance = collect_rows(dataset, captures, sensor)
    xs = {
        k: transform(matrix(rows), detector["preprocessing"])
        for k, rows in parts.items()
    }
    ys = {
        k: np.array([int(r["label"] == "foreground_pause") for r in rows])
        for k, rows in parts.items()
    }
    if any(len(set(y)) != 2 for y in ys.values()):
        raise ValueError("both supervised classes required per split")
    methods = {
        "logistic": LogisticRegression(
            class_weight="balanced", max_iter=2000, random_state=42
        ),
        "histogram": HistGradientBoostingClassifier(
            max_iter=80,
            max_leaf_nodes=7,
            min_samples_leaf=5,
            class_weight="balanced",
            early_stopping=False,
            random_state=42,
        ),
    }
    scores = {}
    for name, model in methods.items():
        model.fit(xs["train"], ys["train"])
        scores[name] = float(
            average_precision_score(
                ys["validation"], model.predict_proba(xs["validation"])[:, 1]
            )
        )
    method = max(scores, key=scores.get)
    model = methods[method]
    cal = model.decision_function(xs["calibration"]).reshape(-1, 1)
    sigmoid = LogisticRegression(max_iter=1000).fit(cal, ys["calibration"])
    spec = dict(
        portable(model, method),
        labels=list(LABELS),
        sigmoid=[sigmoid.coef_.item(), sigmoid.intercept_.item()],
    )

    def probs(part):
        result = np.array([probability(x, spec) for x in xs[part]])
        expected = sigmoid.predict_proba(
            model.decision_function(xs[part]).reshape(-1, 1)
        )[:, 1]
        np.testing.assert_allclose(result, expected, atol=1e-10)
        return result

    # Prefer widest coverage with at most 5% observed selective risk on validation.
    v = probs("validation")
    thresholds = np.unique(np.maximum(v, 1 - v))
    spec["confidence"] = 1.0
    for t in thresholds:
        m = metrics(ys["validation"], v, float(t))
        if m["risk"] is not None and m["risk"] <= 0.05:
            spec["confidence"] = float(t)
            break
    validate_classifier(spec)
    detector["classifier"] = spec
    test = parts["test"]
    y, p = ys["test"], probs("test")
    gate = np.array(
        [
            forest_score(x, detector["forest"]) > detector["threshold"]
            for x in xs["test"]
        ]
    )
    mask = (p >= 0.5) & (np.maximum(p, 1 - p) >= spec["confidence"]) & gate
    pause_groups = {r["group_id"] for r in test if r["label"] == "foreground_pause"}
    hits = {
        r["group_id"]
        for r, hit in zip(test, mask)
        if hit and r["label"] == "foreground_pause"
    }
    crowd = np.array([r["profile"] == "flash-crowd" for r in test])
    report = dict(
        selected=method,
        validation_average_precision=scores,
        confidence=spec["confidence"],
        baseline=baseline_report["model_id"],
        extra_captures=provenance,
        support={
            k: dict(
                windows=len(y0),
                pause=int(y0.sum()),
                groups=len({r["group_id"] for r in parts[k]}),
            )
            for k, y0 in ys.items()
        },
        all=metrics(y, p, spec["confidence"]),
        gated=metrics(y[gate], p[gate], spec["confidence"]),
        cascade=dict(
            pause_windows=int(y.sum()),
            passed_gate=int(y[gate].sum()),
            classified_pause=int((mask & (y == 1)).sum()),
            events=len(pause_groups),
            events_detected=len(hits),
        ),
        flash_crowd=dict(
            windows=int(crowd.sum()),
            hours=float(crowd.sum() * 5 / 3600),
            anomalous=int((crowd & gate).sum()),
            classified_pause=int((crowd & mask).sum()),
            ddos_supported=False,
        ),
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        stage = Path(tmp) / "output"
        stage.mkdir()
        bundle = stage / "bundle.json"
        bundle.write_text(
            json.dumps(
                dict(model_id=model_id(detector), detector=detector),
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        digest = sha(bundle)
        loaded = load_bundle(bundle, digest)
        report.update(
            model_id=loaded["model_id"],
            classifier_version=loaded["classifier_version"],
            bundle_sha256=digest,
        )
        reliability_chart(stage / "reliability.svg", report)
        (stage / "report.json").write_text(
            json.dumps(report, indent=2, allow_nan=False) + "\n"
        )
        stage.rename(dest)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("dataset", "baseline", "sensor", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("captures", nargs="+", type=Path)
    a = parser.parse_args()
    print(
        json.dumps(
            train(a.dataset, a.baseline, a.captures, a.sensor.resolve(), a.output),
            indent=2,
        )
    )
