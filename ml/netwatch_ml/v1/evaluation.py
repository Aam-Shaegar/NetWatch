"""Train on development folds and measure frozen candidates on disjoint folds."""

from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import pickle
import platform
import resource
import sys
import time
import tempfile
from datetime import datetime, timezone

import numpy as np
from sklearn import metrics

from netwatch_ml.v1.dataset import load_dataset, require
from netwatch_ml.v1.model import (
    CANDIDATES, COLUMNS, FEATURE_SET, LABELS, TYPES, VERSIONS, anomaly_scores, classification_choices,
    classify, encoded, load_stage, make_estimator, matrix, sha256, version,
)


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def residual(rows, split):
    return [row for row in rows if row["split"] == split and row["label"] is not None
            and row["route"]["status"] == "no_match"]


def inputs(rows):
    return matrix(row["window"] for row in rows), np.asarray([row["label"] for row in rows])


def binary(labels):
    return (labels != "normal").astype(int)


def threshold_for_find(truth, scores, max_fpr):
    require(set(truth) == {0, 1}, "binary validation requires normal and anomaly examples")
    fp, tp, thresholds = metrics.roc_curve(truth, scores, drop_intermediate=False)
    candidates = [(float(tpr), -float(fpr), min(float(value), math.nextafter(1., 2.)))
                  for fpr, tpr, value in zip(fp, tp, thresholds) if fpr <= max_fpr]
    return max(candidates)


def threshold_for_classify(truth, labels, confidence, max_unknown_acceptance):
    unknown = truth == "unknown"
    require(unknown.any() and (~unknown).any(), "type validation requires known classes and held-out unknown families")
    order = np.argsort(-confidence, kind="stable")
    seen_unknown, correct, rank = 0, 0, 0
    total_unknown = int(unknown.sum())
    best = (0., 1., math.nextafter(1., 2.))
    while rank < len(order):
        threshold = float(confidence[order[rank]])
        while rank < len(order) and confidence[order[rank]] == threshold:
            index = order[rank]
            seen_unknown += int(unknown[index])
            correct += int(not unknown[index] and labels[index] == truth[index])
            rank += 1
        acceptance = seen_unknown / total_unknown
        if acceptance <= max_unknown_acceptance:
            best = max(best, (correct / (len(truth) - total_unknown), 1 - acceptance, threshold))
    return best


def stage_training(stage, train, validation, seed, budget):
    train_values, train_labels = inputs(train)
    validation_values, validation_labels = inputs(validation)
    require(set(TYPES) <= set(train_labels) and set(TYPES) <= set(validation_labels),
            "each known type needs usable rules-unmatched training and validation examples")
    if stage == "find":
        # A held-out family is never used to fit binary model weights.
        training_labels = binary(train_labels)
        require(set(training_labels) == {0, 1}, "binary training requires normal and anomaly examples")
    else:
        selected = np.isin(train_labels, TYPES)
        train_values, train_labels = train_values[selected], train_labels[selected]
        selected_validation = validation_labels != "normal"
        validation_values, validation_labels = validation_values[selected_validation], validation_labels[selected_validation]
    for name in CANDIDATES[stage]:
        estimator = make_estimator(name, seed)
        model = {"candidate": name, "estimator": estimator}
        if stage == "find":
            if name == "isolation_forest":
                estimator.fit(train_values[training_labels == 0])
            else:
                estimator.fit(train_values, training_labels)
            scores = anomaly_scores(model, validation_values)
            truth = binary(validation_labels)
            _, _, threshold = threshold_for_find(truth, scores, budget)
            validation_metrics = binary_report(truth, (scores >= threshold).astype(int), scores)
            ranked = tuple(validation_metrics[key] or 0 for key in ("recall", "pr_auc", "precision")) + (
                -(validation_metrics["fpr"] or 0), *(validation_metrics[key] or 0 for key in ("f1", "roc_auc", "accuracy")))
        else:
            estimator.fit(train_values, train_labels)
            labels, confidence = classification_choices(model, validation_values)
            correct_known, unknown_recall, threshold = threshold_for_classify(validation_labels, labels, confidence, budget)
            validation_metrics = type_report(validation_labels, np.where(confidence >= threshold, labels, "unknown"), (*TYPES, "unknown"))
            ranked = (correct_known, unknown_recall, validation_metrics["macro_f1"] or 0)
        model["threshold"] = threshold
        yield name, model, ranked, validation_metrics


def train_models(dataset, directory, seed, fpr, unknown_acceptance):
    require(0 <= fpr <= 1 and 0 <= unknown_acceptance <= 1, "validation budgets must lie in [0, 1]")
    header, rows = load_dataset(dataset)
    train, validation = residual(rows, "train"), residual(rows, "validation")
    train = [row for row in train if row["label"] != "unknown"]
    require(bool(train) and bool(validation), "no eligible rules-unmatched training or validation data; check annotation and capture quality")
    directory = Path(directory).resolve()
    require(not directory.exists(), "model destination already exists; use a fresh directory")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".models-", dir=directory.parent) as temporary:
        staging = Path(temporary) / "models"
        staging.mkdir()
        common = {"schema_version": 1, "feature_set": FEATURE_SET, "columns": COLUMNS, "dependencies": VERSIONS}
        selection, candidates = {}, {}
        for stage, budget in (("find", fpr), ("classify", unknown_acceptance)):
            scores, candidates[stage] = {}, {}
            for name, model, rank, validation_metrics in stage_training(stage, train, validation, seed, budget):
                raw = pickle.dumps(model, protocol=5)
                file = f"{stage}_{name}.pkl"
                (staging / file).write_bytes(raw)
                candidates[stage][name] = {"file": file, "sha256": version(raw), "threshold": model["threshold"],
                                           "validation": validation_metrics,
                                           "hyperparameters": model["estimator"][-1].get_params()}
                scores[name] = rank
            selection[stage] = max(CANDIDATES[stage], key=scores.__getitem__)
        bundle = dict(common)
        for stage, name in selection.items():
            ref = candidates[stage][name]
            bundle[stage] = {"file": ref["file"], "sha256": ref["sha256"]}
        bundle["model_id"] = "v1-" + version(encoded(bundle))[:24]
        bundle_path = staging / "bundle.json"
        bundle_path.write_bytes(encoded(bundle))
        index = dict(common, model_id=bundle["model_id"], bundle_sha256=sha256(bundle_path),
                     dataset_sha256=sha256(dataset), manifest_sha256=header["manifest_sha256"],
                     dataset_id=header["manifest"]["dataset_id"], dataset_version=header["manifest"]["version"],
                     capture_groups={split: sorted({row["group"] for row in rows if row["split"] == split})
                                     for split in ("train", "validation", "test", "pipeline")},
                     development_groups=sorted({entry["group"] for entry in header["manifest"]["captures"]
                                                if entry["split"] in ("train", "validation")}),
                     development_captures=sorted({entry["capture"]["sha256"] for entry in header["manifest"]["captures"]
                                                  if entry["split"] in ("train", "validation")}),
                     validation_unknown_families=sorted({row["family"] for row in validation if row["label"] == "unknown"}),
                     catalogue_sha256=header.get("catalogue_sha256"), sensor_sha256=header.get("sensor_sha256"),
                     disabled_rules=header.get("disabled_rules", []),
                     seed=seed, max_fpr=fpr, max_unknown_acceptance=unknown_acceptance,
                     trained_at=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                     selected=selection, candidates=candidates,
                     not_applicable={"classify": {"isolation_forest": "single-class anomaly scores provide no multiclass posterior"}})
        (staging / "index.json").write_bytes(encoded(index))
        # Publishing a whole directory prevents a partially trained model set being used.
        staging.rename(directory)
    return {"model_id": bundle["model_id"], "bundle_sha256": index["bundle_sha256"], "selected": selection}


def binary_report(truth, prediction, scores=None):
    tp = int(np.sum((truth == 1) & (prediction == 1)))
    tn = int(np.sum((truth == 0) & (prediction == 0)))
    fp = int(np.sum((truth == 0) & (prediction == 1)))
    fn = int(np.sum((truth == 1) & (prediction == 0)))
    has_both = set(truth) == {0, 1}
    pr_auc = roc_auc = None
    if scores is not None and has_both:
        precision, recall, _ = metrics.precision_recall_curve(truth, scores)
        pr_auc, roc_auc = float(metrics.auc(recall, precision)), float(metrics.roc_auc_score(truth, scores))
    return {"samples": len(truth), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "correct": tp + tn, "incorrect": fp + fn, "labels": ["normal", "anomaly"],
            "confusion_matrix": [[tn, fp], [fn, tp]], "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "pr_auc": pr_auc, "roc_auc": roc_auc, "accuracy": ratio(tp + tn, len(truth)),
            "fpr": ratio(fp, tn + fp), "fnr": ratio(fn, tp + fn)}


def type_report(truth, prediction, labels):
    table = (metrics.confusion_matrix(truth, prediction, labels=labels).tolist() if len(truth)
             else [[0 for _ in labels] for _ in labels])
    known = np.isin(truth, TYPES)
    unknown = truth == "unknown"
    per_class = {}
    for i, label in enumerate(labels):
        actual = int(np.sum(truth == label))
        correct = table[i][i]
        predicted = int(np.sum(prediction == label))
        class_truth = truth == label
        per_class[label] = {"actual": actual, "correct": correct,
                            "missed": int(np.sum(class_truth & np.isin(prediction, ("normal", "insufficient_data")))) if label != "normal" else 0,
                            "wrong_type": int(np.sum(class_truth & ~np.isin(prediction, (label, "normal", "unknown", "insufficient_data")))),
                            "unknown": int(np.sum(class_truth & (prediction == "unknown"))),
                            "precision": ratio(correct, predicted), "recall": ratio(correct, actual),
                            "f1": ratio(2 * correct, actual + predicted)}
    active = [label for label in labels if per_class[label]["actual"]]
    correct = int(np.sum(truth == prediction))
    return {"samples": len(truth), "correct": correct, "incorrect": len(truth) - correct, "labels": labels,
            "confusion_matrix": table, "per_class": per_class,
            "accuracy": ratio(correct, len(truth)),
            "macro_f1": ratio(sum(per_class[label]["f1"] or 0 for label in active), len(active)),
            "weighted_f1": ratio(sum((per_class[label]["f1"] or 0) * per_class[label]["actual"] for label in labels), len(truth)),
            "unknown_recall": ratio(int(np.sum(unknown & (prediction == "unknown"))), int(unknown.sum())),
            "known_to_unknown": ratio(int(np.sum(known & (prediction == "unknown"))), int(known.sum()))}


def episode_report(rows, predictions):
    incidents = []
    positives = {}
    normal_ns = 0
    for row, output in zip(rows, predictions, strict=True):
        label, window = row["label"], row["window"]
        start, end = map(int, (window["window_start_ns"], window["window_end_ns"]))
        if label == "normal" and row["route"]["status"] != "insufficient_data":
            normal_ns += end - start
        if label not in ("normal", None):
            key = (row["group"], window["entity_id"], label, row["episode"])
            event = positives.setdefault(key, [int(row["onset_ns"]), None, None])
            if output in (*TYPES, "unknown"):
                event[1] = end if event[1] is None else min(event[1], end)
                if output == label:
                    event[2] = end if event[2] is None else min(event[2], end)
        if output in (*TYPES, "unknown"):
            incidents.append((row["capture"], output, start, end, label))
    merged = []
    for capture, output, start, end, label in sorted(incidents, key=lambda observation: observation[:4]):
        if merged and merged[-1][:3] == [capture, output, start]:
            merged[-1][2] = end
            merged[-1][3].add(label)
        else:
            merged.append([capture, output, end, {label}])
    false_incidents = sum(labels == {"normal"} for _, _, _, labels in merged)
    matched_incidents = sum(bool(labels & set((*TYPES, "unknown"))) for _, _, _, labels in merged)
    by_type = {}
    for label in (*TYPES, "unknown"):
        events = [event for (_, _, kind, _), event in positives.items() if kind == label]
        delays = sorted((event[2] - event[0]) / 1e9 for event in events if event[2] is not None)
        by_type[label] = {"total": len(events), "detected": sum(event[1] is not None for event in events),
                          "correct_type": sum(event[2] is not None for event in events),
                          "missed": sum(event[1] is None for event in events),
                          "recall": ratio(sum(event[1] is not None for event in events), len(events)),
                          "delay_seconds": delays}
    events_detected = sum(event[1] is not None for event in positives.values())
    precision = ratio(matched_incidents, matched_incidents + false_incidents)
    recall = ratio(events_detected, len(positives))
    hours = normal_ns / 3.6e12
    assessed = sum(row["route"]["status"] != "insufficient_data" for row in rows)
    return {"positive_episodes": len(positives), "detected_episodes": events_detected,
            "missed_episodes": len(positives) - events_detected,
            "miss_rate": ratio(len(positives) - events_detected, len(positives)),
            "episode_recall": recall, "normal_hours": hours,
            "false_incidents": false_incidents, "false_incidents_per_hour": ratio(false_incidents, hours),
            "incident_precision": precision,
            "incident_f1": ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None,
            "measurement_coverage": ratio(assessed, len(rows)), "by_type": by_type}


def run_pipeline(rows, detector, classifier, rules_only=False):
    prediction = np.asarray([row["route"].get("attack_type") or ("insufficient_data" if row["route"]["status"] == "insufficient_data"
                                                               else "normal") for row in rows], dtype="U32")
    compute_start = time.perf_counter()
    cpu_start = time.process_time()
    ml_rows = 0
    if not rules_only:
        unmatched = [i for i, row in enumerate(rows) if row["route"]["status"] == "no_match"]
        ml_rows = len(unmatched)
        if unmatched:
            values = matrix(rows[i]["window"] for i in unmatched)
            anomalies = anomaly_scores(detector, values) >= detector["threshold"]
            if anomalies.any():
                prediction[np.asarray(unmatched)[anomalies]] = classify(classifier, values[anomalies])
    elapsed = time.perf_counter() - compute_start
    cpu_seconds = time.process_time() - cpu_start
    scored = [i for i, row in enumerate(rows) if row["label"] is not None]
    require(bool(scored), "no labelled windows in the pipeline holdout")
    truth = np.asarray([rows[i]["label"] for i in scored])
    observed = prediction[scored]
    types = (*LABELS, "insufficient_data")
    # Insufficient positive windows remain in denominators of end-to-end metrics.
    emitted = np.isin(observed, (*TYPES, "unknown")).astype(int)
    return {"binary": binary_report(binary(truth), emitted),
            "types": type_report(truth, observed, types), "episodes": episode_report(rows, prediction),
            "by_route": dict(Counter(row["route"]["status"] for row in rows)),
            "unlabelled_windows": sum(row["label"] is None for row in rows),
            "offline_ml_compute": {"wall_seconds": elapsed, "cpu_seconds": cpu_seconds,
                                   "windows": ml_rows, "windows_per_second": ml_rows / elapsed,
                                   "peak_process_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                                                             * (1 if sys.platform == "darwin" else 1024)}}


def evaluate(dataset, directory, mode, candidate=None):
    header, rows = load_dataset(dataset)
    path = Path(directory)
    index = json.loads((path / "index.json").read_text())
    require(index["schema_version"] == 1 and index["dependencies"] == VERSIONS
            and index["feature_set"] == FEATURE_SET and tuple(index["columns"]) == COLUMNS,
            "incompatible candidate artifacts")
    require(index["bundle_sha256"] == sha256(path / "bundle.json"), "selected model manifest changed")
    split = "pipeline" if mode == "pipeline" else "test"
    tested = [row for row in rows if row["split"] == split]
    require(bool(tested), f"dataset has no {split} capture group")
    entries = [entry for entry in header["manifest"]["captures"] if entry["split"] == split]
    require(not set(index["development_groups"]) & {entry["group"] for entry in entries},
            "holdout overlaps a development run")
    require(not set(index["development_captures"]) & {entry["capture"]["sha256"] for entry in entries},
            "holdout overlaps a development capture")
    require(not set(index["validation_unknown_families"]) & {row["family"] for row in tested if row["label"] == "unknown"},
            "holdout Unknown families were used for validation")
    require((header.get("catalogue_sha256"), header.get("sensor_sha256"))
            == (index["catalogue_sha256"], index["sensor_sha256"]),
            "holdout sensor or rules differ from the training dataset")
    require(header.get("disabled_rules", []) == index["disabled_rules"],
            "holdout and development must use the same rule enablement")
    report = {"schema_version": 1, "mode": mode, "split": split, "model_id": index["model_id"],
              "dataset": header["manifest"]["dataset_id"], "dataset_version": header["manifest"]["version"],
              "dataset_sha256": sha256(dataset), "development_dataset_sha256": index["dataset_sha256"],
              "manifest_sha256": header["manifest_sha256"],
              "sources": sorted({row["source"] for row in tested}), "capture_groups": sorted({row["group"] for row in tested}),
              "not_applicable": index["not_applicable"].get(mode, {}),
              "disabled_rules": index["disabled_rules"], "results": {}}
    if mode == "pipeline":
        require(candidate is None or candidate in CANDIDATES["find"], "unsupported pipeline detector")
        selected = dict(index["selected"])
        if candidate is not None:
            selected["find"] = candidate
        detector, classifier = (load_stage(path, index["candidates"][stage][selected[stage]], stage) for stage in CANDIDATES)
        report.update(selected=selected, selected_versions={stage: index["candidates"][stage][name]["sha256"]
                                                          for stage, name in selected.items()},
                      rules=run_pipeline(tested, detector, classifier, rules_only=True))
        report["results"]["rules_ml"] = run_pipeline(tested, detector, classifier)
        report["by_source"] = {}
        for source in report["sources"]:
            subset = [row for row in tested if row["source"] == source]
            if any(row["label"] is not None for row in subset):
                report["by_source"][source] = run_pipeline(subset, detector, classifier)
        return report
    eligible = residual(rows, split)
    if mode == "classify":
        eligible = [row for row in eligible if row["label"] != "normal"]
    require(bool(eligible), f"no labelled rules-unmatched examples in {split}; check signal coverage and labels")
    values, truth = inputs(eligible)
    if mode == "find":
        truth = binary(truth)
        require(set(truth) == {0, 1}, "binary holdout must cover both normal and anomaly")
    else:
        require("unknown" in truth and set(TYPES) <= set(truth), "type holdout must cover each known class and unknown families")
    names = (candidate,) if candidate else CANDIDATES[mode]
    source_indexes = {source: np.asarray([row["source"] == source for row in eligible]) for source in report["sources"]}
    if mode == "classify":
        selected = index["selected"]["find"]
        detector = load_stage(path, index["candidates"]["find"][selected], "find")
        reached = anomaly_scores(detector, values) >= detector["threshold"]
    for name in names:
        require(name in CANDIDATES[mode], f"unsupported {mode} model: {name}")
        reference = index["candidates"][mode][name]
        model = load_stage(path, reference, mode)
        if mode == "find":
            scores = anomaly_scores(model, values)
            predicted = (scores >= model["threshold"]).astype(int)
            result = binary_report(truth, predicted, scores)
            result["by_source"] = {source: binary_report(truth[mask], predicted[mask], scores[mask])
                                   for source, mask in source_indexes.items() if mask.any()}
        else:
            labels = (*TYPES, "unknown")
            predicted = classify(model, values)
            result = type_report(truth, predicted, labels)
            result["by_source"] = {source: type_report(truth[mask], predicted[mask], labels)
                                   for source, mask in source_indexes.items() if mask.any()}
            result["after_stage_1"] = type_report(truth[reached], predicted[reached], labels)
        result.update(threshold=model["threshold"], model_version=reference["sha256"])
        report["results"][name] = result
    return report
