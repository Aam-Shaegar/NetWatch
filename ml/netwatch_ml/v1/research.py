"""Train portable traffic-v3 candidates using five source-disjoint development folds."""

import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import pickle
import tempfile

import numpy as np
from jsonschema import ValidationError
from sklearn.model_selection import StratifiedGroupKFold

from ..contracts import validate
from .dataset import records, require, validate_route
from .model import COLUMNS, FEATURE_SET, LABELS, REQUIRED_SIGNALS, TYPES, VERSIONS, encoded, load_bundle, matrix, sha256, version
from .research_candidates import FAMILY, FIND_RECIPES, TYPE_RECIPES, balanced_sample, fit_candidate


def load_rows(path, allow_unknown_loss):
    """Accept a prepared v1 manifest or wrapped development observations with Go routes."""
    rows = []
    identities = set()
    group_sources = {}
    source_folds = {}
    captures = {}
    entries = None
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
                require(isinstance(row, dict), "expected a JSON object")
                if number == 1 and "manifest" in row:
                    require(row["schema_version"] == 1, "incompatible prepared dataset")
                    entries = {entry["id"]: entry for entry in records(row["manifest"])}
                    continue
                window = row["window"]
                require(isinstance(window, dict), "expected a window object")
                capture = row["capture"]
                if entries is not None:
                    entry = entries[capture]
                    row.update(source=entry["source"]["id"], group=entry["group"], split=entry["split"])
                    require(row["window"]["entity_id"] == entry["host"], "inconsistent capture host")
                require("split" in row, "wrapped input requires an explicit split")
                split = row["split"]
                require(split in ("development", "train", "validation", "test", "pipeline"), "invalid split")
                identity = window["event_id"]
                require(identity not in identities, "duplicate observation")
                identities.add(identity)
                group = row["group"]
                source = row["source"]
                fold = row.get("validation_source", source)
                require(all(isinstance(k, str) and k for k in (group, source, capture, fold)),
                        "group, source, capture and validation source must be nonempty strings")
                purpose = "evaluation" if split in ("test", "pipeline") else "development"
                require(group_sources.setdefault(group, (fold, purpose)) == (fold, purpose),
                        "capture group crosses folds or development and holdout")
                require(captures.setdefault(capture, group) == group, "capture crosses groups")
                require(source_folds.setdefault(source, fold) == fold, "publisher crosses validation groups")
                if purpose == "evaluation":
                    continue
                label = row["label"]
                require(label is None or label in LABELS, "unrecognized label")
                route = row["route"]
                require(route["event_id"] == identity, "rule result belongs to a different window")
                require(route["status"] in ("incident", "insufficient_data", "no_match"), "invalid rule status")
                if label is None or route["status"] != "no_match":
                    continue
                window = validate("window", window)
                require(window["feature_set_version"] == FEATURE_SET and window["entity_type"] == "host",
                        "incompatible feature set or entity")
                quality = window["quality"]
                if allow_unknown_loss and quality["capture_dropped"] is None:
                    require(quality["coverage"] == "complete" and quality["late_packets"] == 0
                            and quality["state_evictions"] == 0 and not route.get("attack_type")
                            and all(window["features"][key] is not None for key in REQUIRED_SIGNALS),
                            "ineligible archival window received an ML route")
                else:
                    validate_route(window, route)
                if label != "normal":
                    require(isinstance(row.get("episode"), str) and row["episode"], "missing episode identifier")
                if label == "unknown":
                    require(isinstance(row.get("family"), str) and row["family"], "missing Unknown family")
                rows.append(row)
            except ValidationError as error:
                raise ValueError(f"invalid window at line {number}: {error.message}") from error
            except (TypeError, KeyError, ValueError) as error:
                raise ValueError(f"invalid development input at line {number}: {error}") from error
    require({row["label"] for row in rows} == set(LABELS),
            "eligible rule misses must cover normal, all three attack types and named Unknown families")
    return rows


def group_folds(labels, groups, seed):
    require(len(set(groups)) >= 5, "five-fold validation requires at least five independent source groups")
    for offset in range(100):
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=(seed + offset) % (2**32))
        folds = list(splitter.split(labels, labels, groups))
        if all(set(labels[train]) >= {"normal", *TYPES} for train, _ in folds):
            return folds
    raise ValueError("each training fold must retain normal and every known type while holding sources out")


def select_threshold(stage, rows, labels, scores, choices):
    normal = labels == "normal"
    unknown = labels == "unknown"
    weights = np.zeros(len(rows))
    for label in TYPES:
        indices, mass = balanced_sample(rows, labels, np.flatnonzero(labels == label), len(rows), 0)
        weights[indices] = mass / len(TYPES)
    negative_sources = defaultdict(list)
    episodes = defaultdict(list)
    families = Counter(row["family"] for row in rows if row["label"] == "unknown")
    for index, row in enumerate(rows):
        if normal[index]:
            negative_sources[row.get("validation_source", row["source"])].append(index)
        elif not unknown[index]:
            episodes[row["label"], row["source"], row["group"], row["episode"]].append(index)
    unknown_weights = np.asarray([
        1 / (len(families) * families[row["family"]]) if row["label"] == "unknown" else 0.
        for row in rows
    ])
    thresholds = np.unique(np.r_[
        np.linspace(0.01, 1, 100), np.quantile(scores, np.linspace(0., 1, 101)), math.nextafter(1., 2.),
    ])
    best = None
    for threshold in thresholds:
        accepted = scores >= threshold
        if stage == "find":
            error = float(accepted[normal].mean())
            source_fpr = [accepted[indices].mean() for indices in negative_sources.values()]
            if error > 0.01 or np.mean(source_fpr) > 0.03 or max(source_fpr) > 0.15:
                continue
            correct = accepted
            details = {"negative_window_fpr": error, "negative_mean_source_fpr": float(np.mean(source_fpr)),
                       "negative_worst_source_fpr": float(max(source_fpr))}
        else:
            error = float(unknown_weights @ accepted)
            pooled = float(accepted[unknown].mean())
            if error > 0.10 or pooled > 0.20:
                continue
            correct = accepted & (choices == labels)
            details = {"unknown_acceptance_macro_family": error, "unknown_acceptance_pooled": pooled}
        # Balance window recall by type, source and episode; episode recall gives
        # each type equal mass and counts an episode once when any window matches.
        window_recall = float(weights @ correct)
        hits = defaultdict(list)
        for (label, _, _, _), indices in episodes.items():
            hits[label].append(bool(correct[indices].any()))
        episode_recall = float(np.mean([np.mean(v) for v in hits.values()]))
        rank = (0.7 * window_recall + 0.3 * episode_recall, window_recall, episode_recall, -error, float(threshold))
        if best is None or rank > best[0]:
            details.update(threshold=float(threshold), balanced_known_window_recall=window_recall,
                           macro_known_episode_recall=episode_recall)
            best = (rank, details)
    require(best is not None, "no feasible development threshold")
    return best


def compare_recipe(recipe, stage, rows, values, labels, folds, seed):
    scores = np.full(len(rows), np.nan)
    choices = np.full(len(rows), "", dtype="U20")
    for train, held_out in folds:
        training = np.zeros(len(rows), dtype=bool)
        training[train] = True
        model = fit_candidate(recipe, stage, rows, values, labels, training, seed)
        indices = held_out if stage == "find" else held_out[labels[held_out] != "normal"]
        if not len(indices):
            continue
        probabilities = model.predict_proba(values[indices])
        if stage == "find":
            scores[indices] = probabilities[:, list(model.classes_).index(1)]
        else:
            winner = probabilities.argmax(axis=1)
            scores[indices] = probabilities[np.arange(len(indices)), winner]
            choices[indices] = model.classes_[winner]
    evaluated = np.ones(len(rows), dtype=bool) if stage == "find" else labels != "normal"
    require(np.array_equal(evaluated, np.isfinite(scores)), "cross-validation returned incomplete scores")
    subset = [row for row, use in zip(rows, evaluated) if use]
    return select_threshold(stage, subset, labels[evaluated], scores[evaluated], choices[evaluated])


def train_research(dataset, directory, seed=42, *, allow_unknown_loss=False):
    """Select and refit both stages. Publish a standard bundle to a fresh directory."""
    dataset = Path(dataset)
    directory = Path(directory).resolve()
    require(not directory.exists(), "model destination already exists")
    require(type(seed) is int and 0 <= seed < 2**32, "seed must be a 32-bit unsigned integer")
    rows = load_rows(dataset, allow_unknown_loss)
    labels = np.asarray([row["label"] for row in rows])
    groups = np.asarray([row.get("validation_source", row["source"]) for row in rows])
    values = matrix(row["window"] for row in rows)
    folds = group_folds(labels, groups, seed)
    bundle = {"schema_version": 1, "feature_set": FEATURE_SET, "columns": COLUMNS, "dependencies": VERSIONS}
    selection = {}
    results = {}
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".research-") as temp:
        staging = Path(temp) / "models"
        staging.mkdir()
        for stage, recipes in (("find", FIND_RECIPES), ("classify", TYPE_RECIPES)):
            results[stage] = {}
            ranks = {}
            for recipe in recipes:
                ranks[recipe], results[stage][recipe] = compare_recipe(recipe, stage, rows, values, labels, folds, seed)
            recipe = max(recipes, key=ranks.__getitem__)
            selection[stage] = recipe
            algorithm = FAMILY[recipe.rsplit("_", 1)[1]]
            estimator = fit_candidate(recipe, stage, rows, values, labels, np.ones(len(rows), dtype=bool), seed)
            model = {"candidate": algorithm, "threshold": results[stage][recipe]["threshold"], "estimator": estimator}
            raw = pickle.dumps(model, protocol=5)
            filename = f"{stage}_{algorithm}.pkl"
            (staging / filename).write_bytes(raw)
            bundle[stage] = {"file": filename, "sha256": version(raw)}
        bundle["model_id"] = "v1-" + version(encoded(bundle))[:24]
        bundle_path = staging / "bundle.json"
        bundle_path.write_bytes(encoded(bundle))
        checksum = sha256(bundle_path)
        load_bundle(bundle_path, checksum)
        report = {
            "seed": seed, "quality_policy": "archive-unknown-drops" if allow_unknown_loss else "strict",
            "input_sha256": sha256(dataset), "labels": dict(Counter(labels)),
            "development_folds": [sorted(set(groups[held_out].tolist())) for _, held_out in folds],
            "selection": selection, "development_results": results,
            "model_id": bundle["model_id"], "bundle_sha256": checksum,
        }
        (staging / "research-index.json").write_bytes(encoded(report))
        staging.rename(directory)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("models", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--allow-archive-unknown-loss", action="store_true",
                        help="admit otherwise complete archival windows explicitly routed with an unknown drop count")
    args = parser.parse_args()
    try:
        report = train_research(args.dataset, args.models, args.seed, allow_unknown_loss=args.allow_archive_unknown_loss)
    except (OSError, ValueError) as error:
        parser.exit(1, f"NetWatch research training: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
