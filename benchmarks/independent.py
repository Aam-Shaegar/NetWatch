"""Evaluate frozen NetWatch predictors against independently labeled observations."""

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import ValidationError
from netwatch_ml.contracts import validate
from netwatch_ml.models.detector import load_bundle, predict_window
from netwatch_ml.models.patterns import LABELS
from netwatch_ml.security import RULES, WAF, assess

HERE = Path(__file__).resolve().parent
PASSIVE_FILES = (
    "ml/netwatch_ml/security.py",
    "contracts/security-observation.schema.json",
)
SERVICE = ("foreground_pause", *LABELS, "persistent_exchange")
# HTTP load is operational context. The anomaly inventory remains fixed.
PASSIVE = (set(RULES) - {"http_load"}) | set(WAF)
KINDS = {
    "passive": PASSIVE,
    "service": {"generic_anomaly", *SERVICE},
    "forecast": {"forecast"},
}


def read(path):
    return json.loads(path.read_text())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verified(root, reference):
    path = (root / reference["path"]).resolve()
    if not path.is_relative_to(root):
        raise ValueError("input path must stay inside its declared directory")
    if digest(path) != reference["sha256"]:
        raise ValueError(f"checksum mismatch: {path.name}")
    return path


def load_models(artifact, forecast, training, pins):
    bundles = {}
    for kind, folder in (("service", artifact), ("forecast", forecast)):
        bundle = load_bundle(folder / "bundle.json", pins[kind])
        if bundle["detector"]["dataset_manifest_sha256"] != digest(training):
            raise ValueError(f"{kind} training manifest does not match model")
        bundles[kind] = bundle
    if (
        "pattern_limits" not in bundles["service"]["detector"]
        or "runtime" not in bundles["forecast"]
    ):
        raise ValueError("expected the extended service classifier and a GRU bundle")
    return bundles


def excluded_sources(training, development):
    groups = read(training)["groups"]
    if not groups:
        raise ValueError("empty training provenance")
    ids = set(groups)
    hashes = set(read(HERE / "external-inputs.json").values())
    hashes.update(read(HERE / "used-capture-sha256.json"))
    for group in groups.values():
        hashes.add(group["sha256"])
        hashes.update(group["source_hashes"].values())
    for group in development:
        ids.add(group["id"])
        hashes.update(group["sha256"])
    return ids, hashes


def outcomes(kind, payload, bundles, details=None):
    if kind == "passive":
        result = assess(payload)
        found = {item["label"] for item in result["findings"]}
        return {
            label: None if label in result["unassessed"] else label in found
            for label in PASSIVE
        }

    window = validate("window", payload["window"])
    history = [validate("window", previous) for previous in payload.get("history", [])]
    prediction = predict_window(window, bundles[kind], history)
    if details is not None:
        details.update(prediction.get("diagnostics", {}))
    status = prediction["status"]
    if kind == "forecast":
        return {
            "forecast": status == "anomalous"
            if status in ("normal", "anomalous")
            else None
        }
    label = prediction.get("classification", {}).get("label")
    named = label in (*SERVICE, "benign")
    return {
        "generic_anomaly": status == "anomalous"
        if status in ("normal", "anomalous")
        else None,
        **{
            name: False if status == "normal" else label == name if named else None
            for name in SERVICE
        },
    }


def empty_report():
    return {
        "types": {
            label: dict(
                positive=0,
                negative=0,
                hits=0,
                misses=0,
                false_alarms=0,
                correct_negatives=0,
                unavailable=0,
            )
            for labels in KINDS.values()
            for label in sorted(labels)
        },
        "cases": [],
    }


def evaluate(manifest_path, artifact, forecast, training, report, *, regression=False):
    manifest = read(manifest_path)
    report["manifest_sha256"] = digest(manifest_path)
    expected_unseen = not regression
    if (
        manifest["version"] != 1
        or manifest["unseen_by_developers"] is not expected_unseen
    ):
        raise ValueError(
            "expected a v1 manifest with a provenance attestation matching the evaluation mode"
        )
    rules = {name: digest(HERE.parent / name) for name in PASSIVE_FILES}
    if manifest["passive_sha256"] != rules:
        raise ValueError(
            "passive rules or observation contract differs from the frozen evaluation version"
        )
    report["passive_sha256"] = rules
    excluded_ids, excluded_hashes = excluded_sources(
        training, manifest["development_groups"]
    )
    root = manifest_path.resolve().parent
    groups, input_hashes, case_ids, checked_cases = {}, set(), set(), []
    for group in manifest["holdout_groups"]:
        group_id = group["id"]
        references = group["sources"]
        if (
            not group_id
            or group_id in groups
            or group_id in excluded_ids
            or not references
        ):
            raise ValueError(f"invalid or previously used capture group: {group_id}")
        hashes = {ref["sha256"] for ref in references}
        if hashes & excluded_hashes or any(
            hashes & previous for previous in groups.values()
        ):
            raise ValueError(f"source overlap in capture group: {group_id}")
        for reference in references:
            verified(root, reference)
        groups[group_id] = hashes

    for case in manifest["cases"]:
        case_id, kind = case["id"], case["kind"]
        if (
            not case_id
            or case_id in case_ids
            or case["group"] not in groups
            or kind not in KINDS
        ):
            raise ValueError(f"invalid or duplicate case: {case_id}")
        case_ids.add(case_id)
        expected = case["expect"]
        if (
            not expected
            or set(expected) - KINDS[kind]
            or any(type(value) is not bool for value in expected.values())
        ):
            raise ValueError(f"invalid ground truth: {case_id}")
        ref = case["input"]
        identity = (kind, ref["sha256"])
        if ref["sha256"] in excluded_hashes or identity in input_hashes:
            raise ValueError(f"reused evaluation input: {case_id}")
        input_hashes.add(identity)
        checked_cases.append((case, verified(root, ref)))

    bundles = load_models(artifact, forecast, training, manifest["models"])
    report["models"] = {
        kind: {"id": bundle["model_id"], "sha256": manifest["models"][kind]}
        for kind, bundle in bundles.items()
    }
    seen_observations = set()
    report["forest_only"] = dict(
        positive=0, negative=0, hits=0, false_alarms=0, unavailable=0
    )
    for case, path in checked_cases:
        payload = read(path)
        kind = case["kind"]
        if kind == "passive":
            coordinates = (payload["entity"], payload["start_s"])
        else:
            window = payload["window"]
            coordinates = (window["entity_id"], int(window["window_start_ns"]))
        identity = (case["group"], kind, *coordinates)
        if identity in seen_observations:
            raise ValueError(f"duplicate observation: {case['id']}")
        seen_observations.add(identity)
        details = {}
        actual = outcomes(kind, payload, bundles, details)
        if "generic_anomaly" in case["expect"]:
            expected = case["expect"]["generic_anomaly"]
            forest = report["forest_only"]
            forest["positive" if expected else "negative"] += 1
            score = details.get("forest_score")
            if score is None:
                forest["unavailable"] += 1
            elif score > details["forest_threshold"]:
                forest["hits" if expected else "false_alarms"] += 1
        results = {}
        for label, expected in case["expect"].items():
            row = report["types"][label]
            row["positive" if expected else "negative"] += 1
            observed = actual[label]
            if observed is None:
                status = "unavailable"
            elif expected:
                status = "hits" if observed else "misses"
            else:
                status = "false_alarms" if observed else "correct_negatives"
            row[status] += 1
            results[label] = status
        report["cases"].append(
            {"id": case["id"], "group": case["group"], "results": results}
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "service", "forecast", "training", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument(
        "--regression", action="store_true", help="use previously evaluated data"
    )
    args = parser.parse_args()
    report = empty_report()
    report["mode"] = "regression" if args.regression else "holdout"
    try:
        evaluate(
            args.manifest,
            args.service,
            args.forecast,
            args.training,
            report,
            regression=args.regression,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        ValidationError,
    ) as error:
        report["error"] = str(error)
        print(f"Input error: {error}")

    print("type | hits/positive | false alarms/negative | unavailable | status")
    for label, row in report["types"].items():
        if not row["positive"] or not row["negative"]:
            status = "missing coverage"
        elif row["unavailable"] or row["misses"] or row["false_alarms"]:
            status = "failed"
        else:
            status = "passed"
        row["status"] = status
        print(
            f"{label} | {row['hits']}/{row['positive']} | "
            f"{row['false_alarms']}/{row['negative']} | {row['unavailable']} | {status}"
        )
    report["passed"] = "error" not in report and all(
        row["status"] == "passed" for row in report["types"].values()
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"Report: {args.output}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
