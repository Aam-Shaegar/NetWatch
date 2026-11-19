"""Evaluate a frozen detector against a previously unseen interval manifest in Compose."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/e2e"))
from work_stack import run, wait_for  # noqa: E402

NS = 10**9
LIMITS = (
    "min_recall",
    "max_false_per_hour",
    "max_start_error_s",
    "max_end_error_s",
    "min_normal_hours",
    "min_evaluated_fraction",
)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def verified(folder, item):
    path = (folder / item["path"]).resolve(strict=True)
    if not path.is_relative_to(folder) or digest(path) != item["sha256"]:
        raise ValueError("Unverified holdout input")
    return path


def load_manifest(path, artifact):
    definition = read(path)
    if definition["version"] != 1 or definition["unseen_by_developers"] is not True:
        raise ValueError("Expected a fresh version 1 holdout manifest")
    policy = definition.get("policy_version", "v1")
    if policy not in ("v1", "v2"):
        raise ValueError("Unsupported incident projection policy")
    folder = path.resolve().parent
    bundle = read(artifact / "bundle.json")
    if digest(artifact / "bundle.json") != definition["model_sha256"]:
        raise ValueError("Model differs from the locked version")
    training = verified(folder, definition["training_manifest"])
    detector = bundle["detector"]
    if digest(training) != detector["dataset_manifest_sha256"]:
        raise ValueError("Training provenance does not match the model")
    known = set(read(ROOT / "benchmarks/external-inputs.json").values())
    known.update(read(ROOT / "benchmarks/used-capture-sha256.json"))
    group_ids = set()
    manifest = read(training)
    binding = detector.get("binding")
    if binding:
        if manifest["binding"] != binding or manifest["feature_set_version"] != detector["feature_set_version"]:
            raise ValueError("Training manifest does not match the model scope or feature set")
        for captures in manifest["captures"].values():
            for capture in captures:
                known.update((capture["source_sha256"], capture["windows_sha256"]))
    else:
        for name, group in manifest["groups"].items():
            group_ids.add(name)
            known.add(group["sha256"])
            known.update(group["source_hashes"].values())
    for group in definition["development_groups"]:
        group_ids.add(group["id"])
        known.update(group["sha256"])
    for previous in (ROOT / "data/holdout/anomalies").glob("manifest*.json"):
        # Earlier classification experiments are already known to the developers.
        for group in read(previous)["holdout_groups"]:
            group_ids.add(group["id"])
            known.update(source["sha256"] for source in group["sources"])
    limits = definition["limits"]
    if (
        set(limits) != set(LIMITS)
        or any(
            type(value) not in (int, float) or not math.isfinite(value) or value < 0
            for value in limits.values()
        )
        or not 0 < limits["min_recall"] <= 1
        or limits["min_normal_hours"] <= 0
        or not 0 < limits["min_evaluated_fraction"] <= 1
    ):
        raise ValueError("Invalid or missing preregistered acceptance limits")

    episodes, profiles = [], set()
    seen_epochs, seen_events = set(), set()
    for case in definition["cases"]:
        if not case["id"] or case["id"] in group_ids or not case["sources"]:
            raise ValueError("Invalid or previously used capture group")
        hashes = {source["sha256"] for source in case["sources"]}
        if hashes & known or case["windows"]["sha256"] in known:
            raise ValueError("Previously used source or prepared test windows")
        for source in case["sources"]:
            verified(folder, source)
        window_path = verified(folder, case["windows"])
        group_ids.add(case["id"])
        known.update(hashes | {case["windows"]["sha256"]})
        windows = [json.loads(line) for line in window_path.read_text().splitlines()]
        if not windows:
            raise ValueError("Empty capture group")
        times = [(int(w["window_start_ns"]), int(w["window_end_ns"])) for w in windows]
        if any(b - a != 5 * NS for a, b in times) or any(
            times[i - 1][1] != times[i][0] for i in range(1, len(times))
        ):
            raise ValueError("Expected continuous ordered five-second windows")
        if (
            len(
                {
                    (w["sensor_id"], w["entity_id"], w["entity_type"], w["capture_epoch"])
                    for w in windows
                }
            )
            != 1
        ):
            raise ValueError("Expected one observation stream per case")
        annotations = sorted(
            (int(a), int(b), kind)
            for kind in ("normal", "anomalous")
            for a, b in case[kind]
        )
        if (
            not annotations
            or any(
                a < times[0][0] or b > times[-1][1] or a >= b for a, b, _ in annotations
            )
            or any(
                annotations[i - 1][1] > annotations[i][0]
                for i in range(1, len(annotations))
            )
        ):
            raise ValueError("Unaligned or overlapping ground truth")
        if binding:
            first = windows[0]
            ids = {w["event_id"] for w in windows}
            epoch = first["capture_epoch"]
            if (any(first[key] != value for key, value in binding.items())
                    or any(w["feature_set_version"] != detector["feature_set_version"] for w in windows)
                    or epoch in seen_epochs or ids & seen_events or len(ids) != len(windows)):
                raise ValueError("Holdout does not match the model scope or reuses an observation identity")
            seen_epochs.add(epoch)
            seen_events.update(ids)
        else:
            for index, window in enumerate(windows):
                window.update(event_id=f"evaluation-{len(episodes)}-{index}",
                              capture_epoch=f"evaluation-{len(episodes)}", sensor_id="smoke")
        profiles.add(windows[0]["entity_id"])
        episodes.append((case["id"], windows, annotations))
    if not any(
        kind == "anomalous" for _, _, labels in episodes for _, _, kind in labels
    ):
        raise ValueError("No independently labelled anomalous episodes")
    if not any(kind == "normal" for _, _, labels in episodes for _, _, kind in labels):
        raise ValueError("No independently labelled normal exposure")
    return limits, episodes, sorted(profiles), policy


def normal_overlap(start, end, intervals):
    return sum(max(0, min(end, b) - max(start, a)) for a, b in intervals)


def evaluate(call, sensor, operator, limits, episodes):
    rows = []
    total = dict(
        positive=0,
        found=0,
        false_alarms=0,
        normal_hours=0.0,
        max_start_error_s=0.0,
        max_end_error_s=0.0,
        unresolved_ends=0,
        windows=0,
        evaluated=0,
        split=0,
        merged=0,
    )
    for name, windows, annotations in episodes:
        for offset in range(0, len(windows), 100):
            batch_windows = windows[offset : offset + 100]
            batch_id = hashlib.sha256(
                json.dumps(batch_windows, sort_keys=True).encode()
            ).hexdigest()
            body = dict(
                schema_version=1,
                batch_id=batch_id,
                windows=batch_windows,
                queue_loss={"count": 0},
            )
            if (
                call("/v1/windows", sensor, body, {"Idempotency-Key": batch_id})[0]
                != 200
            ):
                raise RuntimeError("Feature window replay was rejected")
        wait_for(
            lambda: not read_page(call, operator)["pending"],
            "incident projection",
            timeout=120,
        )
        incident_rows = []
        cursor = ""
        while True:
            page = read_page(
                call, operator, before=cursor, entity=windows[0]["entity_id"]
            )
            incident_rows.extend(
                i
                for i in page["incidents"]
                if i["epoch"] == windows[0]["capture_epoch"]
            )
            cursor = page["next"]
            if not cursor:
                break
        anomalies = [(a, b) for a, b, kind in annotations if kind == "anomalous"]
        normals = [(a, b) for a, b, kind in annotations if kind == "normal"]
        row = dict(
            id=name,
            positive=len(anomalies),
            found=0,
            false_alarms=0,
            normal_hours=0.0,
            max_start_error_s=0.0,
            max_end_error_s=0.0,
            unresolved_ends=0,
            windows=0,
            evaluated=0,
            split=0,
            merged=0,
        )
        row["windows"] = len(windows)
        row["episodes"] = [{"start_ns": a, "end_ns": b, "detected": False} for a, b in anomalies]
        row["unavailable"] = {}
        normal_evaluated_ns = 0
        for window in windows:
            state, _, raw = call("/v1/predictions/" + window["event_id"], sensor)
            if state != 200:
                raise RuntimeError("Unable to read scored windows")
            results = json.loads(raw)["predictions"]
            if not results:
                raise RuntimeError("Prediction queue still has unprocessed windows")
            prediction = results[0]["prediction"]
            if prediction["status"] in ("normal", "anomalous"):
                row["evaluated"] += 1
                normal_evaluated_ns += normal_overlap(
                    int(window["window_start_ns"]), int(window["window_end_ns"]), normals
                )
            else:
                reason = prediction.get("unavailable_reason", prediction["status"])
                row["unavailable"][reason] = row["unavailable"].get(reason, 0) + 1
        row["normal_hours"] = normal_evaluated_ns / NS / 3600
        pairs = []
        overlaps = []
        for i, event in enumerate(incident_rows):
            status, _, body = call("/v1/incidents/" + event["id"], operator)
            if status != 200 or json.loads(body)["feature_set_version"] != windows[0]["feature_set_version"]:
                raise RuntimeError("Incident evidence has an inconsistent feature set")
            start = int(event["first_ns"])
            estimate = event.get("estimated_end_ns")
            end = int(estimate or event["last_ns"])
            for j, (a, b) in enumerate(anomalies):
                overlap = min(b, end) - max(a, start)
                if overlap <= 0:
                    continue
                overlaps.append((i, j))
                if a <= int(event["detected_ns"]) < b:
                    pairs.append((overlap, i, j, start, estimate))
        row["split"] = sum(
            sum(j == expected for _, j in overlaps) > 1
            for expected in range(len(anomalies))
        )
        row["merged"] = sum(
            sum(i == event for i, _ in overlaps) > 1
            for event in range(len(incident_rows))
        )
        matched_events, matched_truth = set(), set()
        for _, i, j, start, end in sorted(pairs, reverse=True):
            if i in matched_events or j in matched_truth:
                continue
            matched_events.add(i)
            matched_truth.add(j)
            a, b = anomalies[j]
            event = incident_rows[i]
            row["episodes"][j].update(
                detected=True,
                start_error_s=(start - a) / NS,
                end_error_s=(int(end) - b) / NS if end is not None else None,
                opening_delay_s=(int(event["detected_ns"]) - a) / NS,
                closing_delay_s=(int(event["closed_ns"]) - b) / NS if event["closed_ns"] else None,
            )
            row["max_start_error_s"] = max(
                row["max_start_error_s"], abs(start - a) / NS
            )
            if end is None:
                row["unresolved_ends"] += 1
            else:
                row["max_end_error_s"] = max(
                    row["max_end_error_s"], abs(int(end) - b) / NS
                )
        row["found"] = len(matched_truth)
        row["false_alarms"] = sum(
            i not in matched_events
            and any(a <= int(event["detected_ns"]) < b for a, b in normals)
            for i, event in enumerate(incident_rows)
        )
        for key in total:
            total[key] = (
                max(total[key], row[key])
                if key.startswith("max_")
                else total[key] + row[key]
            )
        rows.append(row)
    recall = total["found"] / total["positive"]
    false_per_hour = (
        total["false_alarms"] / total["normal_hours"] if total["normal_hours"] else None
    )
    evaluated_fraction = total["evaluated"] / total["windows"]
    checks = {
        "scoring_coverage": evaluated_fraction >= limits["min_evaluated_fraction"],
        "recall": recall >= limits["min_recall"],
        "episode_integrity": total["split"] == 0 and total["merged"] == 0,
        "false_rate": false_per_hour is not None and false_per_hour <= limits["max_false_per_hour"],
        "normal_exposure": total["normal_hours"] >= limits["min_normal_hours"],
        "start_error": total["max_start_error_s"] <= limits["max_start_error_s"],
        "end_error": total["unresolved_ends"] == 0
        and total["max_end_error_s"] <= limits["max_end_error_s"],
    }
    return dict(
        passed=all(checks.values()),
        checks=checks,
        limits=limits,
        totals=total,
        recall=recall,
        false_per_hour=false_per_hour,
        evaluated_fraction=evaluated_fraction,
        cases=rows,
    )


def read_page(call, token, **filters):
    status, _, body = call("/v1/incidents?" + urlencode(filters), token)
    if status != 200:
        raise RuntimeError("Unable to read operator journal")
    return json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "artifact", "report"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        limits, cases, profiles, policy = load_manifest(args.manifest, args.artifact)
        result = run(
            args.artifact.resolve(),
            args.report,
            entities=",".join(profiles),
            policy=policy,
            exercise=lambda call, sensor, operator: evaluate(
                call, sensor, operator, limits, cases
            ),
        )
        report = read(args.report)
        report["passed"] = result["passed"]
        report["manifest_sha256"] = digest(args.manifest)
        report["policy_version"] = policy
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        AssertionError,
        subprocess.SubprocessError,
    ) as err:
        report = dict(passed=False, error=str(err))
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Acceptance {'passed' if report['passed'] else 'did not pass'}: {args.report}"
    )
    if "error" in report:
        print(report["error"])
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
