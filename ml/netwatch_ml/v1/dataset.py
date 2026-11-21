"""Compile publisher annotations and sensor-replayed captures into a pinned JSONL dataset."""

import calendar
import csv
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from netwatch_ml.contracts import validate
from netwatch_ml.v1.model import FEATURE_SET, LABELS, TYPES, sha256, usable

ROOT = Path(__file__).resolve().parents[3]
SPLITS = frozenset(("train", "validation", "test", "pipeline"))
NS = 10**9
WINDOW_NS = 5 * NS
GENIS = {"dos-udp": "udp_flood", "dos-icmp": "icmp_flood", "benign": "normal",
         "benign-admin": "normal", "benign-background": "normal", "benign-user": "normal"}
GOTHAM = {"TCP Scan": "tcp_port_scan", "Merlin UDP Flooding": "udp_flood",
          "Mirai UDP Flooding": "udp_flood", "Merlin ICMP Flooding": "icmp_flood", "Benign": "normal"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    ns = int(value)
    require(0 <= ns <= 2**63 - 1, "timestamp outside int64")
    return ns


def second_ns(seconds):
    return timestamp(Decimal(seconds) * NS)


def gotham_time(value):
    day, hhmmss, zone = value.rsplit(" ", 2)
    require(zone == "GMT", "expected Gotham GMT timestamp")
    h, m, s = hhmmss.split(":")
    midnight = calendar.timegm(datetime.strptime(day, "%b %d, %Y").timetuple())
    return second_ns(midnight + int(h) * 3600 + int(m) * 60 + Decimal(s))


def label_parts(label):
    if label in LABELS and label != "unknown":
        return label, None
    require(label.startswith("unknown:") and bool(re.fullmatch(r"[a-z0-9_]{1,60}", label[8:]))
            and label[8:] not in TYPES, "unknown annotation must name an out-of-catalog family")
    return "unknown", label[8:]


def verified_path(base, spec):
    path = (base / spec["path"]).resolve(strict=True)
    require(path.is_file() and re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]) is not None,
            "expected artifact file and SHA-256")
    require(sha256(path) == spec["sha256"], "capture or annotations checksum mismatch")
    return path


def annotations(path, entry):
    spec = entry["annotations"]
    kind = spec["format"]
    lower, upper = map(timestamp, (entry["coverage_start_ns"], entry["coverage_end_ns"]))
    mapping = {**(GENIS if kind == "genis" else GOTHAM if kind == "gotham" else {}), **spec.get("label_map", {})}
    intervals = set()
    with path.open(newline="", encoding="utf-8-sig") as file:
        for row in csv.DictReader(file):
            if kind == "genis":
                if row["DstAddr"] not in (entry["host"], "", "*"):
                    continue
                raw = row["Label"]
                start, end = second_ns(row["StartTime"]), second_ns(row["LastTime"]) + 1
                episode = f"{raw}:{start}:{end}"
            elif kind == "gotham":
                if row["ip.dst"] != entry["host"] and (row["label"] != "Benign" or row["ip.src"] != entry["host"]):
                    continue
                raw = row["label"]
                time = gotham_time(row["frame.time"])
                if not lower <= time < upper:
                    continue
                start, end = time // WINDOW_NS * WINDOW_NS, time // WINDOW_NS * WINDOW_NS + WINDOW_NS
                episode = None  # Consecutive marked packet buckets form one observed episode.
            elif kind == "interval_csv":
                if row["host"] != entry["host"]:
                    continue
                raw = row["label"]
                start, end = timestamp(row["start_ns"]), timestamp(row["end_ns"])
                episode = row["episode_id"]
                require(bool(episode), "interval CSV requires episode_id")
            else:
                raise ValueError("unsupported annotation format")
            require(end > start, "invalid annotation interval")
            if start >= upper or end <= lower:
                continue
            mapped = mapping.get(raw, raw if kind == "interval_csv" else None)
            # Keep unreviewed attack labels as ambiguity rather than quietly marking normal.
            label, family = label_parts(mapped) if mapped is not None else (None, None)
            intervals.add((start, end, label, family, episode))
    require(intervals, "no publisher annotations overlap the selected host and coverage")
    if kind == "gotham":
        joined = []
        for label, family in {(x[2], x[3]) for x in intervals}:
            bounds = sorted({(x[0], x[1]) for x in intervals if x[2:4] == (label, family)})
            for start, end in bounds:
                if joined and joined[-1][2:4] == (label, family) and joined[-1][1] == start:
                    previous = joined.pop()
                    start = previous[0]
                joined.append((start, end, label, family, f"{label}:{start}"))
        intervals = joined
    return sorted(set(intervals), key=lambda item: (item[:2], str(item[2:])))


def annotation_for(start, end, candidates):
    positive = [event for event in candidates if event[2] != "normal"]
    if positive:
        choices = {(label, family) for _, _, label, family, _ in positive}
        if len(choices) != 1 or positive[0][2] is None:
            return None, None, None, None
        lower, _, label, family, episode = min(positive, key=lambda item: item[:2])
        return label, family, episode, lower
    if any(a <= start and b >= end and label == "normal" for a, b, label, _, _ in candidates):
        return "normal", None, None, None
    return None, None, None, None


def records(manifest):
    require(manifest["schema_version"] == 1 and bool(manifest["dataset_id"]) and bool(manifest["version"]),
            "invalid dataset manifest metadata")
    result = manifest["captures"]
    require(isinstance(result, list) and bool(result), "dataset manifest must contain captures")
    groups, captures, identifiers = {}, {}, set()
    views = defaultdict(list)
    for entry in result:
        split, group = entry["split"], entry["group"]
        require(split in SPLITS and isinstance(group, str) and bool(group), "invalid split or capture group")
        require(groups.setdefault(group, split) == split, "a capture group appears in multiple splits")
        capture_hash = entry["capture"]["sha256"]
        require(captures.setdefault(capture_hash, group) == group, "capture bytes appear in multiple groups")
        require(entry["id"] not in identifiers and re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", entry["id"]),
                "duplicate or invalid capture ID")
        identifiers.add(entry["id"])
        source = entry["source"]
        require(all(isinstance(source[key], str) and source[key] for key in ("id", "version", "url", "terms"))
                and entry["annotations"]["reference"], "publisher provenance and terms are required")
        require(str(ipaddress.ip_address(entry["host"])) == entry["host"], "use a canonical destination address")
        start, end = map(timestamp, (entry["coverage_start_ns"], entry["coverage_end_ns"]))
        require(end - start >= WINDOW_NS, "capture needs a full window of declared coverage")
        previous_ranges = views[capture_hash, entry["host"]]
        require(all(end <= old_start or start >= old_end for old_start, old_end in previous_ranges),
                "the same capture and destination has overlapping coverage")
        previous_ranges.append((start, end))
        drops = entry.get("capture_dropped")
        require(drops is None or (type(drops) is int and drops >= 0 and entry.get("capture_loss_reference")),
                "a measured loss counter requires its provenance")
    return result


def compile_dataset(manifest_path, output, sensor, catalogue):
    manifest_path, output = Path(manifest_path).resolve(), Path(output).resolve()
    manifest = json.loads(manifest_path.read_text())
    entries = records(manifest)
    used = set(json.loads((ROOT / "benchmarks" / "used-capture-sha256.json").read_text()))
    disabled = sorted({rule.strip() for rule in os.getenv("NETWATCH_DISABLED_RULES", "").split(",") if rule.strip()})
    require(set(disabled) <= set(TYPES), "unrecognized disabled rule in dataset settings")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".compile-", dir=output.parent) as temporary:
        temp = Path(temporary)
        prepared, incoming, decisions, windows_path = (temp / name for name in ("prepared", "incoming", "decisions", "windows.jsonl"))
        with prepared.open("w") as output_stream, incoming.open("w") as rule_stream:
            output_stream.write(json.dumps({"schema_version": 1, "manifest": manifest,
                                           "manifest_sha256": sha256(manifest_path),
                                           "sensor_sha256": sha256(sensor), "catalogue_sha256": sha256(catalogue),
                                           "disabled_rules": disabled}) + "\n")
            for entry in entries:
                split = entry["split"]
                if split in ("test", "pipeline"):
                    require(entry["capture"]["sha256"] not in used, "archive already used by NetWatch; choose a fresh holdout capture")
                capture = verified_path(manifest_path.parent, entry["capture"])
                truth = annotations(verified_path(manifest_path.parent, entry["annotations"]), entry)
                command = [str(Path(sensor).resolve()), "replay", "--input", str(capture), "--output", str(windows_path),
                           "--host", entry["host"], "--sensor", "v1-offline", "--epoch", entry["id"],
                           "--feature-set", FEATURE_SET, "--coverage-start", str(entry["coverage_start_ns"]),
                           "--coverage-end", str(entry["coverage_end_ns"])]
                if entry.get("capture_dropped") is not None:
                    command.extend(("--capture-dropped", str(entry["capture_dropped"])))
                subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
                last_start, offset, active, observed = -1, 0, [], 0
                with windows_path.open() as stream:
                    for line in stream:
                        window = validate("window", json.loads(line))
                        start, end = int(window["window_start_ns"]), int(window["window_end_ns"])
                        require(start > last_start and window["entity_id"] == entry["host"]
                                and window["feature_set_version"] == FEATURE_SET, "sensor replay returned incompatible timeline")
                        last_start = start
                        active = [item for item in active if item[1] > start]
                        while offset < len(truth) and truth[offset][0] < end:
                            if truth[offset][1] > start:
                                active.append(truth[offset])
                            offset += 1
                        label, family, episode, onset = annotation_for(start, end, active)
                        rule_stream.write(json.dumps({"group": entry["group"], "window": window}) + "\n")
                        output_stream.write(json.dumps({"capture": entry["id"], "window": window, "label": label,
                                                        "family": family, "episode": episode, "onset_ns": onset}) + "\n")
                        observed += label is not None
                require(observed, "publisher annotations did not align to sensor windows")
                windows_path.unlink()
        with incoming.open() as source, decisions.open("w") as destination:
            subprocess.run([str(Path(catalogue).resolve())], stdin=source, stdout=destination, check=True)
        assembled = temp / "assembled"
        with prepared.open() as source, decisions.open() as destination, assembled.open("w") as file:
            file.write(next(source))
            for line, decision in zip(source, destination, strict=True):
                record, route = json.loads(line), json.loads(decision)
                validate_route(record["window"], route)
                record["route"] = route
                file.write(json.dumps(record, allow_nan=False) + "\n")
        # Linking a completed file into place is atomic and preserves an existing dataset.
        output.hardlink_to(assembled)


def validate_route(window, route):
    require(window["event_id"] == route["event_id"] and route["status"] in ("incident", "insufficient_data", "no_match"),
            "invalid rules result for window")
    require(route.get("attack_type") in TYPES if route["status"] == "incident" else not route.get("attack_type"),
            "invalid rule type")
    require((route["status"] != "insufficient_data") == usable(window), "rule and ML disagree on window eligibility")


def load_dataset(path):
    with Path(path).open() as file:
        header = json.loads(next(file))
        require(header["schema_version"] == 1, "invalid prepared dataset")
        entries = {entry["id"]: entry for entry in records(header["manifest"])}
        windows, identities, unknown = [], set(), {}
        for line in file:
            row = json.loads(line)
            entry = entries[row["capture"]]
            row.update(split=entry["split"], group=entry["group"], source=entry["source"]["id"])
            window = validate("window", row["window"])
            validate_route(window, row["route"])
            require(window["event_id"] not in identities and window["entity_id"] == entry["host"],
                    "duplicate event or mismatched destination in prepared dataset")
            identities.add(window["event_id"])
            require(row["label"] is None or row["label"] in LABELS, "unknown prepared dataset label")
            if row["label"] == "unknown":
                _, family = label_parts(f"unknown:{row['family']}")
                require(unknown.setdefault(family, row["split"]) == row["split"], "unknown family appears in multiple splits")
            if row["label"] in (*TYPES, "unknown"):
                require(bool(row["episode"]) and row["onset_ns"] is not None, "positive window lacks publisher event")
            windows.append(row)
    require(windows, "empty prepared dataset")
    return header, windows
