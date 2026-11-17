"""Replay independent labeled PCAP runs through the serving predictor."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from netwatch_ml.models.detector import load_bundle, predict_window


def audit(artifact, captures, sensor):
    meta = json.loads((artifact / "report.json").read_text())
    bundle = load_bundle(artifact / "bundle.json", meta["bundle_sha256"])
    confusion = defaultdict(Counter)
    episodes = defaultdict(Counter)
    runs = []
    seen = set()
    for manifest in sorted(captures.glob("*/manifest.json")):
        m = json.loads(manifest.read_text())
        source = manifest.parent / "traffic.pcap"
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if (digest != m["sha256"] or digest in seen or m["seed"] in seen or
                "0 packets dropped by kernel" not in m["capture_log"].splitlines()):
            raise ValueError("capture integrity, independence or capture loss")
        seen.update((digest, m["seed"]))
        intervals = m["intervals"]
        expected = Counter(benign=6, large_upload=1, large_response=1, connection_surge=1,
                           persistent_exchange=1, foreground_pause=1)
        if (Counter(i["label"] for i in intervals) != expected
                or any(i["start"] >= i["end"] or i["requests"] <= 0 for i in intervals)
                or any(a["end"] > b["start"] for a, b in zip(intervals, intervals[1:]))):
            raise ValueError("incomplete or overlapping workload intervals")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "windows.jsonl"
            replay = subprocess.run([str(sensor.resolve()), "replay", "--input", str(source), "--output", str(out),
                                     "--service", "127.0.0.1:8080", "--epoch", str(m["seed"]),
                                     "--coverage-start", str(intervals[0]["start"]),
                                     "--coverage-end", str(intervals[-1]["end"] + 900_000_000)], capture_output=True, check=True)
            stats = json.loads(replay.stderr)
            if stats["late_packets"] or stats["status_counts"] != {"decoded": stats["records"]}:
                raise ValueError(f"incomplete replay: {stats}")
            windows = [json.loads(line) for line in out.read_text().splitlines()]
        results = []
        for interval in intervals:
            truth = interval["label"]
            observations = []
            for w in windows:
                start, end = int(w["window_start_ns"]), int(w["window_end_ns"])
                if interval["start"] <= start and end <= interval["end"]:
                    # Offline PCAP lacks drop metadata; the recorder independently measured zero.
                    w["quality"]["capture_dropped"] = 0
                    prediction = predict_window(w, bundle)
                    label = prediction.get("classification", {}).get("label", prediction["status"])
                    confusion[truth][label] += 1
                    observations.append((start, end, label, prediction["status"]))
            width = 5_000_000_000
            expected_windows = interval["end"] // width - (interval["start"] + width - 1) // width
            missing = expected_windows - len(observations)
            if missing < 0 or len({item[0] for item in observations}) != len(observations):
                raise ValueError("duplicate windows")
            if missing:
                confusion[truth]["missing_window"] += missing
            # Two matching labels in three consecutive complete windows, computed within each interval.
            # This tests repeated recognition, independently of whether a previous journal incident is still open.
            confirmed = False
            delay = None
            for a, b, c in zip(observations, observations[1:], observations[2:]):
                triple = (a, b, c)
                if (a[1] == b[0] and b[1] == c[0]
                        and all(x[3] in ("normal", "anomalous") for x in triple)
                        and sum(x[2] == truth for x in triple) >= 2):
                    confirmed = True
                    delay = (c[1] - interval["start"]) / 1e9
                    break
            if truth != "benign":
                episodes[truth]["total"] += 1
                episodes[truth]["confirmed"] += confirmed
            results.append(dict(label=truth, windows=expected_windows, missing=missing, confirmed=confirmed,
                                confirmation_delay_s=delay,
                                anomalous=sum(x[3]=="anomalous" for x in observations)))
        runs.append(dict(seed=m["seed"], sha256=digest, packets=stats["records"], intervals=results))
    attempted = {p.name for p in captures.glob("run-*") if p.is_dir()}
    if attempted != {f"run-{r['seed']}" for r in runs}:
        raise ValueError("unfinished or mismatched capture directories")
    if not runs:
        raise ValueError("no completed runs")
    return dict(model_id=bundle["model_id"], runs=runs, windows=confusion, episodes=episodes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact", "captures", "sensor"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.artifact, args.captures, args.sensor), indent=2))
