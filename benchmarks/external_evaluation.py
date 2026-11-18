"""Reproduce the external benchmark with frozen NetWatch rules and local input files."""

import argparse
import json
from pathlib import Path

from auth import examine, FILES
from benign_control import benign_control
from gotham import evaluate
from kitsune import benchmark, SCENARIOS, sha
from netwatch_ml.security import RULES, WAF

SERVICE = [
    "generic_anomaly",
    "foreground_pause",
    "large_upload",
    "large_response",
    "connection_surge",
    "persistent_exchange",
    "forecast",
]
DEVICES = [
    "iotsim-combined-cycle-1.csv",
    "iotsim-combined-cycle-10.csv",
    "iotsim-predictive-maintenance-1.csv",
]


def combine(captures, devices, auth):
    summary = {
        label: dict(
            hits=0,
            misses=0,
            unassessed=0,
            delays_s=[],
            false_incidents=0,
            normal_minutes=0,
        )
        for label in [*SERVICE, *RULES, *WAF]
    }

    def episode(label, detected, available, delay):
        row = summary[label]
        key = "hits" if detected else "misses" if available else "unassessed"
        row[key] += 1
        if delay is not None:
            row["delays_s"].append(delay)

    def control(label, false, minutes):
        summary[label]["false_incidents"] += false
        summary[label]["normal_minutes"] += minutes

    for capture in captures:
        for label, rule in capture["rules"].items():
            if rule["expected"]:
                episode(
                    label,
                    rule["detected"],
                    rule["assessed_attack_minutes"] > 0,
                    rule["delay_s"],
                )
            control(label, rule["false_incidents"], rule["assessed_benign_minutes"])
    # Primary attack vantage and independent benign trace. The second observer is diagnostic only.
    for ep in devices[0]["episodes"]:
        episode(ep["rule"], ep["matched"], ep["assessed"], ep["delay_s"])
    for label, normal in devices[2]["normal"].items():
        control(label, normal["false_incidents"], normal["minutes"])
    for case in auth:
        episode(
            "password_guessing",
            case["detected"],
            True,
            case["delay_from_first_logged_failure_s"],
        )
    for row in summary.values():
        row["reviewed"] = row["hits"] + row["misses"] + row["unassessed"]
        row["false_per_hour"] = (
            60 * row["false_incidents"] / row["normal_minutes"]
            if row["normal_minutes"]
            else None
        )
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--sensor", type=Path, help="use production Go replay for Kitsune inputs"
    )
    args = parser.parse_args()
    hashes = json.loads(Path(__file__).with_name("external-inputs.json").read_text())
    for name, expected in hashes.items():
        if sha(args.folder / name) != expected:
            parser.error(f"unexpected digest for {name}")
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        sensor = args.sensor
        if sensor is None:
            sensor = Path(tmp) / "netwatch-sensor"
            subprocess.run(
                ["go", "build", "-o", str(sensor), "./cmd/netwatch-sensor"],
                cwd=Path(__file__).resolve().parents[1],
                check=True,
            )
        captures = [benchmark(args.folder, n, sensor) for n in SCENARIOS]
    devices = [evaluate(args.folder / n) for n in DEVICES]
    auth = [examine(args.folder / n) for n in FILES]
    summary = combine(captures, devices, auth)
    print("class | detected/reviewed | missed | unavailable | false/hour | delay(s)")
    for label, row in summary.items():
        rate = row["false_per_hour"]
        frac = f"{row['hits']}/{row['reviewed']}" if row["reviewed"] else "n/a"
        print(
            label,
            frac,
            row["misses"],
            row["unassessed"],
            rate if rate is not None else "n/a",
            row["delays_s"] or "n/a",
            sep=" | ",
        )
    control = benign_control(args.folder / "hue-benign.pcap")
    print("Independent benign control (incidents / assessed minutes):")
    for label, row in control.items():
        print(label, row["false_incidents"], "/", row["assessed_minutes"])
    if args.json:
        args.json.write_text(
            json.dumps(
                dict(
                    summary=summary,
                    kitsune=captures,
                    gotham=devices,
                    splunk=auth,
                    hue_control=control,
                ),
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
