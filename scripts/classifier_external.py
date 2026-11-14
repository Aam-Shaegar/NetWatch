"""Prepare offline traffic-v1 windows for the held-out CIC capture excerpts."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from scapy.utils import RawPcapReader

from netwatch_ml.models.detector import load_bundle, predict_window

SOURCES = {
    "Friday-scan.pcap": ("port_scan", "--host", "192.168.10.50"),
    "Friday-ddos.pcap": ("ddos_like", "--service", "192.168.10.50:80"),
    "CIC-DDoS-2019-WebDDoS.pcap": ("ddos_like", "--service", "192.168.50.1:80"),
}


def audit(folder, sensor, bundle, output):
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {}
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage = Path(tmp) / "result"
        stage.mkdir()
        for name, (family, option, entity) in SOURCES.items():
            capture = folder / name
            with RawPcapReader(str(capture)) as reader:
                times = [
                    m.sec * 1_000_000_000 + m.usec * (1 if reader.nano else 1000)
                    for _, m in reader
                ]
            # Large gaps in the excerpts are unknown exposure. Never fill them with silent observations.
            ordered = sorted(times)
            gaps = [
                (a, b) for a, b in zip(ordered, ordered[1:]) if b - a > 5_000_000_000
            ]
            raw = stage / (name + ".raw")
            subprocess.run(
                [
                    str(sensor),
                    "replay",
                    "--input",
                    str(capture),
                    "--output",
                    str(raw),
                    option,
                    entity,
                    "--epoch",
                    name,
                    "--coverage-start",
                    str(ordered[0]),
                    "--coverage-end",
                    str(ordered[-1] + 1),
                ],
                check=True,
                capture_output=True,
            )
            counts = Counter()
            complete = 0
            with (stage / (name + ".jsonl")).open("w") as f:
                for line in raw.read_text().splitlines():
                    w = json.loads(line)
                    start, end = int(w["window_start_ns"]), int(w["window_end_ns"])
                    if any(start < b and end > a for a, b in gaps):
                        continue
                    result = predict_window(w, bundle)
                    counts[result["classification"]["label"]] += 1
                    complete += w["quality"]["coverage"] == "complete"
                    print(json.dumps(dict(window=w, prediction=result)), file=f)
            raw.unlink()
            report[name] = dict(
                family=family,
                entity=entity,
                packets=len(times),
                complete=complete,
                sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                outcomes=dict(counts),
            )
        (stage / "audit.json").write_text(json.dumps(report, indent=2) + "\n")
        stage.rename(output)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("pcaps", "sensor", "artifact", "output"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    meta = json.loads((args.artifact / "report.json").read_text())
    print(
        json.dumps(
            audit(
                args.pcaps,
                args.sensor.resolve(),
                load_bundle(args.artifact / "bundle.json", meta["bundle_sha256"]),
                args.output,
            ),
            indent=2,
        )
    )
