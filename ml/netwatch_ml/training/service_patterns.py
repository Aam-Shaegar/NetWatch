"""Extend a trained pause classifier with limits fitted to normal service windows."""
import argparse
import json
from pathlib import Path
import tempfile

from netwatch_ml.models.detector import load_bundle, model_id
from netwatch_ml.models.patterns import LIMIT_KEYS, measurements, match
from netwatch_ml.training.baselines import read_partitions, sha


def build(dataset, source, output):
    original = json.loads((source / "report.json").read_text())
    base = load_bundle(source / "bundle.json", original["bundle_sha256"])["detector"]
    if ("classifier" not in base or "pattern_limits" in base or
            base["dataset_manifest_sha256"] != sha(dataset / "manifest.json")):
        raise ValueError("expected the matching trained laboratory classifier")
    parts = read_partitions(dataset)
    normal = parts["train"] + parts["calibration"]
    # A fixed 50% margin above each reference maximum, chosen before collecting test episodes.
    limits = {label: max(values) * 1.5 for label, values in zip(LIMIT_KEYS, zip(*(measurements(r) for r in normal)))}
    reference_matches = sum(match(r, limits)[1] > 1 for r in normal)
    detector = dict(base, pattern_limits=limits)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage = Path(tmp) / "artifact"
        stage.mkdir()
        path = stage / "bundle.json"
        path.write_text(json.dumps(dict(model_id=model_id(detector), detector=detector), allow_nan=False))
        digest = sha(path)
        loaded = load_bundle(path, digest)
        report = dict(model_id=loaded["model_id"], classifier_version=loaded["classifier_version"],
                      bundle_sha256=digest, source_sha256=original["bundle_sha256"],
                      limits=limits, normal_reference_windows=len(normal), reference_matches=reference_matches)
        (stage / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        stage.rename(output)
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("dataset", "source", "output"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    print(json.dumps(build(args.dataset, args.source, args.output), indent=2))
