"""Offline commands for the NetWatch v1 dataset, models, and acceptance reports."""

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

from jsonschema import ValidationError

from netwatch_ml.v1.dataset import compile_dataset
from netwatch_ml.v1.evaluation import evaluate, train_models
from netwatch_ml.v1.model import encoded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    data = commands.add_parser("prepare")
    data.add_argument("manifest")
    data.add_argument("output")
    data.add_argument("--sensor", required=True)
    data.add_argument("--catalogue", required=True)
    train = commands.add_parser("train")
    train.add_argument("dataset")
    train.add_argument("models")
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--max-fpr", type=float, default=0.02)
    train.add_argument("--max-unknown-acceptance", type=float, default=0.10)
    test = commands.add_parser("evaluate")
    test.add_argument("mode", choices=("find", "classify", "pipeline"))
    test.add_argument("dataset")
    test.add_argument("models")
    test.add_argument("report")
    test.add_argument("--model")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            compile_dataset(args.manifest, args.output, args.sensor, args.catalogue)
            print(args.output)
        elif args.command == "train":
            print(encoded(train_models(args.dataset, args.models, args.seed, args.max_fpr,
                                       args.max_unknown_acceptance)).decode(), end="")
        else:
            result = encoded(evaluate(args.dataset, args.models, args.mode, args.model))
            path = Path(args.report)
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".report-", dir=path.parent) as staging:
                completed = Path(staging) / "report.json"
                completed.write_bytes(result)
                completed.replace(path)
            print(result.decode(), end="")
    except (ValueError, OSError, ValidationError, KeyError, TypeError, ArithmeticError,
            EOFError, AttributeError, ImportError, subprocess.CalledProcessError, StopIteration) as error:
        print(f"NetWatch v1: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
