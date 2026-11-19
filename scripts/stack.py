"""Commands for the persistent NetWatch Docker stack and one-shot training."""

import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def compose(work_file, *arguments, env=None):
    command = ["docker", "compose"]
    if work_file is not None:
        command += ["--env-file", str(work_file)]
    file, *parts = arguments
    return subprocess.run(
        [*command, "-f", str(ROOT / "deploy" / file), *parts],
        cwd=ROOT,
        env=env,
        check=False,
    ).returncode


def work(args):
    config = args.env.expanduser().resolve()
    if not config.is_file():
        raise SystemExit(f"Create {config} from deploy/work.env.example first.")
    commands = {
        "start": ("up", "-d", "--build", "--wait", "--wait-timeout", "120"),
        "status": ("ps", "-a"),
        "logs": ("logs", "--tail", "150"),
        "stop": ("stop",),
    }
    if args.action == "logs":
        if args.follow:
            return compose(config, "work.yaml", *commands["logs"], "--follow")
    return compose(config, "work.yaml", *commands[args.action])


def train(args):
    dataset = args.dataset.expanduser().resolve()
    target = args.output.expanduser().resolve()
    manifest_path = dataset / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"No dataset manifest in {dataset}.")
    manifest = json.loads(manifest_path.read_text())
    module, source = (
        ("profiled", "/dataset/manifest.json") if "captures" in manifest
        else ("baselines", "/dataset")
    )
    if target.exists():
        raise SystemExit(f"Model output path must not exist: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    env = dict(
        os.environ,
        NETWATCH_DATASET_DIR=str(dataset),
        NETWATCH_TRAIN_MODULE=module,
        NETWATCH_TRAIN_INPUT=source,
        NETWATCH_TRAIN_OUTPUT_DIR=str(target.parent),
        NETWATCH_TRAIN_OUTPUT_NAME=target.name,
        NETWATCH_RUN_UID=str(os.getuid()),
        NETWATCH_RUN_GID=str(os.getgid()),
    )
    return compose(None, "train.yaml", "run", "--rm", "--build", "trainer", env=env)


def check():
    # Compose config expands variables without opening the local TLS/model paths.
    example = {
        "NETWATCH_TLS_DIR": "/etc/netwatch/tls",
        "NETWATCH_DB_PASSWORD": "compose-check",
        "NETWATCH_DATABASE_URL": "postgres://netwatch:compose-check@db/netwatch",
        "NETWATCH_SENSOR_TOKENS": '{}',
        "NETWATCH_OPERATOR_TOKENS": '{}',
        "NETWATCH_MODEL_DIR": "/var/lib/netwatch/model",
        "NETWATCH_MODEL_ID": "compose-check",
        "NETWATCH_MODEL_SHA256": "0" * 64,
        "NETWATCH_SERVICE_MODEL_ENTITIES": "TCP/192.0.2.10:443",
    }
    if compose(None, "work.yaml", "--profile", "sensor", "--profile", "probe", "config", "--quiet", env=dict(os.environ, **example)):
        return 1
    trainer = {"NETWATCH_DATASET_DIR": "/var/lib/netwatch/dataset",
               "NETWATCH_TRAIN_MODULE": "profiled", "NETWATCH_TRAIN_INPUT": "/dataset/manifest.json",
               "NETWATCH_TRAIN_OUTPUT_DIR": "/var/lib/netwatch/models", "NETWATCH_TRAIN_OUTPUT_NAME": "candidate",
               "NETWATCH_RUN_UID": str(os.getuid()), "NETWATCH_RUN_GID": str(os.getgid())}
    return compose(None, "train.yaml", "config", "--quiet", env=dict(os.environ, **trainer))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    serve = modes.add_parser("work")
    serve.add_argument("action", choices=("start", "status", "logs", "stop"))
    serve.add_argument("--env", type=Path, default=ROOT / ".env.work")
    serve.add_argument("--follow", action="store_true")
    learn = modes.add_parser("train")
    learn.add_argument("dataset", type=Path)
    learn.add_argument("output", type=Path)
    modes.add_parser("check")
    args = parser.parse_args()
    if args.mode == "check":
        return check()
    return work(args) if args.mode == "work" else train(args)


if __name__ == "__main__":
    raise SystemExit(main())
