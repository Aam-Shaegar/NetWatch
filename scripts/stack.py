"""Commands for the persistent NetWatch Docker stack and one-shot training."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def compose(work_file, *arguments, env=None, **streams):
    command = ["docker", "compose"]
    if work_file is not None:
        command += ["--env-file", str(work_file)]
    file, *parts = arguments
    return subprocess.run(
        [*command, "-f", str(ROOT / "deploy" / file), *parts],
        cwd=ROOT,
        env=env,
        check=False,
        **streams,
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
    if args.action in ("backup", "restore"):
        if args.archive is None:
            raise SystemExit("Set --archive to an external PostgreSQL archive path.")
        archive = args.archive.expanduser().absolute()
        if args.action == "backup":
            return backup(config, archive)
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", args.database or ""):
            raise SystemExit("Set --database to a new database name using lowercase ASCII letters, digits, or underscore.")
        return restore(config, archive, args.database)
    if args.action == "logs" and args.follow:
        return compose(config, "work.yaml", "--profile", "*", *commands["logs"], "--follow")
    profiles = () if args.action == "start" else ("--profile", "*")
    return compose(config, "work.yaml", *profiles, *commands[args.action])


def database_command(config, *args, **streams):
    return compose(
        config, "work.yaml", "exec", "-T", "db", "sh", "-euc",
        'export PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" PGDATABASE="$POSTGRES_DB"; exec "$@"',
        "netwatch-db", *args, **streams,
    )


def backup(config, archive):
    if archive.exists():
        raise SystemExit(f"Backup path already exists: {archive}")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=archive.parent, prefix=".netwatch-backup-") as temp:
        status = database_command(
            config, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", stdout=temp,
        )
        if status:
            return status
        temp.seek(0)
        if temp.read(5) != b"PGDMP":
            raise SystemExit("Backup did not produce a PostgreSQL custom archive.")
        os.fsync(temp.fileno())
        try:
            os.link(temp.name, archive)
        except FileExistsError as err:
            raise SystemExit(f"Backup path already exists: {archive}") from err
    print(f"Backup saved at {archive}")
    return 0


def restore(config, archive, database):
    with archive.open("rb", buffering=0) as source:
        if source.read(5) != b"PGDMP":
            raise SystemExit("Restore requires a PostgreSQL custom archive created by pg_dump.")
        source.seek(0)
        status = database_command(config, "pg_restore", "--list", stdin=source, stdout=subprocess.DEVNULL)
        if status:
            return status
        # CREATE DATABASE also guards against overwriting an existing database.
        status = database_command(config, "createdb", "--maintenance-db=postgres", database)
        if status:
            return status
        source.seek(0)
        status = database_command(
            config, "pg_restore", "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges",
            "--dbname", database, stdin=source,
        )
        if status:
            print(f"Restore failed; the newly created database {database} was left for inspection.", file=sys.stderr)
            return status
    print(f"Backup restored into {database}")
    return 0


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
    if compose(None, "work.yaml", "--profile", "sensor", "--profile", "sensor-v1", "--profile", "probe", "config", "--quiet", env=dict(os.environ, **example)):
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
    serve.add_argument("action", choices=("start", "status", "logs", "stop", "backup", "restore"))
    serve.add_argument("--env", type=Path, default=ROOT / ".env.work")
    serve.add_argument("--follow", action="store_true")
    serve.add_argument("--archive", type=Path, help="archive path for backup or restore")
    serve.add_argument("--database", help="new database name for restore")
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
