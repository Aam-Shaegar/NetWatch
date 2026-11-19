"""Measure a read-only HTTP service pilot on NetWatch's isolated Docker network."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import time
import urllib.request

from server_smoke import main as pipeline

ROOT = Path(__file__).resolve().parents[1]


def command(args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=kwargs.pop("timeout", 120),
        **kwargs,
    ).stdout.strip()


def save(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


def query(container, sql, database="netwatch_test"):
    return command(
        [
            "docker",
            "exec",
            container,
            "psql",
            "-XAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            database,
            "-c",
            sql,
        ]
    )


def deliver(base, token, windows):
    batch = dict(
        schema_version=1, batch_id="", windows=windows, queue_loss={"count": 0}
    )
    batch["batch_id"] = hashlib.sha256(json.dumps(batch).encode()).hexdigest()
    req = urllib.request.Request(
        base + "/v1/windows",
        data=json.dumps(batch).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "Idempotency-Key": batch["batch_id"],
        },
    )
    with urllib.request.urlopen(req, timeout=15) as res:
        ack = json.load(res)
    if (
        ack["accepted_event_ids"] != [w["event_id"] for w in windows]
        or ack["batch_id"] != batch["batch_id"]
    ):
        raise RuntimeError("unexpected delivery acknowledgement")


def backup(container):
    # Capture data in a consistent dump once the projection queue has drained.
    dest = "restore_drill"
    command(
        [
            "docker",
            "exec",
            container,
            "pg_dump",
            "-U",
            "postgres",
            "-Fc",
            "-f",
            "/tmp/drill.dump",
            "netwatch_test",
        ]
    )
    command(["docker", "exec", container, "createdb", "-U", "postgres", dest])
    command(
        [
            "docker",
            "exec",
            container,
            "pg_restore",
            "-U",
            "postgres",
            "--exit-on-error",
            "-d",
            dest,
            "/tmp/drill.dump",
        ]
    )
    tables = query(
        container,
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1",
    ).splitlines()
    checks = {}
    for table in tables:
        sql = f"SELECT count(*),md5(coalesce(string_agg(to_jsonb(t)::text,chr(10) ORDER BY to_jsonb(t)::text),'')) FROM \"{table}\" t"
        original = query(container, sql)
        if original != query(container, sql, dest):
            raise RuntimeError("restored content mismatch: " + table)
        checks[table] = int(original.split("|")[0])
    return checks


def run(args):
    artifact = args.artifact.resolve()
    info = json.loads((artifact / "report.json").read_text())
    token = secrets.token_hex(32)
    config = dict(
        NETWATCH_MODEL_ID=info["model_id"],
        NETWATCH_MODEL_BUNDLE=str(artifact / "bundle.json"),
        NETWATCH_MODEL_SHA256=info["bundle_sha256"],
        NETWATCH_OPERATOR_TOKENS=json.dumps({"pilot": token}),
    )
    name = "nw-ops-" + str(time.time_ns())
    out = ROOT / "data/runs" / name
    out.mkdir(parents=True, mode=0o770)
    out.chmod(0o770)
    env = dict(
        os.environ, NETWATCH_RUN_DIR=str(out), NETWATCH_OUTPUT_GID=str(os.getgid())
    )
    compose = [
        "docker",
        "compose",
        "-p",
        name,
        "-f",
        str(ROOT / "deploy/lab/compose.yaml"),
        "-f",
        str(ROOT / "deploy/lab/operations.yaml"),
    ]

    def dc(*parts, **kwargs):
        return command(compose + list(parts), env=env, **kwargs)

    stamp = lambda: datetime.now(timezone.utc).isoformat()
    report = dict(
        sensor_image=command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", "netwatch-sensor:dev"]
        ),
        go=command(["go", "version"], cwd=ROOT),
        started=stamp(),
        duration_requested_s=args.seconds,
        git=command(["git", "rev-parse", "HEAD"], cwd=ROOT),
        model=info["model_id"],
        bundle_sha256=info["bundle_sha256"],
        host=platform.machine(),
        docker=json.loads(
            command(
                [
                    "docker",
                    "info",
                    "--format",
                    '{"cpus":{{.NCPU}},"ram_bytes":{{.MemTotal}},"kernel":"{{.KernelVersion}}"}',
                ]
            )
        ),
        network="isolated target eth0 TCP 8080",
        window_s=5,
        capture_lateness=args.lateness,
        rates=[4] if args.pause else [5, 15, 3],
        phase_s=60,
    )
    print(out, flush=True)
    save(out / "report.json", report)

    def exercise(db, native, get):
        base = "http://" + native["NETWATCH_LISTEN"]
        target = dc("ps", "-q", "target")
        ip = command(
            [
                "docker",
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                target,
            ]
        )
        # Use the target namespace; omit raw PCAP and per-request logs during long runs.
        sensor = dc(
            "run",
            "-d",
            "--no-deps",
            "sensor",
            "live",
            "--interface",
            "eth0",
            "--service",
            ip + ":8080",
            "--filter",
            "tcp port 8080",
            "--sensor",
            "smoke",
            "--lateness",
            args.lateness,
            "--output",
            "/output/windows.jsonl",
        )
        if args.pause:
            client = dc(
                "run",
                "-d",
                "--no-deps",
                "-v",
                str(ROOT / "lab") + ":/lab:ro",
                "-e",
                "PROFILE=pause",
                "-e",
                "RATE=4",
                "-e",
                "SEED=91",
                "-e",
                f"DURATION={args.seconds}",
                "client",
                "python",
                "/lab/collection_client.py",
            )
        else:
            client = dc(
                "run",
                "-d",
                "--no-deps",
                "-v",
                str(ROOT / "scripts/ops_client.py") + ":/lab/ops_client.py:ro",
                "client",
                "python",
                "/lab/ops_client.py",
                str(args.seconds),
            )
        started = time.monotonic()
        if get(base + "/v1/incidents")[0] != 401:
            raise RuntimeError("anonymous journal access")
        windows = out / "windows.jsonl"
        while not windows.exists() and time.monotonic() - started < 15:
            time.sleep(0.2)
        offset = 0

        def flush():
            nonlocal offset
            with windows.open("rb") as stream:
                stream.seek(offset)
                while True:
                    line = stream.readline()
                    if not line.endswith(b"\n"):
                        return
                    deliver(base, native["NETWATCH_SENSOR_TOKEN"], [json.loads(line)])
                    offset = stream.tell()

        sample_at = 0
        while True:
            flush()
            elapsed = time.monotonic() - started
            if elapsed >= sample_at:
                proc = command(["docker", "exec", sensor, "cat", "/proc/1/status"])
                rss = {
                    line.split(":")[0]: int(line.split()[1])
                    for line in proc.splitlines()
                    if line.startswith(("VmRSS:", "VmHWM:"))
                }
                if len(rss) != 2:
                    raise RuntimeError("missing sensor RSS counters")
                report.update(
                    elapsed_s=round(elapsed, 2),
                    rss_kib=rss["VmRSS"],
                    peak_rss_kib=max(report.get("peak_rss_kib", 0), rss["VmHWM"]),
                )
                stats = query(
                    db,
                    "SELECT (SELECT count(*) FROM predictions),(SELECT count(*) FROM incidents)",
                )
                with (out / "samples.jsonl").open("a") as stream:
                    print(
                        json.dumps(
                            dict(time=stamp(), elapsed_s=elapsed, **rss, counts=stats)
                        ),
                        file=stream,
                    )
                save(out / "report.json", report)
                sample_at = elapsed + min(60, max(5, args.seconds / 12))
            if elapsed >= args.seconds + 4:
                break
            time.sleep(0.25)
        command(["docker", "stop", "-t", "8", sensor])
        flush()
        if (
            command(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}}/{{.State.ExitCode}}",
                    client,
                ]
            )
            != "exited/0"
        ):
            raise RuntimeError("HTTP client failed")
        if args.pause:
            truth = json.loads((out / "truth.json").read_text())
            report["http"] = {
                "errors": 0,
                "elapsed_s": (truth["end_ns"] - truth["start_ns"]) / 1e9,
                "success": sum(
                    len((out / (lane + ".jsonl")).read_text().splitlines())
                    for lane in truth["lanes"]
                ),
            }
        else:
            report["http"] = json.loads(
                command(["docker", "logs", client]).splitlines()[-1]
            )
        raw = subprocess.run(
            ["docker", "logs", sensor], text=True, capture_output=True, check=True
        )
        stop = next(
            e
            for e in map(json.loads, (raw.stdout + raw.stderr).splitlines())
            if e["event"] == "live_stopped"
        )
        duration = (int(stop["end_ns"]) - int(stop["start_ns"])) / 1e9
        stats = stop["stats"]
        with windows.open() as captured:
            window_packets = sum(
                w["features"]["in_packets"] + w["features"]["out_packets"]
                for w in map(json.loads, captured)
            )
        if (
            stop.get("error")
            or window_packets != stop["records"]
            or report["http"]["errors"]
        ):
            raise RuntimeError("capture, window accounting or HTTP workload failed")
        if report["http"]["elapsed_s"] < args.seconds:
            raise RuntimeError("short HTTP workload")
        report.update(
            capture_seconds=duration,
            records=stop["records"],
            pps=stop["records"] / duration,
            capture=stats,
            late_packets=stop.get("late_packets"),
            drop_fraction=stats["dropped"] / max(1, stats["received"]),
        )
        for _ in range(200):
            if query(db, "SELECT count(*) FROM incident_queue") == "0":
                break
            time.sleep(0.15)
        else:
            raise RuntimeError("projection backlog")
        report["prediction_latency_s"] = query(
            db,
            "SELECT percentile_cont(ARRAY[0.5,0.95,0.99]) WITHIN GROUP (ORDER BY extract(epoch FROM processed_at)-window_end_ns/1e9) FROM predictions JOIN feature_windows USING(event_id)",
        )
        latency = query(
            db,
            """SELECT json_build_object(
                'observation_to_receipt', percentile_cont(0.95) WITHIN GROUP
                    (ORDER BY extract(epoch FROM received_at)-window_end_ns/1e9),
                'receipt_to_prediction', percentile_cont(0.95) WITHIN GROUP
                    (ORDER BY extract(epoch FROM processed_at-received_at)))
                FROM predictions JOIN feature_windows USING(event_id)""",
        )
        report["pipeline_p95_seconds"] = json.loads(latency)
        report["incident_latency_s"] = query(
            db,
            "SELECT coalesce(json_agg(extract(epoch FROM detected_at)-detected_ns/1e9),'[]') FROM incidents",
        )
        if args.pause:
            event = truth["events"][0]
            matched = query(
                db,
                "SELECT extract(epoch FROM detected_at)-detected_ns/1e9 FROM incidents "
                f"WHERE detected_ns BETWEEN {int(event['start_ns'])} AND {int(event['end_ns'])}",
            )
            report["pause_detected"] = bool(matched)
            report["pause_incident_latency_s"] = [
                float(row) for row in matched.splitlines()
            ]
        report["restored_rows"] = backup(db)
        if (
            report["restored_rows"]["predictions"]
            != report["restored_rows"]["feature_windows"]
        ):
            raise RuntimeError("incomplete prediction history")
        command(["docker", "pause", db])
        try:
            # readiness has a 2 s DB timeout
            try:
                urllib.request.urlopen(base + "/health/ready", timeout=8)
            except urllib.error.HTTPError as e:
                if e.code != 503:
                    raise
            else:
                raise RuntimeError("unavailable DB reported ready")
        finally:
            command(["docker", "unpause", db])
        if get(base + "/health/ready")[0] != 200:
            raise RuntimeError("database recovery failed")
        report.update(db_outage="503 then 200", finished=stamp())
        save(out / "report.json", report)

    try:
        dc("up", "-d", "--wait", "target")
        pipeline(model_config=config, experiment=exercise)
    finally:
        # compose run creates one-off containers; clean up only this unique project.
        ids = command(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                "label=com.docker.compose.project=" + name,
            ]
        ).splitlines()
        if ids:
            command(["docker", "rm", "-f", *ids])
        dc("down", "--remove-orphans")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--lateness", default="1s", help="sensor event-time reorder allowance")
    parser.add_argument(
        "--pause",
        action="store_true",
        help="use audited two-lane commissioning workload",
    )
    args = parser.parse_args()
    if args.pause and args.seconds > 1800:
        parser.error("pause drill supports at most 1800 seconds")
    if not 30 <= args.seconds <= 604800:
        parser.error("duration must be between 30 seconds and seven days")
    run(args)
