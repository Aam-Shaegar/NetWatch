"""Exercise the work stack with isolated PostgreSQL and a pinned local model."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def wait_for(check, purpose, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except OSError:
            pass
        time.sleep(0.3)
    raise RuntimeError(f"Timed out waiting for {purpose}")


def run(artifact, output, exercise=None, entities="TCP/192.0.2.10:8080", policy="v1", operations=False):
    info = json.loads((artifact / "report.json").read_text())
    raw = (artifact / "bundle.json").read_bytes()
    checksum = hashlib.sha256(raw).hexdigest()
    if checksum != info["bundle_sha256"]:
        raise ValueError("Incorrect model checksum")
    model = json.loads(raw)["detector"]
    version = model["feature_set_version"]
    binding = model.get("binding", {"sensor_id": "smoke", "entity_id": "TCP/192.0.2.10:8080"})
    other_sensor = "e2e-other" if binding["sensor_id"] != "e2e-other" else "e2e-alternate"
    project = "netwatch-work-test-" + secrets.token_hex(5)
    token, another, operator, password = [secrets.token_hex(24) for _ in range(4)]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="netwatch-work-test-") as folder:
        tls_dir = Path(folder)
        cert, key = tls_dir / "cert.pem", tls_dir / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # The disposable certificate must be readable by the non-root container.
        tls_dir.chmod(0o755)
        key.chmod(0o444)
        cert.chmod(0o444)
        tls = ssl.create_default_context(cafile=str(cert))
        database = f"postgres://netwatch:{password}@db:5432/netwatch?sslmode=disable"
        env = dict(
            os.environ,
            NETWATCH_DB_USER="netwatch",
            NETWATCH_DB_PASSWORD=password,
            NETWATCH_DATABASE_URL=database,
            NETWATCH_MIGRATION_DATABASE_URL=database,
            NETWATCH_TLS_DIR=str(tls_dir),
            NETWATCH_MODEL_DIR=str(artifact),
            NETWATCH_MODEL_SHA256=checksum,
            NETWATCH_MODEL_ID=info["model_id"],
            NETWATCH_SENSOR_TOKENS=json.dumps({binding["sensor_id"]: token, other_sensor: another}),
            NETWATCH_OPERATOR_TOKENS=json.dumps({"tester": operator}),
            NETWATCH_API_HOST="127.0.0.1",
            NETWATCH_API_PORT=str(port),
            NETWATCH_GRPC_PORT="0",
            NETWATCH_POLICY_VERSION=policy,
            NETWATCH_CAPTURE_FEATURE_SET=version,
            NETWATCH_SERVICE_MODEL_ENTITIES=entities + "," + binding["entity_id"],
        )
        env.pop("COMPOSE_PROFILES", None)
        base = f"https://127.0.0.1:{port}"
        command = [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(ROOT / "deploy/work.yaml"),
        ]

        def docker(*parts, check=True, **kwargs):
            return subprocess.run(
                [*command, *parts], cwd=ROOT, env=env, timeout=600, check=check, **kwargs
            )

        def call(route, bearer=None, payload=None, headers=None):
            options = dict(headers or {})
            if bearer:
                options["Authorization"] = f"Bearer {bearer}"
            if payload is not None:
                options["Content-Type"] = "application/json"
            data = json.dumps(payload).encode() if payload is not None else None
            req = Request(base + route, data, options)
            try:
                response = urlopen(req, context=tls, timeout=5)
            except HTTPError as error:
                response = error
            with response:
                return response.code, response.headers, response.read()

        try:
            build = (
                ["--no-build"]
                if os.getenv("NETWATCH_E2E_PREBUILT") == "1"
                else ["--build"]
            )
            docker("up", "-d", *build, "--wait", "--wait-timeout", "150")
            assert call("/health/ready")[0] == 200
            assert call("/")[0] == 200
            assert call("/v1/incidents")[0] == 401

            window = json.loads(
                (ROOT / "contracts/examples/window.valid.json").read_text()
            )
            window.update(
                sensor_id=binding["sensor_id"],
                event_id="work-smoke",
                feature_set_version=version,
                entity_type="destination_service",
                entity_id=binding["entity_id"],
            )
            window["features"] = {name: window["features"].get(name) for name in model["features"]}
            window["quality"]["capture_dropped"] = 0
            batch = dict(
                schema_version=1,
                batch_id="1" * 64,
                windows=[window],
                queue_loss={"count": 0},
            )
            assert (
                call(
                    "/v1/windows", token, batch, {"Idempotency-Key": batch["batch_id"]}
                )[0]
                == 200
            )

            def prediction():
                status, _, body = call("/v1/predictions/work-smoke", token)
                return json.loads(body)["predictions"] if status == 200 else None

            pred = wait_for(prediction, "the committed prediction")[0]
            assert pred["prediction"]["model_id"] == info["model_id"]
            assert pred["prediction"]["feature_set_version"] == version
            assert pred["policy_version"] == policy
            assert pred["prediction"]["status"] in ("normal", "anomalous")

            docker("stop", "ml")
            obs = {
                "schema_version": 1,
                "entity": "work-smoke",
                "start_s": 0,
                "interval_s": 60,
                "metrics": {"in_pps": 15, "pps_baseline_ratio": 1},
            }
            status, headers, body = call("/v1/security/observations", token, obs)
            assert status == 202, (status, body)
            route = headers["Location"]
            receipt = json.loads(body)
            assert (
                json.loads(call("/v1/security/observations", token, obs)[2]) == receipt
            )
            assert call(route, another)[0] == 404
            assert json.loads(call(route, token)[2])["status"] in ("pending", "leased")
            code, _, payload = call("/v1/pipeline/status", operator)
            assert code == 200 and json.loads(payload)["assessment"]["queued"] == 1
            docker("start", "ml")

            def assessed():
                status, _, body = call(route, token)
                got = json.loads(body)
                return got if status == 200 and got["status"] == "done" else None

            stored = wait_for(assessed, "processing of the accepted observation")
            journal = json.loads(
                call("/v1/security/observations?entity=work-smoke", operator)[2]
            )
            assert [row["id"] for row in journal["observations"]] == [
                stored["observation_id"]
            ]
            assert (
                json.loads(call("/v1/pipeline/status", operator)[2])["assessment"][
                    "queued"
                ]
                == 0
            )
            docker("restart", "api")
            wait_for(lambda: call("/health/ready")[0] == 200, "API after restart")
            assert json.loads(call(route, token)[2]) == stored
            operation_report = None
            if operations:
                operation_report = verify_operations(
                    docker, call, token, operator, base, tls_dir, batch
                )
            extra = exercise(call, token, operator) if exercise is not None else None
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(
                    {
                        "passed": True,
                        "model_id": info["model_id"],
                        "prediction": pred["prediction"]["status"],
                        "acceptance": extra,
                        "operations": operation_report,
                        "checks": [
                            "tls",
                            "static_journal",
                            "auth",
                            "window_to_prediction",
                            "assessment_during_ml_outage",
                            "duplicate_receipt",
                            "sensor_scope",
                            "assessment_recovered",
                            "queue_status",
                            "persisted_after_api_restart",
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            return extra
        finally:
            docker("down", "-v", "--remove-orphans", check=False)


def verify_operations(docker, call, sensor, operator, base, folder, historical_batch):
    executable = folder / "netwatch"
    subprocess.run(["go", "build", "-o", str(folder), "./cmd/netwatch", "./cmd/netwatch-sensor"], cwd=ROOT, check=True)
    token_file = folder / "operator.token"
    token_file.touch(mode=0o600)
    token_file.write_text(operator + "\n")

    def cli(action, status=0, *options):
        result = subprocess.run(
            [str(executable), action, "--url", base, "--ca", str(folder / "cert.pem"),
             "--token-file", str(token_file), "--json", *options],
            capture_output=True, text=True, timeout=20,
        )
        assert result.returncode == status, (result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout)

    stale = cli("doctor", 2)
    assert "capture_stale" in stale["issues"] and "no_recent_usable_prediction" in stale["issues"], stale
    assert call("/v1/pipeline/status", sensor)[0] == 401
    assert "incidents" in cli("incidents", 0, "--since", "24h")

    end = time.time_ns() // 5_000_000_000 * 5_000_000_000
    window = dict(historical_batch["windows"][0], event_id="work-live", capture_epoch="work-live",
                  window_start_ns=str(end - 5_000_000_000), window_end_ns=str(end))
    batch = dict(historical_batch, batch_id="2" * 64, windows=[window])
    headers = {"Idempotency-Key": batch["batch_id"]}
    window_file = folder / "live-window.jsonl"
    window_file.write_text(json.dumps(window) + "\n")
    spool = folder / "spool"
    sender = str(folder / "netwatch-sensor")
    subprocess.run([sender, "enqueue", "--spool", str(spool), "--input", str(window_file)],
                   capture_output=True, text=True, timeout=20, check=True)
    docker("stop", "worker", "db")
    assert call("/health/ready")[0] == 503
    assert call("/v1/windows", sensor, batch, headers)[0] == 503
    outage = cli("doctor", 2)
    assert set(outage["issues"]) == {"ingestion_not_ready", "pipeline_status_unavailable"}, outage
    docker("start", "db")
    wait_for(lambda: call("/health/ready")[0] == 200, "API recovery after database restart")
    delivered = subprocess.run(
        [sender, "send", "--once", "--spool", str(spool), "--endpoint", base + "/v1/windows"],
        env=dict(os.environ, NETWATCH_SENSOR_TOKEN=sensor,
                 NETWATCH_SENSOR_CA_PEM=(folder / "cert.pem").read_text()),
        capture_output=True, text=True, timeout=20,
    )
    assert delivered.returncode == 0, delivered.stderr
    queued = cli("status")["inference"]["queued"]
    assert queued == 1, queued
    pending = cli("doctor", 2, "--max-age", "2m")
    assert "no_recent_usable_prediction" in pending["issues"], pending
    docker("start", "worker")

    def recovered():
        status = cli("status")
        return status if status["usable_prediction"]["event_age_s"] < 120 else None

    snapshot = wait_for(recovered, "a recent prediction after worker restart")
    assert cli("doctor", 0, "--max-age", "2m")["ready"]
    latest = time.time_ns() // 5_000_000_000 * 5_000_000_000
    bad_quality = dict(window, event_id="work-loss", window_start_ns=str(latest - 5_000_000_000),
                       window_end_ns=str(latest), capture_epoch="work-loss",
                       quality=dict(window["quality"], coverage="gap", capture_dropped=1))
    bad_batch = dict(batch, batch_id="3" * 64, windows=[bad_quality])
    assert call("/v1/windows", sensor, bad_batch, {"Idempotency-Key": bad_batch["batch_id"]})[0] == 200
    wait_for(lambda: cli("status")["prediction"]["status"] == "insufficient_data", "a capture loss abstention")
    degraded = cli("doctor", 2, "--max-age", "2m")
    assert "capture_quality_degraded" in degraded["issues"] and "latest_prediction_unavailable" in degraded["issues"], degraded
    wait_for(lambda: cli("status")["projection_pending"] == 0, "incident queue to drain")
    backup = verify_database_restore(docker)
    return {
        "stale_replay_reported": True,
        "postgres_outage_reported": True,
        "sensor_spool_delivered_over_https_with_private_ca": True,
        "capture_loss_reported": True,
        "durable_inference_jobs_while_worker_stopped": queued,
        "recovered_delay_s": snapshot["usable_prediction"]["processing_delay_s"],
        "restored_table_rows": backup,
    }


def verify_database_restore(docker):
    def sql(database, statement):
        return docker("exec", "-T", "db", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                      "-U", "netwatch", "-d", database, "-c", statement, text=True,
                      stdout=subprocess.PIPE).stdout.strip()

    archive = docker("exec", "-T", "db", "pg_dump", "-Fc", "-U", "netwatch", "netwatch",
                     stdout=subprocess.PIPE).stdout
    target = "restore_drill"
    docker("exec", "-T", "db", "createdb", "-U", "netwatch", target)
    docker("exec", "-T", "db", "pg_restore", "--exit-on-error", "-U", "netwatch", "-d", target, input=archive)
    tables = sql("netwatch", "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1").splitlines()
    target_tables = sql(target, "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1").splitlines()
    assert tables and tables == target_tables
    counts = {}
    for table in tables:
        ident = '"' + table.replace('"', '""') + '"'
        query = ("SELECT count(*),md5(coalesce(string_agg(row_json, chr(10) ORDER BY row_json),'')) "
                 f"FROM (SELECT to_jsonb(t)::text AS row_json FROM {ident} AS t) AS rows")
        original = sql("netwatch", query)
        assert original == sql(target, query), table
        counts[table] = int(original.split("|", 1)[0])
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--policy", default="v1", choices=("v1", "v2"))
    args = parser.parse_args()
    run(args.artifact.resolve(strict=True), args.output, policy=args.policy, operations=True)
