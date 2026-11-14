"""Force real ENOSPC on a private 1 MiB tmpfs; verify a committed record survives."""

import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
(ROOT / "data/runs").mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=ROOT / "data/runs") as tmp:
    Path(tmp).chmod(0o755)  # Synthetic public fixture mounted read-only in a capability-free container.
    fixture = json.loads((ROOT / "contracts/examples/window.valid.json").read_text())
    Path(tmp, "samples").write_text(json.dumps(fixture) + "\n")
    Path(tmp, "next").write_text(
        json.dumps(dict(fixture, event_id="after-disk-full")) + "\n"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            "/scratch:size=1m",
            "-v",
            f"{tmp}:/inputs:ro",
            "--entrypoint",
            "sh",
            "netwatch-sensor:dev",
            "-ec",
            """
netwatch-sensor enqueue --input /inputs/samples --spool /scratch/q
if dd if=/dev/zero of=/scratch/fill bs=4096 2>/dev/null; then exit 1; fi
# The last allocated segment page can still have room for several records.
count=1
while message=$(netwatch-sensor enqueue --input /inputs/next --spool /scratch/q 2>&1); do
    count=$((count+1))
    test "$count" -lt 16
done
echo "$count"
case "$message" in *"no space left on device"*) ;; *) exit 1 ;; esac
rm /scratch/fill
netwatch-sensor spool-status --spool /scratch/q
netwatch-sensor enqueue --input /inputs/next --spool /scratch/q
netwatch-sensor spool-status --spool /scratch/q
""",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + " " + result.stderr)
    states = [
        json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")
    ]
    pending = [s["pending"] for s in states if "pending" in s]
    if (
        len(pending) != 2
        or pending[0] != int(result.stdout.splitlines()[0])
        or pending[1] != pending[0] + 1
    ):
        raise RuntimeError("unexpected persisted queue counts: " + str(pending))
    print(
        f"ENOSPC rejected append; {pending[0]} records survived; retry left {pending[1]} pending."
    )
