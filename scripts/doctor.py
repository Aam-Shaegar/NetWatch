"""Print the versions used by the local build."""

from pathlib import Path
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    tools = [
        ("go", "version"),
        ("node", "--version"),
        ("npm", "--version"),
        ("python3", "--version"),
        ("docker", "compose", "version"),
        (str(root / "scripts/uv"), "--version"),
    ]
    failed = []
    for name, *args in tools:
        executable = shutil.which(name)
        if executable is None:
            print(f"{name}: missing")
            failed.append(name)
            continue
        result = subprocess.run([executable, *args], text=True, capture_output=True)
        print((result.stdout or result.stderr).strip())
        if result.returncode:
            failed.append(Path(name).name)

    if failed:
        print("Check these tools:", ", ".join(failed))
        return 1
    print("Tooling ready. Lab commands check the Docker daemon.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
