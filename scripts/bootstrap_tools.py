"""Install the local uv fallback used by scripts/uv."""

from pathlib import Path
import shutil
import subprocess
import venv


def main():
    if shutil.which("uv"):
        print("Using uv from PATH")
        return

    target = Path(__file__).resolve().parents[1] / ".tools/uv"
    if not (target / "bin/uv").exists():
        venv.EnvBuilder(with_pip=True).create(target)
        subprocess.run(
            [str(target / "bin/python"), "-m", "pip", "install", "uv==0.13.7"],
            check=True,
        )
    print("Using project-local uv")


if __name__ == "__main__":
    main()
