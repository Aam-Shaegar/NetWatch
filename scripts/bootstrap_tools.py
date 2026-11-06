"""Install tooling only inside this repository when uv is absent."""
from pathlib import Path
import shutil,subprocess,sys,venv
root=Path(__file__).resolve().parents[1]
if shutil.which('uv'):
    print('Using uv from PATH')
else:
    target=root/'.tools/uv'
    if not (target/'bin/uv').exists():
        venv.EnvBuilder(with_pip=True).create(target)
        subprocess.run([str(target/'bin/python'),'-m','pip','install','uv==0.13.7'],check=True)
    print('Using project-local uv')
