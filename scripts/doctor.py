import shutil, subprocess, sys
from pathlib import Path
failed=[]
for tool,args in [('go',['version']),('node',['--version']),('npm',['--version']),('python3',['--version']),('docker',['compose','version']),('uv',['--version'])]:
    if tool=='uv' and not shutil.which(tool) and Path('.tools/uv/bin/uv').exists():tool=str(Path('.tools/uv/bin/uv').resolve())
    if not shutil.which(tool):failed.append(tool);print(tool+': missing');continue
    result=subprocess.run([tool,*args],text=True,capture_output=True)
    print((result.stdout or result.stderr).strip())
    if result.returncode:failed.append(tool)
if failed:print('Missing tools:',', '.join(failed));sys.exit(1)
print('Tooling ready. Docker daemon availability is checked by lab commands.')
