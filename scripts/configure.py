from pathlib import Path
import secrets
p=Path('.env')
if p.exists():print('.env already exists; preserved')
else:
    with p.open('x') as f:f.write('NETWATCH_DB_PASSWORD='+secrets.token_urlsafe(32)+'\n')
    p.chmod(0o600);print('Created local .env (ignored by Git)')
