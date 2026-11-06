"""Restore the verified public IoT-23 sample using the tracked manifest."""
import hashlib
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.request import urlopen


def main():
    root = Path(__file__).resolve().parents[1]
    meta = json.loads((root / 'data/manifests/iot23-somfy-01.json').read_text())
    dest = root / 'data/raw/iot23' / meta['file_name']
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if hashlib.sha256(dest.read_bytes()).hexdigest() != meta['sha256']:
            raise ValueError('Existing sample differs from the manifest; file preserved')
        print('Verified', dest)
        return
    with NamedTemporaryFile(dir=dest.parent, delete=False) as file:
        partial = Path(file.name)
    try:
        with urlopen(meta['source'], timeout=30) as response:
            data = response.read(meta['bytes'] + 1)
        if len(data) != meta['bytes'] or hashlib.sha256(data).hexdigest() != meta['sha256']:
            raise ValueError('Downloaded capture differs from the verified manifest')
        partial.write_bytes(data)
        partial.replace(dest)
        print('Restored', dest)
    finally:
        partial.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
