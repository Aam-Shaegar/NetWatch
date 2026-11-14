"""Verify an actual trained detector via sensor -> API -> worker -> ML -> PostgreSQL."""
import argparse
from collections import deque
import json
from pathlib import Path
import tempfile

from netwatch_ml.models.detector import load_bundle, predict_window
from server_smoke import main as pipeline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('windows', type=Path)
    args = parser.parse_args()
    report = json.loads((args.artifact / 'report.json').read_text())
    path = (args.artifact / 'bundle.json').resolve()
    bundle = load_bundle(path, report['bundle_sha256'])
    past = deque(maxlen=12)
    with args.windows.open() as stream:
        for line in stream:
            window = json.loads(line)
            expected = predict_window(window, bundle, list(past))
            if expected['score'] is not None:
                break
            past.append(window)
        else:
            raise ValueError('provide a capture with a supported complete window')
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / 'window.jsonl'
        records = [window, *past] if 'runtime' in bundle else [window]
        sample.write_text(''.join(json.dumps(r) + '\n' for r in records))
        prediction = pipeline(sample, {'NETWATCH_MODEL_ID': bundle['model_id'],
                                      'NETWATCH_MODEL_BUNDLE': str(path),
                                      'NETWATCH_MODEL_SHA256': report['bundle_sha256']})
        if prediction != expected:
            raise ValueError('stored prediction differs from offline inference')


if __name__ == '__main__':
    main()
