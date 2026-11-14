"""Run capture, trained inference, incident review and restart on a disposable lab."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

from collect_dataset import collect, ROOT
from server_smoke import main as pipeline


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--run', type=Path, help='reuse a recorded pause run from the lab')
    args = parser.parse_args()
    folder = args.run
    if folder is None:
        parent = ROOT / 'data/runs' / f'incident-{time.time_ns()}'
        parent.mkdir(parents=True)
        folder = parent / collect(parent, 'pause', 91, 90, 4, {})
    report = json.loads((args.artifact / 'report.json').read_text())
    token = secrets.token_hex(32)
    config = dict(NETWATCH_MODEL_BUNDLE=str((args.artifact / 'bundle.json').resolve()),
                  NETWATCH_MODEL_SHA256=report['bundle_sha256'], NETWATCH_MODEL_ID=report['model_id'],
                  NETWATCH_OPERATOR_TOKENS=json.dumps({'acceptance':token}),
                  NETWATCH_WEB_DIR=str(ROOT/'web/dist'))

    def journal(get, base, restart):
        for _ in range(200):
            code, result = get(base+'/v1/incidents', token)
            if code == 200 and any(i['closed_ns'] for i in result['incidents']):
                break
            time.sleep(.1)
        else:
            raise RuntimeError('no closed incident in the actual model output')
        event = json.loads((folder/'truth.json').read_text())['events'][0]
        target = next(i for i in result['incidents'] if
                      int(i['first_ns']) < event['end_ns'] and int(i['closed_ns'] or 0) > event['start_ns'])
        path = base+'/v1/incidents/'+target['id']
        env = dict(os.environ, NETWATCH_UI_URL=base, NETWATCH_UI_TEST_TOKEN=token, NETWATCH_UI_ID=target['id'])
        subprocess.run(['node','test/journal.mjs'],cwd=ROOT/'web',env=env,check=True,timeout=90)
        before = get(path, token)
        restart()
        for _ in range(100):
            try:
                if get(path, token) == before and before[1]['incident']['ack_by']=='acceptance':
                    break
            except OSError:
                pass
            time.sleep(.1)
        else:
            raise RuntimeError('incident history differs after restart')
        print('Persisted incident',target['id'],'events',len(before[1]['events']),'after restart',flush=True)

    pipeline(folder/'live.jsonl',config,journal)


if __name__ == '__main__':
    main()
