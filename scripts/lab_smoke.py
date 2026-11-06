"""Collect an independent run, or a short smoke recording, in an isolated network."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['stable','ramp','flash-crowd'], default='stable')
    parser.add_argument('--duration', type=int, default=10)
    parser.add_argument('--rate', type=int, default=5)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    if not 1 <= args.duration <= 1800 or not 1 <= args.rate <= 50:
        parser.error('duration must be 1–1800 seconds and rate 1–50 requests/s')
    root = Path(__file__).resolve().parents[1]
    run_id = f'{args.profile}-{time.time_ns()}'
    output = root / 'data/runs' / run_id
    output.mkdir(parents=True)
    env = dict(os.environ, NETWATCH_RUN_DIR=str(output), PROFILE=args.profile, SEED=str(args.seed),
               RATE=str(args.rate), DURATION=str(args.duration))
    compose = ['docker','compose','-p',f'netwatch-{run_id}','-f',str(root/'deploy/lab/compose.yaml')]
    def run(command, **kwargs):
        return subprocess.run(command, cwd=root, env=env, check=True, **kwargs)
    try:
        run(compose + ['up','-d','--build','target','recorder'])
        capture = output / 'traffic.pcap'
        for _ in range(30):
            if capture.exists() and capture.stat().st_size >= 24:
                break
            time.sleep(1)
        else:
            raise RuntimeError('capture did not start')
        image = run(['docker','image','inspect','netwatch-lab:dev','--format','{{.Id}}'],
                    capture_output=True, text=True).stdout.strip()
        run(compose + ['run','--rm','client'])
    finally:
        run(compose + ['down'])
    result = json.loads((output/'ground_truth.json').read_text())
    if result['successful_requests'] == 0 or capture.stat().st_size <= 24:
        raise RuntimeError('no usable capture; inspect run files')
    manifest = output / 'manifest.json'
    run(['python3','scripts/register_capture.py',str(capture),'--source','local-lab','--run-id',run_id,
         '--output',str(manifest)])
    record = json.loads(manifest.read_text())
    record.update(group_id=run_id, image=image, scenario=vars(args), observation_profile='target eth0, TCP port 8080')
    manifest.write_text(json.dumps(record, indent=2)+'\n')
    print('Recording saved:', output)


if __name__ == '__main__':
    main()
