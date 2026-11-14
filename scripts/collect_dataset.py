"""Collect independent runs using NetWatch's isolated Compose lab and real Go sensor."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '-f', 'deploy/lab/compose.yaml', '-f', 'deploy/lab/collection.yaml']


def command(args, env=None, timeout=120):
    result = subprocess.run(args, cwd=ROOT, env=env, timeout=timeout, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args[:4]} failed: {result.stderr[-3000:]}')
    return result.stdout.strip()


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + '\n')


def collect(folder, profile, seed, duration, rate, provenance):
    group = 'nw-' + uuid.uuid4().hex[:16]
    output = folder / group
    output.mkdir()
    output.chmod(0o770)  # The restricted Linux client writes via the host group.
    env = dict(os.environ, NETWATCH_RUN_DIR=str(output), PROFILE=profile, SEED=str(seed),
               DURATION=str(duration), RATE=str(rate), NETWATCH_OUTPUT_GID=str(os.getgid()))
    base = [*COMPOSE, '-p', group]

    def compose(*args, timeout=120):
        return command([*base, *args], env, timeout)

    record = dict(schema_version=1, group_id=group, profile=profile, seed=seed, duration=duration,
                  rate=rate, provenance=provenance, status='incomplete')
    write_json(output / 'manifest.json', record)
    print('Starting', group, profile, seed, flush=True)
    try:
        compose('up', '-d', '--wait', '--no-build', 'target')
        target = compose('ps', '-q', 'target')
        networks = json.loads(command(['docker', 'inspect', '-f', '{{json .NetworkSettings.Networks}}', target]))
        address = networks[group + '_lab_data']['IPAddress']
        env['NETWATCH_SERVICE'] = address + ':8080'
        compose('up', '-d', '--no-build', 'sensor')
        sensor = compose('ps', '-q', 'sensor')
        for _ in range(100):
            logs = compose('logs', '--no-log-prefix', 'sensor')
            if '"live_started"' in logs:
                break
            time.sleep(.2)
        else:
            raise RuntimeError('sensor did not start')
        compose('run', '--rm', '--no-deps', 'client', timeout=duration + 90)
        metrics = json.loads(compose('exec', '-T', 'target', 'python', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/metrics').read().decode())"))
        time.sleep(1.5)
        compose('stop', '-t', '5', 'sensor')
        if command(['docker', 'inspect', '-f', '{{.State.ExitCode}}', sensor]) != '0':
            raise RuntimeError('sensor exited unsuccessfully')
        logs = [json.loads(line) for line in compose('logs', '--no-log-prefix', 'sensor').splitlines()
                if line.startswith('{')]
        stopped = next(e for e in logs if e['event'] == 'live_stopped')
        if stopped.get('error') or stopped['stats']['dropped'] or stopped['stats']['interface_dropped']:
            raise RuntimeError('capture incomplete')
        for name in ('live.pcap', 'live.jsonl'):
            command(['docker', 'cp', f'{sensor}:/output/{name}', str(output / name)])
        with (output / 'live.pcap').open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        record.update(service=env['NETWATCH_SERVICE'], target_requests=metrics, capture=stopped,
                      sha256=checksum,
                      status='captured')
        write_json(output / 'manifest.json', record)
        print('Captured', group, profile, stopped['records'], flush=True)
        return group
    finally:
        compose('down', '-v', '--remove-orphans')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--normal-runs', type=int, default=20)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--use-local-images', action='store_true', help='use installed lab and sensor images')
    args = parser.parse_args()
    if not 10 <= args.normal_runs <= 100 or not 30 <= args.seconds <= 1800 or not 1 <= args.workers <= 12:
        parser.error('expected 10..100 normal runs, 30..1800 seconds and 1..12 concurrent labs')
    folder = ROOT / 'data/runs' / ('collection-' + uuid.uuid4().hex[:12])
    folder.mkdir(parents=True)
    print(folder, flush=True)
    if not args.use_local_images:
        command([*COMPOSE, 'build', 'target', 'sensor'], timeout=1800)
    files = ['lab/client.py', 'lab/target.py', 'lab/collection_client.py', 'deploy/lab/compose.yaml',
             'deploy/lab/collection.yaml', 'deploy/lab/Dockerfile', 'scripts/collect_dataset.py']
    provenance = dict(commit=command(['git', 'rev-parse', 'HEAD']),
                      sources={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
                      images={name: command(['docker', 'image', 'inspect', '-f', '{{.Id}}', name])
                              for name in ('netwatch-lab:dev', 'netwatch-sensor:dev')})
    for name in files:
        snapshot = folder / 'sources' / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes((ROOT / name).read_bytes())
    profiles = ['stable', 'ramp', 'flash-crowd']
    plan = [(profiles[i % 3], args.seed + i, args.seconds, 2 + i % 4) for i in range(args.normal_runs)]
    plan += [('pause', args.seed + args.normal_runs + i, min(90, args.seconds), 4) for i in range(2)]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(collect, folder, *scenario, provenance) for scenario in plan]
        groups = [future.result() for future in futures]
    write_json(folder / 'collection.json', dict(groups=groups, config=vars(args)))
    print('Completed', folder, flush=True)


if __name__ == '__main__':
    main()
