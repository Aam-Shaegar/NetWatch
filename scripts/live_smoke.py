"""Verify Linux live capture against replay in an isolated, disposable Docker lab."""
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    root = Path(__file__).resolve().parents[1]
    run_id = f'live-{time.time_ns()}'
    output = root / 'data/runs' / run_id
    output.mkdir(parents=True)
    env = dict(os.environ, NETWATCH_RUN_DIR=str(output), PROFILE='stable',
               RATE='5', DURATION='20', SEED='42')
    compose = ['docker', 'compose', '-p', f'netwatch-{run_id}', '-f',
               str(root / 'deploy/lab/compose.yaml')]

    def run(args, *, check=True, timeout=120):
        result = subprocess.run(args, cwd=root, env=env, text=True,
                                capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f'{args}:\n{result.stdout}\n{result.stderr}')
        return result

    def inspect(cid):
        return json.loads(run(['docker', 'inspect', cid]).stdout)[0]

    def logs(cid):
        result = run(['docker', 'logs', cid])
        events = []
        for line in (result.stdout + '\n' + result.stderr).splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    try:
        print('Building Linux sensor and lab...', flush=True)
        run(compose + ['build', 'target', 'sensor'], timeout=1800)
        run(compose + ['up', '-d', '--wait', 'target'])
        target = run(compose + ['ps', '-q', 'target']).stdout.strip()
        networks = inspect(target)['NetworkSettings']['Networks']
        address = next(iter(networks.values()))['IPAddress']
        env['NETWATCH_SERVICE'] = f'{address}:8080'
        run(compose + ['up', '-d', '--no-build', 'sensor'])
        sensor = run(compose + ['ps', '-q', 'sensor']).stdout.strip()
        for _ in range(40):
            if any(e.get('event') == 'live_started' for e in logs(sensor)):
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(f'sensor did not start: {logs(sensor)}')
        config = inspect(sensor)['HostConfig']
        assert {c.removeprefix('CAP_') for c in config['CapAdd']} == {'NET_RAW'}, config['CapAdd']
        assert config['CapDrop'] == ['ALL'], config['CapDrop']
        assert not config['Privileged'] and config['ReadonlyRootfs']
        devices = json.loads(run(['docker', 'exec', sensor, 'netwatch-sensor', 'interfaces']).stdout)
        assert any(d['Name'] == 'eth0' for d in devices)
        base = ['docker', 'run', '--rm', '--network', f'container:{target}',
                '--cap-drop', 'ALL', '--read-only', '--tmpfs', '/tmp']
        capture = ['live', '--interface', 'eth0', '--filter', 'udp port 9',
                   '--duration', '1s', '--output', '/tmp/silent.jsonl']
        denied = run(base + ['netwatch-sensor:dev'] + capture, check=False)
        assert denied.returncode != 0 and 'permi' in denied.stderr.lower(), denied.stderr
        invalid = run(base + ['--cap-add', 'NET_RAW', 'netwatch-sensor:dev', 'live',
                              '--interface', 'eth0', '--filter', '(', '--output', '/tmp/bad.jsonl'], check=False)
        assert invalid.returncode != 0 and 'syntax' in invalid.stderr.lower(), invalid.stderr
        before = time.monotonic()
        silent = run(base + ['--cap-add', 'NET_RAW', 'netwatch-sensor:dev'] + capture, timeout=10)
        assert time.monotonic() - before < 5
        quiet = [json.loads(s) for s in silent.stderr.splitlines() if s.startswith('{')]
        assert quiet[-1]['event'] == 'live_stopped' and quiet[-1]['records'] == 0
        print('Sending HTTP traffic in the isolated network...', flush=True)
        run(compose + ['run', '--rm', 'client'])
        truth = json.loads((output / 'ground_truth.json').read_text())
        assert truth['successful_requests'] > 0
        time.sleep(2)
        before = time.monotonic()
        run(compose + ['stop', '-t', '5', 'sensor'])
        assert time.monotonic() - before < 5
        assert inspect(sensor)['State']['ExitCode'] == 0
        events = logs(sensor)
        (output / 'sensor.log.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
        stopped = next(e for e in events if e.get('event') == 'live_stopped')
        assert stopped['records'] > 0 and stopped['late_packets'] == 0
        assert stopped['stats']['dropped'] == 0 and stopped['stats']['interface_dropped'] == 0
        assert 'error' not in stopped
        started = next(e for e in events if e.get('event') == 'live_started')
        run(['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
             '-v', f'{output}:/output', 'netwatch-sensor:dev', 'replay',
             '--input', '/output/live.pcap', '--output', '/output/offline.jsonl',
             '--service', env['NETWATCH_SERVICE'], '--epoch', started['epoch']])
        live = [json.loads(s) for s in (output / 'live.jsonl').read_text().splitlines()]
        offline = {w['window_start_ns']: w for w in
                   map(json.loads, (output / 'offline.jsonl').read_text().splitlines())}
        complete = [w for w in live if w['quality']['coverage'] == 'complete']
        assert len(complete) >= 2, live
        for w in complete:
            assert w['features'] == offline[w['window_start_ns']]['features'], w
            assert w['quality']['capture_dropped'] == 0
        report = dict(run_id=run_id, complete_windows=len(complete),
                      compared_features=len(complete[0]['features']), live_windows=len(live),
                      records=stopped['records'], stats=stopped['stats'],
                      checks=['interfaces', 'NET_RAW only', 'permission denial', 'invalid BPF',
                              'idle duration', 'SIGTERM', 'live/replay feature equality'])
        (output / 'live-report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        print(f'Artifacts: {output}')
    finally:
        run(compose + ['down', '--remove-orphans'])


if __name__ == '__main__':
    main()
