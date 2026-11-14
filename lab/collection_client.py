"""Record observed HTTP workload and a bounded foreground pause in the lab."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import random
import time
import urllib.request

from client import target_rate


def main():
    profile = os.environ['PROFILE']
    duration = int(os.environ['DURATION'])
    rate = int(os.environ['RATE'])
    seed = int(os.environ['SEED'])
    if profile not in {'stable', 'ramp', 'flash-crowd', 'pause'}:
        raise ValueError('unknown profile')
    if not 30 <= duration <= 1800 or not 1 <= rate <= 12:
        raise ValueError('duration or rate outside collection range')
    output = Path('/output')
    start = time.monotonic()
    start_ns = time.time_ns()
    end = start + duration
    events = []

    def lane(name, begin, stop, path, lane_seed):
        rng = random.Random(lane_seed)
        time.sleep(max(0, begin - time.monotonic()))
        with (output / f'{name}.jsonl').open('x') as log:
            while time.monotonic() < stop:
                now = time.monotonic()
                if name == 'main' and profile == 'pause' and now >= start + duration / 3 and not events:
                    pause_start = time.time_ns()
                    time.sleep(max(0, start + 2 * duration / 3 - now))
                    events.append(dict(kind='foreground_pause', start_ns=pause_start, end_ns=time.time_ns()))
                    continue
                before = time.time_ns()
                with urllib.request.urlopen('http://target:8080' + path, timeout=3) as response:
                    size = len(response.read())
                log.write(json.dumps(dict(start_ns=before, end_ns=time.time_ns(), path=path, bytes=size)) + '\n')
                rps = 0.5 if name == 'background' else target_rate(profile, rate, now - start, duration)
                time.sleep(max(0, min(stop - time.monotonic(), rng.uniform(0.9, 1.1) / rps - (time.monotonic() - now))))

    lanes = [('main', start, end, '/'), ('background', start, end, '/background')]
    if profile == 'flash-crowd':
        for visitor in ('visitor1', 'visitor2'):
            lanes.append((visitor, start + duration * .4, start + duration * .6, '/'))
    with ThreadPoolExecutor(max_workers=len(lanes)) as pool:
        futures = [pool.submit(lane, *args, seed + i) for i, args in enumerate(lanes)]
        for future in futures:
            future.result()
    truth = dict(start_ns=start_ns, end_ns=time.time_ns(), events=events, lanes=[lane[0] for lane in lanes])
    (output / 'truth.json').write_text(json.dumps(truth, indent=2) + '\n')


if __name__ == '__main__':
    main()
