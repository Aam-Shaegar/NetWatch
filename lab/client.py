"""Bounded HTTP workloads inside the isolated target network."""
import json
import os
from pathlib import Path
import random
import time
import urllib.error
import urllib.request


def target_rate(profile, base, elapsed, duration):
    fraction = elapsed / duration
    if profile == 'ramp':
        return base * (0.25 + 0.75 * fraction)
    if profile == 'flash-crowd' and not 0.4 <= fraction < 0.6:
        return base * 0.2
    return base


def main():
    rate = float(os.environ['RATE'])
    duration = int(os.environ['DURATION'])
    seed = int(os.environ['SEED'])
    profile = os.environ['PROFILE']
    if not 1 <= rate <= 50 or not 1 <= duration <= 1800:
        raise ValueError('lab bounds: 1–50 rps, 1–1800 seconds')
    if profile not in {'stable', 'ramp', 'flash-crowd'}:
        raise ValueError('unknown workload')
    rng = random.Random(seed)
    start = time.time_ns()
    clock_start = time.monotonic()
    success = errors = 0
    with Path('/output/requests.jsonl').open('x') as events:
        while (elapsed := time.monotonic() - clock_start) < duration:
            before = time.monotonic()
            timestamp = time.time_ns()
            try:
                with urllib.request.urlopen('http://target:8080/', timeout=2) as response:
                    response.read()
                success += 1
                ok = True
            except (OSError, urllib.error.URLError):
                errors += 1
                ok = False
            events.write(json.dumps({'start_ns': str(timestamp), 'end_ns':str(time.time_ns()), 'ok':ok}) + '\n')
            interval = rng.uniform(.9, 1.1) / target_rate(profile, rate, elapsed, duration)
            time.sleep(max(0, interval - (time.monotonic() - before)))
    result = dict(kind='lab_benign_http', profile=profile, seed=seed, requested_rate=rate,
                  requested_duration=duration, actual_start_ns=str(start), actual_end_ns=str(time.time_ns()),
                  successful_requests=success, failed_requests=errors, not_training_ready=True)
    Path('/output/ground_truth.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
