"""Ordinary read-only requests to the isolated Compose service during the pilot."""

import json
import sys
import time
import urllib.request

duration = int(sys.argv[1])
start = time.monotonic()
success = errors = 0
next_background = start
while (elapsed := time.monotonic() - start) < duration:
    rate = (5, 15, 3)[int(elapsed // 60) % 3]
    before = time.monotonic()
    if before >= next_background:
        try:
            with urllib.request.urlopen(
                "http://target:8080/background", timeout=2
            ) as response:
                response.read()
            success += 1
        except OSError:
            errors += 1
        next_background = before + 2
    # One planned silence during commissioning; subsequent phases are normal.
    if 70 <= elapsed < 95:
        time.sleep(0.2)
        continue
    try:
        with urllib.request.urlopen("http://target:8080/", timeout=2) as response:
            response.read()
        success += 1
    except OSError:
        errors += 1
    time.sleep(max(0, 1 / rate - (time.monotonic() - before)))
print(
    json.dumps(
        dict(success=success, errors=errors, elapsed_s=time.monotonic() - start)
    ),
    flush=True,
)
