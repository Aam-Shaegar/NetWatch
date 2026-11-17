"""Record bounded HTTP workloads on loopback inside a network-isolated lab container."""
import hashlib
import http.client
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import random
import signal
import subprocess
import sys
import threading
import time


class Service(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        size = int(self.headers["Content-Length"])
        self.rfile.read(size)
        response = bytes(int(self.path[1:]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args):
        pass


def record(folder, seed):
    folder.mkdir()
    rng = random.Random(seed)
    phases = ["large_upload", "large_response", "connection_surge", "persistent_exchange", "foreground_pause"]
    rng.shuffle(phases)
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    capture = folder / "traffic.pcap"
    proc = subprocess.Popen(["tcpdump", "-Z", "root", "-U", "-n", "-i", "lo", "-s", "0", "-w", str(capture),
                             "tcp port 8080"], stderr=subprocess.PIPE, text=True)
    intervals = []
    try:
        while "listening on" not in proc.stderr.readline():
            if proc.poll() is not None:
                raise RuntimeError("capture failed to start")
        for phase in [s for fault in phases for s in ("benign", fault)] + ["benign"]:
            duration = rng.uniform(18, 22) if phase == "benign" else rng.uniform(24, 29)
            rate = rng.uniform(29, 35) if phase == "connection_surge" else rng.uniform(3, 7)
            size = rng.choice((65536, 98304, 131072))
            start = time.time_ns()
            end = time.monotonic() + duration
            next_background = 0
            conn = None
            requests = 0
            while time.monotonic() < end:
                background = time.monotonic() >= next_background
                if background:
                    next_background = time.monotonic() + 2
                if phase == "foreground_pause" and not background:
                    time.sleep(0.02)
                    continue
                if conn is None:
                    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=2,
                                                       source_address=("127.0.0.2", 0))
                body = bytes(size if phase == "large_upload" else 0)
                reply = size if phase == "large_response" else (32768 if background else 13)
                conn.request("POST", "/" + str(reply), body=body)
                result = conn.getresponse()
                if result.status != 200 or len(result.read()) != reply:
                    raise ValueError("incomplete HTTP exchange")
                if phase != "persistent_exchange":
                    conn.close()
                    conn = None
                requests += 1
                time.sleep(1 / rate)
            if conn:
                conn.close()
            intervals.append(dict(label=phase, start=start, end=time.time_ns(), rate=rate,
                                  size=size, requests=requests))
        time.sleep(1)
    finally:
        proc.send_signal(signal.SIGINT)
        _, log = proc.communicate(timeout=10)
        server.server_close()
    if proc.returncode or "0 packets dropped by kernel" not in log.splitlines():
        raise RuntimeError(log)
    with capture.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = dict(seed=seed, intervals=intervals, capture_log=log,
                    sha256=digest)
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    record(Path(sys.argv[1]), int(sys.argv[2]))
