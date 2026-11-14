from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock

counts = Counter()
lock = Lock()
background = b'x' * 32768


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics' and self.client_address[0] == '127.0.0.1':
            with lock:
                body = json.dumps(dict(counts)).encode()
        elif self.path in {'/', '/background'}:
            body = background if self.path == '/background' else b'netwatch-lab\n'
            if self.client_address[0] != '127.0.0.1':
                with lock:
                    counts[self.path] += 1
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
