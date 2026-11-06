from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b"netwatch-lab\n"
        self.send_response(200); self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass
ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
