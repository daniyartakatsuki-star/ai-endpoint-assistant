"""Week 8: stand-in "C2 server" for the LummaC2-style emulation.

Binds to 127.0.0.1 ONLY, so nothing leaves the lab machine.

  GET  /s2      -> serves stage2.ps1 (the harmless "second stage")
  POST /upload  -> saves the uploaded decoy archive to ./received/

Port 8080 is used because Splunk occupies 8000 (same as Week 6).

Run (from this folder, in its own window):
    python c2_listener.py
"""

import datetime
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST, PORT = "127.0.0.1", 8080
HERE = os.path.dirname(os.path.abspath(__file__))
STAGE2 = os.path.join(HERE, "stage2.ps1")
RECEIVED = os.path.join(HERE, "received")


class Handler(BaseHTTPRequestHandler):
    def _stamp(self, msg):
        print(f"[{datetime.datetime.now():%H:%M:%S}] {self.client_address[0]} {msg}", flush=True)

    def do_GET(self):
        if self.path != "/s2":
            self.send_error(404)
            return
        with open(STAGE2, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._stamp("GET /s2 -> stage2.ps1 served (optional stage-2 fetch: T1105 ingress)")

    def do_POST(self):
        if self.path != "/upload":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        os.makedirs(RECEIVED, exist_ok=True)
        name = os.path.join(RECEIVED, f"loot-{datetime.datetime.now():%H%M%S}.zip")
        with open(name, "wb") as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
        self._stamp(f"POST /upload -> {len(data)} bytes saved to {name} (A5 exfiltration: T1041)")

    def log_message(self, *args):  # silence the default access log; _stamp prints instead
        pass


if __name__ == "__main__":
    print(f"Lab C2 listener on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    HTTPServer((HOST, PORT), Handler).serve_forever()
