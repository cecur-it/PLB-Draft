#!/usr/bin/env python3
"""Traces: PROMPT §4 Phase 4 (validation). Test-only HTTP sink for tests/test_legs.sh (stdlib only, runs in the Fluent Bit debug image).

Listens on the given name=port pairs and appends one JSON line per request to <outdir>/<name>.ndjson:
{"path", "method", "headers": {...}, "body": "<utf-8 text, gunzipped when Content-Encoding: gzip>"}.
Usage: sink.py <outdir> console=8080 siem=8081 esoc=4318
"""
import gzip
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()


def make_handler(outfile):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _record(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                raw = b""
                while True:
                    size = int(self.rfile.readline().strip() or b"0", 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    raw += self.rfile.read(size)
                    self.rfile.readline()
            if self.headers.get("Content-Encoding", "").lower() == "gzip":
                raw = gzip.decompress(raw)
            entry = {
                "path": self.path,
                "method": self.command,
                "headers": {k: v for k, v in self.headers.items()},
                "body": raw.decode("utf-8", "replace"),
            }
            with LOCK, open(outfile, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = _record
        do_PUT = _record

        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    servers = []
    for spec in sys.argv[2:]:
        name, port = spec.split("=", 1)
        outfile = os.path.join(outdir, name + ".ndjson")
        open(outfile, "a", encoding="utf-8").close()
        srv = ThreadingHTTPServer(("0.0.0.0", int(port)), make_handler(outfile))
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("sink ready", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
