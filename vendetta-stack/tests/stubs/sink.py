#!/usr/bin/env python3
"""Local sink stub used as Console / SIEM / ESOC-HTTP / Errow-cloud endpoint in smoke tests.

Traces: PROMPT §3 Phase 4 (smoke test), CS3 §4.3 (three egress legs).

Every POST/PUT is appended as one JSON line to ``$SINK_DATA_DIR/<sanitized-path>.ndjson``:
``{"t": epoch, "method": ..., "path": ..., "has_api_key": bool, "body": <str>}`` (gzip request bodies are decompressed first).
Secrets are never stored: only the *presence* of ``X-API-Key`` / ``Authorization`` is recorded.

  GET    /health            liveness
  GET    /_dump/<path>      all recorded lines for <path> (NDJSON), 404 when none
  GET    /_paths            JSON list of recorded paths
  DELETE /_reset            forget everything
"""
from __future__ import annotations

import gzip
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA_DIR = Path(os.environ.get("SINK_DATA_DIR", "/data"))
MAX_BODY = int(os.environ.get("SINK_MAX_BODY", str(8 * 1024 * 1024)))
LOCK = threading.Lock()


def _file_for(path: str) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"
    return DATA_DIR / f"{name}.ndjson"


class Handler(BaseHTTPRequestHandler):
    server_version = "vendetta-sink/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes = b"{}", ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(413, b'{"error":"too large"}')
            return
        raw = self.rfile.read(length) if length else b""
        if "gzip" in (self.headers.get("Content-Encoding") or "").lower():
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                self._send(400, b'{"error":"bad gzip body"}')
                return
        entry = {
            "t": time.time(),
            "method": self.command,
            "path": self.path.split("?", 1)[0],
            "has_api_key": bool(self.headers.get("X-API-Key") or self.headers.get("Authorization")),
            "content_type": self.headers.get("Content-Type", ""),
            "body": raw.decode("utf-8", "replace"),
        }
        with LOCK:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with _file_for(entry["path"]).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        self._send(200, b'{"status":"ok"}')

    do_POST = _record
    do_PUT = _record

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send(200, b'{"status":"ok"}')
        elif path == "/_paths":
            with LOCK:
                names = sorted(p.stem for p in DATA_DIR.glob("*.ndjson")) if DATA_DIR.exists() else []
            self._send(200, json.dumps(names).encode())
        elif path.startswith("/_dump/"):
            target = _file_for("/" + path[len("/_dump/"):])
            with LOCK:
                data = target.read_bytes() if target.exists() else None
            if data is None:
                self._send(404, b'{"error":"no records"}')
            else:
                self._send(200, data, "application/x-ndjson")
        else:
            self._send(404, b'{"error":"not found"}')

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/_reset":
            self._send(404, b'{"error":"not found"}')
            return
        with LOCK:
            if DATA_DIR.exists():
                for item in DATA_DIR.glob("*.ndjson"):
                    item.unlink()
        self._send(200, b'{"status":"reset"}')


def main() -> int:
    port = int(os.environ.get("SINK_PORT", "8080"))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    sys.stderr.write(f"sink listening on :{port}, data dir {DATA_DIR}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
