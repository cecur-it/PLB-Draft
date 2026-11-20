#!/usr/bin/env python3
"""Tiny stand-in for the OpenSearch Dashboards saved-objects API (test fixture).

Implements just what dashboards/import.sh calls, and enforces what the real API
enforces: the osd-xsrf header and HTTP basic auth. Used by tests/run-tests.sh
when the ~1 GB Dashboards image is not pulled.
"""
import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

EXPECTED = "Basic " + base64.b64encode(os.environ["MOCK_USER_PASS"].encode()).decode()
STORE = {}
SETTINGS = {}


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorised(self):
        if self.headers.get("Authorization") != EXPECTED:
            self.reply(401, {"statusCode": 401, "error": "Unauthorized"})
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        if not self.authorised():
            return
        if url.path == "/api/status":
            self.reply(200, {"status": {"overall": {"state": "green"}}})
        elif url.path == "/api/saved_objects/_find":
            kind = parse_qs(url.query).get("type", [""])[0]
            found = [k for k in STORE if k[0] == kind]
            self.reply(200, {"total": len(found), "per_page": 200, "page": 1, "saved_objects": []})
        else:
            self.reply(404, {"statusCode": 404})

    def do_POST(self):
        url = urlparse(self.path)
        if not self.authorised():
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if self.headers.get("osd-xsrf") is None:
            self.reply(400, {"statusCode": 400, "message": "Request must contain a osd-xsrf header."})
            return
        if url.path == "/api/saved_objects/_import":
            if "overwrite=true" not in url.query or "multipart/form-data" not in (self.headers.get("Content-Type") or ""):
                self.reply(400, {"statusCode": 400, "message": "expected multipart upload with overwrite=true"})
                return
            count = 0
            for line in body.splitlines():
                try:
                    doc = json.loads(line)
                except ValueError:
                    continue
                if isinstance(doc, dict) and "type" in doc and "id" in doc:
                    STORE[(doc["type"], doc["id"])] = doc
                    count += 1
            self.reply(200, {"success": True, "successCount": count, "successResults": []})
        elif url.path == "/api/opensearch-dashboards/settings":
            SETTINGS.update(json.loads(body)["changes"])
            self.reply(200, {"settings": SETTINGS})
        else:
            self.reply(404, {"statusCode": 404})

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-dashboards: " + (fmt % args) + "\n")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 5601), Handler).serve_forever()
