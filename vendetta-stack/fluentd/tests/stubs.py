#!/usr/bin/env python3
"""Traces: PROMPT §4 Phase 4 (validation); CONTRACT §5. Test-only stub services for fluentd/tests/test_routing.sh (stdlib only).

Usage: stubs.py <outdir> <pkidir> <name>=<port> ...      names: opensearch gateway manager feedback esoc siem cloud
Every request is appended to <outdir>/<name>.ndjson as {"path","query","method","headers","peer_cn","body","items"}.
  opensearch  TLS (pki/opensearch.*), Basic admin:$STUB_OS_PASSWORD; GET / -> version; POST .../_bulk parsed into "items"
              ({"action","meta","doc"}) and answered per item in "results"; a `create` whose _id was seen before answers 409 (as OpenSearch does)
  gateway     TLS (pki/llm-gateway.*) with a REQUIRED client certificate; POST /triage -> 202
  manager     TLS (pki/vendetta-manager.*); POST /security/user/authenticate?raw=true -> "stub-jwt-token" (Basic wazuh-wui:$STUB_MANAGER_PASSWORD);
              PUT /active-response?agents_list=N requires "Authorization: Bearer stub-jwt-token"
  feedback    plain HTTP, any POST -> 200
  esoc|siem|cloud  TLS (pki/<name>-sink.*); esoc requires a client certificate
"""
import base64
import gzip
import json
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOCK = threading.Lock()
SEEN_IDS = set()
JWT = "stub-jwt-token"


def peer_cn(conn):
    try:
        cert = conn.getpeercert()
    except (AttributeError, ValueError):
        return None
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def parse_bulk(text):
    lines = [ln for ln in text.split("\n") if ln.strip()]
    items, i = [], 0
    while i < len(lines):
        head = json.loads(lines[i])
        action, meta = next(iter(head.items()))
        doc = None
        if action != "delete":
            i += 1
            doc = json.loads(lines[i])
        items.append({"action": action, "meta": meta, "doc": doc})
        i += 1
    return items


def make_handler(name, outfile):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return

        def _send(self, code, body=b"{}", ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
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
            return raw.decode("utf-8", "replace")

        def _basic_ok(self, user, password):
            want = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
            return self.headers.get("Authorization") == want

        def _handle(self):
            parts = urlsplit(self.path)
            body = self._body()
            entry = {"path": parts.path, "query": parts.query, "method": self.command,
                     "headers": {k: v for k, v in self.headers.items()}, "peer_cn": peer_cn(self.connection), "body": body}
            status, reply = 200, b"{}"
            if name == "opensearch":
                if not self._basic_ok("admin", os.environ.get("STUB_OS_PASSWORD", "")):
                    status, reply = 401, b'{"error":"unauthorized"}'
                elif self.command == "GET" and parts.path == "/":
                    reply = json.dumps({"name": "stub", "version": {"number": "2.17.1", "distribution": "opensearch"}}).encode()
                elif parts.path.endswith("/_bulk"):
                    entry["items"] = parse_bulk(body)
                    results = []
                    with LOCK:
                        for it in entry["items"]:
                            action, meta = it["action"], it["meta"]
                            code, err = 200, None
                            if action == "create":
                                key = (meta.get("_index"), meta.get("_id"))
                                if key in SEEN_IDS:
                                    code, err = 409, {"type": "version_conflict_engine_exception", "reason": "document already exists"}
                                else:
                                    SEEN_IDS.add(key)
                                    code = 201
                            item = {"_index": meta.get("_index"), "_id": meta.get("_id"), "status": code}
                            if err:
                                item["error"] = err
                            results.append({action: item})
                    entry["results"] = results
                    reply = json.dumps({"took": 1, "errors": any(r[next(iter(r))]["status"] >= 400 for r in results), "items": results}).encode()
            elif name == "gateway":
                if self.command == "POST" and parts.path == "/triage":
                    status = 202
                else:
                    status = 404
            elif name == "manager":
                if parts.path == "/security/user/authenticate":
                    if self._basic_ok("wazuh-wui", os.environ.get("STUB_MANAGER_PASSWORD", "")):
                        self._record(entry)
                        return self._send(200, JWT.encode(), "text/plain")
                    status = 401
                elif parts.path == "/active-response" and self.headers.get("Authorization") != f"Bearer {JWT}":
                    status = 401
            self._record(entry)
            self._send(status, reply)

        def _record(self, entry):
            with LOCK, open(outfile, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")

        do_POST = do_PUT = do_GET = do_HEAD = _handle

    return Handler


def serve(name, port, outdir, pkidir):
    outfile = os.path.join(outdir, name + ".ndjson")
    open(outfile, "a", encoding="utf-8").close()
    srv = ThreadingHTTPServer(("0.0.0.0", port), make_handler(name, outfile))
    if name != "feedback":
        cert = {"opensearch": "opensearch", "gateway": "llm-gateway", "manager": "vendetta-manager"}.get(name, name + "-sink")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(pkidir, cert + ".crt"), os.path.join(pkidir, cert + ".key"))
        if name in ("gateway", "esoc"):
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(os.path.join(pkidir, "ca.crt"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    outdir, pkidir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    for spec in sys.argv[3:]:
        name, port = spec.split("=", 1)
        serve(name, int(port), outdir, pkidir)
    print("stubs ready", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
