#!/usr/bin/env python3
"""Configurable mock HTTP(S) endpoints for scripts/tests/test_scripts.sh (stdlib only, no network beyond loopback).

Usage: mock_stack.py --config spec.json --ports-file ports.json [--request-log requests.jsonl]

spec.json: {"listeners": [{"name": "gateway", "host": "127.0.0.1", "port": 0, "tls": {"cert": "...", "key": "...", "ca": "...", "require_client_cert": false},
                           "routes": {"GET /health": {"status": 200, "json": {...}},
                                      "POST /mcp": {"jsonrpc": {"tools/list": {"tools": [...]}}},
                                      "PUT /_snapshot/*": {"status": 200, "json": {"acknowledged": true}}},
                           "auth": {"basic": "admin:secret"} | {"bearer": "token"}}]}

Route keys are "METHOD /path" (exact), "METHOD /prefix/*" (prefix) or "* /path". A route may carry "auth" to override the
listener's auth, "sequence" (list of responses served in order; the last repeats) and "text" instead of "json".
Every request is appended to --request-log as JSON (method, path, auth_ok, jsonrpc method) — credentials are never logged.
The ports file maps listener name to the bound port once all listeners are up.
"""
import argparse
import base64
import http.server
import json
import signal
import time
import ssl
import sys
import threading


def route_for(routes, method, path):
    for key in (f"{method} {path}", f"* {path}"):
        if key in routes:
            return routes[key]
    best = None
    for key, val in routes.items():
        m, _, p = key.partition(" ")
        if p.endswith("*") and m in (method, "*") and path.startswith(p[:-1]):
            if best is None or len(p) > len(best[0]):
                best = (p, val)
    return best[1] if best else None


def auth_ok(spec, headers):
    if not spec:
        return True
    got = headers.get("Authorization", "")
    if "bearer" in spec:
        return got == f"Bearer {spec['bearer']}"
    if "basic" in spec:
        return got == "Basic " + base64.b64encode(spec["basic"].encode()).decode()
    return True


def make_handler(listener, log_lock, log_path):
    routes = listener.get("routes", {})
    counters = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            return

        def _reply(self, status, body, ctype):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            path = self.path.split("?")[0]
            route = route_for(routes, self.command, path)
            spec = (route or {}).get("auth", listener.get("auth"))
            ok = auth_ok(spec, self.headers)
            rpc = None
            if raw:
                try:
                    rpc = json.loads(raw).get("method")
                except (ValueError, AttributeError):
                    rpc = None
            if log_path:
                with log_lock, open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"listener": listener["name"], "method": self.command, "path": path,
                                         "auth_ok": ok, "has_auth": "Authorization" in self.headers, "rpc": rpc,
                                         "bytes": len(raw)}) + "\n")
            if route is None:
                self._reply(404, '{"error":"no route"}', "application/json")
                return
            if not ok:
                self._reply(401, '{"error":"unauthorized"}', "application/json")
                return
            if "sequence" in route:
                key = f"{self.command} {path}"
                idx = counters.get(key, 0)
                counters[key] = idx + 1
                route = route["sequence"][min(idx, len(route["sequence"]) - 1)]
            if "jsonrpc" in route:
                req = json.loads(raw or b"{}")
                result = route["jsonrpc"].get(req.get("method"))
                if result is None:
                    reply = {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "method not found"}}
                else:
                    reply = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
                self._reply(200, json.dumps(reply), "application/json")
                return
            status = route.get("status", 200)
            if "text" in route:
                self._reply(status, route["text"], "text/plain")
            else:
                self._reply(status, json.dumps(route.get("json", {})), "application/json")

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--ports-file", required=True)
    ap.add_argument("--request-log", default="")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as fh:
        spec = json.load(fh)
    lock = threading.Lock()
    servers, ports = [], {}
    for lst in spec["listeners"]:
        srv = http.server.ThreadingHTTPServer((lst.get("host", "127.0.0.1"), int(lst.get("port", 0))), make_handler(lst, lock, args.request_log))
        srv.daemon_threads = True
        tls = lst.get("tls")
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(tls["cert"], tls["key"])
            if tls.get("require_client_cert"):
                ctx.load_verify_locations(tls["ca"])
                ctx.verify_mode = ssl.CERT_REQUIRED
            # the handshake runs in the per-request thread, so a client that connects and never completes it
            # cannot block accept() (and with it the whole listener or the shutdown)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
        ports[lst["name"]] = srv.server_address[1]
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    with open(args.ports_file, "w", encoding="utf-8") as fh:
        json.dump(ports, fh)
    # Lock-free stop flag: a handler that touches an Event/Lock can deadlock, because the main thread may
    # already hold that mutex (inside Event.wait) when the signal is dispatched on it.
    stop = []

    def on_signal(*_):
        # repeated TERMs re-enter the handler through CPython's pending-call path; ignore them after the first
        if stop:
            return
        stop.append(1)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    while not stop:
        time.sleep(0.1)
    return 0  # the serve_forever threads are daemons: leaving without a graceful shutdown cannot hang on a half-open client


if __name__ == "__main__":
    sys.exit(main())
