#!/usr/bin/env python3
"""errow-feedback webhook: receives Errow findings and runs errow-to-vendetta.sh.

Traces: CONTRACT §2 (service errow-feedback :9102, HTTP webhook + bearer), §3/§5 (Fluentd `http-feedback-loop` posts
findings with severity >= high to POST /errow-finding), §6 (feedback loop, G9 offensive safety: dry-run unless
ERROW_FEEDBACK_LIVE=true and a signed approval exists), §11 (RUNTIME.md).

Endpoints
  POST /errow-finding   Authorization: Bearer <feedback_webhook_token>; body = NDJSON, a JSON array or one JSON document
                        (shipper findings / SARIF / normalized alerts). Optional ?dry_run=1 forces a dry-run.
  POST /approved-action Authorization: Bearer <feedback_webhook_token>; one JSON object
                        {fingerprint, agent_id, command?, run?} for the Fluentd execd leg. Same live + signed-approval
                        gates as errow-to-vendetta.sh (approval checks live in action_gate.py). Optional ?dry_run=1.
  GET  /health          unauthenticated liveness (no secrets)
  GET  /metrics         unauthenticated Prometheus text

Safety: the request body is passed to the script on stdin only; the command line is a fixed argv list (no shell,
no request data in argv or environment). Body size is capped; the bearer token is compared in constant time.
Stdlib only.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import action_gate

HERE = Path(__file__).resolve().parent
MAX_OUTPUT_LINES = 200


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


class Config:
    def __init__(self) -> None:
        self.bind = os.environ.get("FEEDBACK_BIND", "0.0.0.0")
        self.port = env_int("FEEDBACK_PORT", 9102)
        self.token_file = os.environ.get("FEEDBACK_WEBHOOK_TOKEN_FILE", "/run/secrets/feedback_webhook_token")
        self.max_body = env_int("FEEDBACK_MAX_BODY_BYTES", 1_048_576)
        self.script = os.environ.get("FEEDBACK_SCRIPT", str(HERE / "errow-to-vendetta.sh"))
        self.script_timeout = env_int("FEEDBACK_SCRIPT_TIMEOUT", 120)
        self.max_parallel = max(1, env_int("FEEDBACK_MAX_PARALLEL", 2))
        self.tls_cert = os.environ.get("FEEDBACK_TLS_CERT", "")
        self.tls_key = os.environ.get("FEEDBACK_TLS_KEY", "")
        self.tls_ca = os.environ.get("FEEDBACK_TLS_CA", "/pki/ca.crt")
        self.feedback_dir = os.environ.get("FEEDBACK_DIR", "/var/log/feedback-loop")

    @property
    def live(self) -> bool:
        return os.environ.get("ERROW_FEEDBACK_LIVE", "false") == "true"

    @property
    def tls(self) -> bool:
        return bool(self.tls_cert and self.tls_key)


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, str, str], int] = {}
        self.runs: dict[str, int] = {}
        self.gate: dict[str, int] = {}
        self.bytes_in = 0
        self.script_seconds = 0.0
        self.script_count = 0

    def request(self, method: str, path: str, code: int) -> None:
        with self._lock:
            key = (method, path, str(code))
            self.requests[key] = self.requests.get(key, 0) + 1

    def gate_decision(self, decision: str) -> None:
        with self._lock:
            self.gate[decision] = self.gate.get(decision, 0) + 1

    def run(self, result: str, seconds: float) -> None:
        with self._lock:
            self.runs[result] = self.runs.get(result, 0) + 1
            self.script_seconds += seconds
            self.script_count += 1

    def add_bytes(self, count: int) -> None:
        with self._lock:
            self.bytes_in += count

    def render(self, live: bool) -> str:
        with self._lock:
            lines = [
                "# HELP errow_feedback_requests_total HTTP requests by method, path and status code.",
                "# TYPE errow_feedback_requests_total counter",
            ]
            for (method, path, code), value in sorted(self.requests.items()):
                lines.append(f'errow_feedback_requests_total{{method="{method}",path="{path}",code="{code}"}} {value}')
            lines += [
                "# HELP errow_feedback_script_runs_total errow-to-vendetta.sh invocations by result.",
                "# TYPE errow_feedback_script_runs_total counter",
            ]
            for result, value in sorted(self.runs.items()):
                lines.append(f'errow_feedback_script_runs_total{{result="{result}"}} {value}')
            lines += [
                "# HELP errow_feedback_script_seconds_sum Total script wall time.",
                "# TYPE errow_feedback_script_seconds_sum counter",
                f"errow_feedback_script_seconds_sum {self.script_seconds:.6f}",
                "# HELP errow_feedback_script_seconds_count Script invocations measured.",
                "# TYPE errow_feedback_script_seconds_count counter",
                f"errow_feedback_script_seconds_count {self.script_count}",
                "# HELP errow_feedback_request_bytes_total Accepted request body bytes.",
                "# TYPE errow_feedback_request_bytes_total counter",
                f"errow_feedback_request_bytes_total {self.bytes_in}",
                "# HELP errow_feedback_live_enabled 1 when ERROW_FEEDBACK_LIVE=true (actions still need signed approvals).",
                "# TYPE errow_feedback_live_enabled gauge",
                f"errow_feedback_live_enabled {1 if live else 0}",
                "# HELP errow_feedback_gate_decisions_total /approved-action decisions by outcome.",
                "# TYPE errow_feedback_gate_decisions_total counter",
            ]
            for decision, value in sorted(self.gate.items()):
                lines.append(f'errow_feedback_gate_decisions_total{{decision="{decision}"}} {value}')
        return "\n".join(lines) + "\n"


def make_handler(config: Config, token: bytes, metrics: Metrics, slots: threading.BoundedSemaphore):
    log_lock = threading.Lock()

    def decision_log(line: str) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            with log_lock:
                with open(Path(config.feedback_dir) / "feedback.log", "a", encoding="utf-8") as handle:
                    handle.write(f"{stamp} {line}\n")
        except OSError:
            pass

    gate = action_gate.Gate(log=decision_log, metrics=metrics.gate_decision)

    class Handler(BaseHTTPRequestHandler):
        server_version = "errow-feedback"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            sys.stderr.write(f"{self.log_date_time_string()} {self.client_address[0]} {fmt % args}\n")

        def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            metrics.request(self.command, urlsplit(self.path).path, code)

        def _json(self, code: int, payload: dict) -> None:
            self._send(code, (json.dumps(payload, separators=(",", ":")) + "\n").encode())

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            scheme, _, supplied = header.partition(" ")
            return scheme.lower() == "bearer" and hmac.compare_digest(supplied.strip().encode(), token)

        def gate_request(self, body: bytes, dry_run: bool) -> None:
            try:
                payload = json.loads(body)
            except ValueError:
                self._json(400, {"status": "invalid", "decision": "invalid", "reason": "body is not JSON"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"status": "invalid", "decision": "invalid", "reason": "body must be a JSON object"})
                return
            try:
                code, reply = gate.handle(payload, dry_run)
            except Exception as exc:  # fail closed: an unexpected gate fault never reaches the manager
                code, reply = 500, {"status": "error", "decision": "error", "reason": f"gate fault: {exc}"}
            self._json(code, reply)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path == "/health":
                self._json(200, {"status": "ok", "live": config.live})
            elif path == "/metrics":
                self._send(200, metrics.render(config.live).encode(), "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            parts = urlsplit(self.path)
            # Early rejections leave the request body unread, so the connection must not be reused.
            self.close_connection = True
            if parts.path not in ("/errow-finding", "/approved-action"):
                self._json(404, {"error": "not found"})
                return
            if not self._authorized():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer realm="errow-feedback"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                metrics.request("POST", parts.path, 401)
                return
            length_header = self.headers.get("Content-Length")
            if length_header is None or not length_header.isdigit():
                self._json(411, {"error": "Content-Length required"})
                return
            length = int(length_header)
            if length > config.max_body:
                self.close_connection = True
                self._json(413, {"error": f"body exceeds {config.max_body} bytes"})
                return
            if length == 0:
                self._json(400, {"error": "empty body"})
                return
            body = self.rfile.read(length)
            self.close_connection = self.headers.get("Connection", "").lower() == "close"
            metrics.add_bytes(len(body))
            dry_run = parse_qs(parts.query).get("dry_run", ["0"])[0] in ("1", "true")
            if parts.path == "/approved-action":
                self.gate_request(body, dry_run)
                return
            argv = ["bash", config.script]
            if dry_run:
                argv.append("--dry-run")
            if not slots.acquire(timeout=5):
                self._json(429, {"error": "too many concurrent requests"})
                return
            started = time.monotonic()
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv, request data only on stdin
                    argv, input=body, capture_output=True, timeout=config.script_timeout, check=False
                )
            except subprocess.TimeoutExpired:
                metrics.run("timeout", time.monotonic() - started)
                self._json(504, {"error": "script timed out"})
                return
            except OSError as exc:
                metrics.run("error", time.monotonic() - started)
                self._json(500, {"error": f"cannot run script: {exc.strerror}"})
                return
            finally:
                slots.release()
            metrics.run("ok" if proc.returncode == 0 else "error", time.monotonic() - started)
            lines = proc.stdout.decode("utf-8", "replace").splitlines()[:MAX_OUTPUT_LINES]
            code = {0: 200, 3: 400}.get(proc.returncode, 500)
            self._json(
                code,
                {
                    "status": "ok" if proc.returncode == 0 else "error",
                    "exit_code": proc.returncode,
                    "live": config.live and "--dry-run" not in argv,
                    "lines": lines,
                },
            )

    return Handler


def read_token(path: str) -> bytes:
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"errow-feedback: bearer token file unreadable: {path}: {exc.strerror}") from exc
    if not token:
        raise SystemExit(f"errow-feedback: bearer token file is empty: {path}")
    return token.encode()


def healthcheck(config: Config) -> int:
    scheme = "https" if config.tls else "http"
    context = ssl.create_default_context(cafile=config.tls_ca) if config.tls else None
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
            f"{scheme}://localhost:{config.port}/health", timeout=3, context=context
        ) as response:
            return 0 if response.status == 200 else 1
    except (OSError, ValueError):
        return 1


def serve(config: Config) -> int:
    token = read_token(config.token_file)
    if not Path(config.script).is_file():
        raise SystemExit(f"errow-feedback: script not found: {config.script}")
    metrics = Metrics()
    slots = threading.BoundedSemaphore(config.max_parallel)
    httpd = ThreadingHTTPServer((config.bind, config.port), make_handler(config, token, metrics, slots))
    httpd.daemon_threads = True
    if config.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config.tls_cert, config.tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=httpd.shutdown, daemon=True).start())
    print(
        f"errow-feedback listening on {config.bind}:{config.port} tls={config.tls} live={config.live}",
        file=sys.stderr,
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Errow feedback webhook (POST /errow-finding, GET /health, GET /metrics)")
    parser.add_argument("--healthcheck", action="store_true", help="probe /health on localhost and exit 0/1")
    args = parser.parse_args(argv)
    config = Config()
    if args.healthcheck:
        return healthcheck(config)
    return serve(config)


if __name__ == "__main__":
    sys.exit(main())
