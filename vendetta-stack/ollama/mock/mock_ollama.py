#!/usr/bin/env python3
"""mock_ollama.py — stdlib-only stand-in for an Ollama worker (CI, smoke tests, air-gapped dry runs).

Traces: PROMPT §1 Tier 4 (nemotron-3-nano:30b / gemma4:26b / gemma4:31b / qwensploit-v2:9b), CONTRACT §4.2 (AIIncidentAnalysis),
        §8.1 (mock listens 127.0.0.1:11434 behind the same mTLS worker proxy as the real worker).

Endpoints
  GET  /                      "Ollama is running"
  GET  /api/version           {"version": "0.40.5"}
  GET  /api/tags              the three approved models (always 200, even when a model is "down")
  GET  /v1/models             OpenAI-style model list
  GET  /metrics               Prometheus text: requests per model, down state, rejected requests
  POST /v1/chat/completions   OpenAI-compatible; the message content is a schema-valid AIIncidentAnalysis
  GET|POST /__control         loopback-only fault injection:
                                {"down_models": ["gemma4:26b"]}   those models answer HTTP 503
                                {"bad_output_models": ["..."]}    those models answer 200 with non-JSON content
                                {"latency_ms": 1500}              artificial delay before every completion
                                {"reset": true}                   clear the three settings and all counters
                                                                  (MOCK_DOWN_MODELS / MOCK_LATENCY_MS only set the initial state)
                              Non-loopback peers, or requests carrying Forwarded/X-Forwarded-* headers
                              (i.e. relayed by a proxy), get 403.

Deterministic analysis (first matching rule wins, case-insensitive, over the user messages):
  privilege -> HIGH   Privilege Escalation  | malware -> CRITICAL Execution   | brute -> HIGH Credential Access
  vulnerab|CVE -> HIGH Initial Access       | fim|syscheck -> MEDIUM Impact   | ssh -> MEDIUM Lateral Movement
  otherwise LOW Discovery.
  * engineUsed is the requested model.
  * A system prompt mentioning "forensic" adds proposedDetectionRule + proposedRemediation.
  * nemotron-3-nano:30b adds needsVerification=true and an nmap toolCall when the text contains
    "unknown host" or "scan"; the target is MOCK_TOOL_TARGET (default scan-target.vendetta.lab) unless the
    text carries an explicit `target=<host-or-ip>` token.

Environment: MOCK_BIND (127.0.0.1:11434), MOCK_DOWN_MODELS (CSV), MOCK_LATENCY_MS (0), MOCK_TOOL_TARGET.
Run:   python3 mock_ollama.py            Probe (container healthcheck):  python3 mock_ollama.py --healthcheck
Exit codes: 0 ok / healthy, 1 unhealthy, 2 usage or configuration error.
"""
import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.40.5"
DEFAULT_BIND = "127.0.0.1:11434"
MAX_BODY = 1 << 20
MODELS = {
    "nemotron-3-nano:30b": {"family": "nemotron", "size": "30B", "bytes": 24_000_000_000},
    "gemma4:26b": {"family": "gemma4", "size": "26B", "bytes": 17_000_000_000},
    "gemma4:31b": {"family": "gemma4", "size": "31B", "bytes": 20_000_000_000},
    "qwensploit-v2:9b": {"family": "qwen3.5", "size": "9B", "bytes": 6_000_000_000},
}
DEFAULT_TOOL_TARGET = "scan-target.vendetta.lab"
NMAP_PORTS = "1-1024,3389,8080,8443"

# (pattern, severity, tactic, technique, probable root cause, recommended action, confidence)
RULES = [
    (r"privilege", "HIGH", "Privilege Escalation", "T1068 Exploitation for Privilege Escalation",
     "A process obtained elevated rights outside an approved change.",
     "Isolate the host, review sudo/SUID changes and revoke the escalated session.", 85),
    (r"malware", "CRITICAL", "Execution", "T1204.002 User Execution: Malicious File",
     "A malicious payload was executed on the endpoint.",
     "Quarantine the endpoint, capture memory and block the file hash.", 92),
    (r"brute", "HIGH", "Credential Access", "T1110 Brute Force",
     "Repeated failed authentications indicate password guessing.",
     "Block the source address, enforce MFA and rotate exposed credentials.", 88),
    (r"vulnerab|\bcve\b|cve-\d", "HIGH", "Initial Access", "T1190 Exploit Public-Facing Application",
     "A known vulnerability is exposed on a reachable service.",
     "Patch or mitigate the affected service and verify with a rescan.", 80),
    (r"\bfim\b|syscheck", "MEDIUM", "Impact", "T1565.001 Data Manipulation: Stored Data Manipulation",
     "A monitored file changed outside the maintenance window.",
     "Compare the file against the baseline and restore it if the change is unauthorised.", 72),
    (r"ssh", "MEDIUM", "Lateral Movement", "T1021.004 Remote Services: SSH",
     "SSH activity deviates from the normal access pattern.",
     "Verify the account owner and restrict SSH sources.", 70),
]
DEFAULT_RULE = ("", "LOW", "Discovery", "T1082 System Information Discovery",
                "Routine system activity without malicious indicators.",
                "No immediate action; keep monitoring.", 60)
NEEDS_TOOL = re.compile(r"unknown host|scan")


def is_loopback(addr):
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def digest_of(name):
    return hashlib.sha256(f"mock:{name}".encode()).hexdigest()


def message_text(message):
    content = message.get("content", "")
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content if isinstance(content, str) else ""


def classify(user_text):
    lowered = user_text.lower()
    for rule in RULES:
        if re.search(rule[0], lowered):
            return rule
    return DEFAULT_RULE


def build_analysis(model, system_text, user_text, tool_target):
    _, severity, tactic, technique, cause, action, confidence = classify(user_text)
    category = technique.split(" ", 1)[1]
    analysis = {
        "triageSummary": f"Mock analysis by {model}: {category} indicators ({severity.lower()}).",
        "severityAssessment": severity,
        "mitreTactic": tactic,
        "mitreTechnique": technique,
        "probableRootCause": cause,
        "recommendedImmediateAction": action,
        "confidenceScore": confidence,
        "engineUsed": model,
    }
    if "forensic" in system_text.lower():
        level = {"CRITICAL": 13, "HIGH": 10, "MEDIUM": 7, "LOW": 3}[severity]
        analysis["proposedDetectionRule"] = (
            f'<rule id="100900" level="{level}"><description>Mock forensic rule: {category}</description></rule>'
        )
        analysis["proposedRemediation"] = f"{action} Document the finding and add the rule above to local_rules.xml."
    if model == "nemotron-3-nano:30b" and NEEDS_TOOL.search(user_text.lower()):
        explicit = re.search(r"target=([A-Za-z0-9._:-]+)", user_text)
        analysis["needsVerification"] = True
        analysis["toolCalls"] = [{
            "tool": "nmap",
            "args": {"target": explicit.group(1) if explicit else tool_target, "scan_type": "version", "ports": NMAP_PORTS},
            "rationale": "Verify the exposed services of the host before escalating the severity.",
        }]
    return analysis


class MockState:
    def __init__(self, down_models=(), latency_ms=0, tool_target=DEFAULT_TOOL_TARGET):
        self.lock = threading.Lock()
        self.tool_target = tool_target
        self.reset()
        self.down = set(down_models)
        self.latency_ms = latency_ms

    def reset(self):
        with self.lock:
            self.down = set()
            self.bad_output = set()
            self.latency_ms = 0
            self.requests = {m: 0 for m in MODELS}
            self.rejected = {m: 0 for m in MODELS}

    def snapshot(self):
        with self.lock:
            return {"down_models": sorted(self.down), "bad_output_models": sorted(self.bad_output),
                    "latency_ms": self.latency_ms, "requests": dict(self.requests)}

    def metrics(self):
        with self.lock:
            lines = [
                "# HELP mock_ollama_info Mock Ollama build information.",
                "# TYPE mock_ollama_info gauge",
                f'mock_ollama_info{{version="{VERSION}"}} 1',
                "# HELP mock_ollama_requests_total Chat completion requests received per model.",
                "# TYPE mock_ollama_requests_total counter",
            ]
            lines += [f'mock_ollama_requests_total{{model="{m}"}} {n}' for m, n in self.requests.items()]
            lines += ["# HELP mock_ollama_rejected_total Requests answered 503 because the model is down.",
                      "# TYPE mock_ollama_rejected_total counter"]
            lines += [f'mock_ollama_rejected_total{{model="{m}"}} {n}' for m, n in self.rejected.items()]
            lines += ["# HELP mock_ollama_model_down 1 when the model is injected as down.",
                      "# TYPE mock_ollama_model_down gauge"]
            lines += [f'mock_ollama_model_down{{model="{m}"}} {1 if m in self.down else 0}' for m in MODELS]
            return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-ollama"
    sys_version = ""

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write("mock-ollama %s %s\n" % (self.address_string(), fmt % args))
        except OSError:
            pass  # a closed log pipe must never fail a request or the healthcheck

    @property
    def state(self):
        return self.server.state

    def send_json(self, code, payload, headers=None):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, code, text, ctype="text/plain; charset=utf-8"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def error(self, code, message, kind="invalid_request_error", err_code=None):
        self.send_json(code, {"error": {"message": message, "type": kind, "code": err_code}})

    def load_body(self):
        """Consume the request body up front so an early error reply never leaves bytes on a keep-alive socket."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            self.error(413, "request body missing or too large")
            return False
        self.body = self.rfile.read(length)
        return True

    def read_json(self):
        try:
            data = json.loads(self.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            self.error(400, "request body is not valid JSON")
            return None
        if not isinstance(data, dict):
            self.error(400, "request body must be a JSON object")
            return None
        return data

    def control_allowed(self):
        relayed = any(h.lower().startswith("x-forwarded-") or h.lower() == "forwarded" for h in self.headers.keys())
        if relayed or not is_loopback(self.client_address[0]):
            self.error(403, "/__control is reachable from loopback only", "permission_error", "forbidden")
            return False
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self.send_text(200, "Ollama is running")
        elif path == "/api/version":
            self.send_json(200, {"version": VERSION})
        elif path == "/api/tags":
            self.send_json(200, {"models": [{
                "name": name, "model": name, "modified_at": "2026-11-13T00:00:00Z", "size": meta["bytes"],
                "digest": digest_of(name),
                "details": {"parent_model": "", "format": "gguf", "family": meta["family"],
                            "families": [meta["family"]], "parameter_size": meta["size"], "quantization_level": "Q4_K_M"},
            } for name, meta in MODELS.items()]})
        elif path == "/v1/models":
            self.send_json(200, {"object": "list", "data": [
                {"id": name, "object": "model", "created": 1794700800, "owned_by": "mock-ollama"} for name in MODELS]})
        elif path == "/metrics":
            self.send_text(200, self.state.metrics(), "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/__control":
            if self.control_allowed():
                self.send_json(200, self.state.snapshot())
        else:
            self.error(404, f"unknown path {path}", err_code="not_found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not self.load_body():
            return
        if path == "/v1/chat/completions":
            self.chat_completions()
        elif path == "/__control":
            self.control()
        else:
            self.error(404, f"unknown path {path}", err_code="not_found")

    def control(self):
        if not self.control_allowed():
            return
        data = self.read_json()
        if data is None:
            return
        state = self.state
        if data.get("reset") is True:
            state.reset()
            self.send_json(200, state.snapshot())
            return
        for key in ("down_models", "bad_output_models"):
            if key in data:
                names = data[key]
                if not isinstance(names, list) or any(n not in MODELS for n in names):
                    self.error(400, f"{key} must be a list of approved model tags: {sorted(MODELS)}")
                    return
        latency = data.get("latency_ms")
        if "latency_ms" in data and (not isinstance(latency, int) or isinstance(latency, bool) or not 0 <= latency <= 600000):
            self.error(400, "latency_ms must be an integer between 0 and 600000")
            return
        if not any(k in data for k in ("down_models", "bad_output_models", "latency_ms")):
            self.error(400, 'expected {"down_models":[...]}, {"bad_output_models":[...]}, {"latency_ms":n} or {"reset":true}')
            return
        with state.lock:
            if "down_models" in data:
                state.down = set(data["down_models"])
            if "bad_output_models" in data:
                state.bad_output = set(data["bad_output_models"])
            if "latency_ms" in data:
                state.latency_ms = latency
        self.send_json(200, state.snapshot())

    def chat_completions(self):
        data = self.read_json()
        if data is None:
            return
        model = data.get("model")
        messages = data.get("messages")
        if model not in MODELS:
            self.error(404, f"model '{model}' not found", err_code="model_not_found")
            return
        if not isinstance(messages, list) or not messages or not all(isinstance(m, dict) for m in messages):
            self.error(400, "messages must be a non-empty array of message objects")
            return
        if data.get("stream"):
            self.error(400, "stream=true is not supported by the mock")
            return
        state = self.state
        with state.lock:
            state.requests[model] += 1
            down = model in state.down
            bad_output = model in state.bad_output
            latency_ms = state.latency_ms
            if down:
                state.rejected[model] += 1
        if down:
            self.error(503, f"model '{model}' is unavailable (mock down)", "server_error", "model_unavailable")
            return
        if latency_ms:
            time.sleep(latency_ms / 1000)
        system_text = "\n".join(message_text(m) for m in messages if m.get("role") == "system")
        user_text = "\n".join(message_text(m) for m in messages if m.get("role") == "user")
        if bad_output:
            content = "Mock malformed output: this is not JSON."
        else:
            content = json.dumps(build_analysis(model, system_text, user_text, state.tool_target), separators=(",", ":"))
        prompt_tokens = math.ceil(sum(len(message_text(m)) for m in messages) / 4)
        completion_tokens = math.ceil(len(content) / 4)
        self.send_json(200, {
            "id": "chatcmpl-mock-" + hashlib.sha256((model + user_text).encode()).hexdigest()[:16],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                      "total_tokens": prompt_tokens + completion_tokens},
        })


class MockServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind, state):
        host, port = parse_bind(bind)
        if ":" in host:
            self.address_family = socket.AF_INET6
        self.state = state
        super().__init__((host, port), Handler)


def parse_bind(bind):
    host, sep, port = bind.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise ValueError(f"MOCK_BIND must be host:port (got '{bind}')")
    return host.strip("[]") or "127.0.0.1", int(port)


def parse_models(csv):
    names = [n.strip() for n in csv.split(",") if n.strip()]
    unknown = [n for n in names if n not in MODELS]
    if unknown:
        raise ValueError(f"unknown model(s) {unknown}; approved: {sorted(MODELS)}")
    return names


def healthcheck(bind):
    host, port = parse_bind(bind)
    host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = f"http://{'[' + host + ']' if ':' in host else host}:{port}/api/version"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.status == 200 and json.load(response).get("version") == VERSION
    except (OSError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stdlib-only mock of an Ollama worker (see module docstring).")
    parser.add_argument("--bind", default=os.environ.get("MOCK_BIND", DEFAULT_BIND), help="host:port (env MOCK_BIND)")
    parser.add_argument("--healthcheck", action="store_true", help="probe /api/version on --bind and exit 0/1")
    args = parser.parse_args(argv)
    try:
        if args.healthcheck:
            return 0 if healthcheck(args.bind) else 1
        latency = int(os.environ.get("MOCK_LATENCY_MS", "0"))
        state = MockState(parse_models(os.environ.get("MOCK_DOWN_MODELS", "")), latency,
                          os.environ.get("MOCK_TOOL_TARGET", DEFAULT_TOOL_TARGET))
        server = MockServer(args.bind, state)
    except (ValueError, OSError) as exc:
        print(f"mock-ollama: {exc}", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    print(f"mock-ollama {VERSION} listening on {args.bind} (down: {sorted(state.down) or 'none'})", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
