#!/usr/bin/env python3
"""errow-mcp — MCP streamable-HTTP bridge that exposes Errow's offensive tooling to the LLM gateway.

Errow's own `errow/tools/mcp/*` is an MCP *client*; this is the compliant server-side shim. JSON-RPC 2.0
over HTTPS on :9103 with mutual TLS (`verify required`, server cert /pki/errow-mcp.crt|key, CA /pki/ca.crt):
`initialize`, `notifications/initialized`, `ping`, `tools/list` (inputSchema generated from the policy arg
specs) and `tools/call`. `GET /health` and `GET /metrics` (Prometheus text) need a CA-signed client cert too.

Every tools/call is re-validated by policy.py (independent of the gateway; role arrives in `_meta.role`),
rate limited, audited as an `mcp_exec` NDJSON event and — only when MCP_LIVE=true — executed in an ephemeral
hardened Errow sandbox container via DOCKER_HOST (executor.py). Otherwise the reply is a dry-run plan.
Stateless: no Mcp-Session-Id, responses are always application/json, GET/DELETE /mcp answer 405.

Traces: PROMPT §2.3, §1 Tier 4; CONTRACT §2 (port 9103, /pki), §4.5 (MCP policy), §8.4/§15 (mcp_events).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from events import EventLog
from executor import ExecConfig, ExecError, Executor
from policy import Policy, PolicyError, RateLimited
from sanitize import sanitize_text, sanitize_value

VERSION = "1.0.0"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
BUCKETS = (0.05, 0.25, 1.0, 5.0, 30.0, 120.0, 600.0, 900.0)
ID_RE = re.compile(r"[^A-Za-z0-9._:@-]")

DESCRIPTIONS = {
    "bbot": "Passive-only BBOT attack-surface enumeration (presets subdomain-enum|safe) of an allow-listed domain.",
    "nmap": "Allow-listed host/CIDR scan with a fixed set of scan types/ports/timing (no NSE scripts, no -sS/-sU/-O/-A).",
    "nuclei": "Nuclei template scan limited to cves/exposures/misconfiguration/technologies tags; no fuzz/dos/intrusive.",
    "gobuster": "Directory brute force (dir mode, fixed wordlists, <=10 threads) against an allow-listed URL.",
    "subfinder": "Passive subdomain discovery for an allow-listed domain.",
    "wafw00f": "Default-detection WAF fingerprint of an allow-listed URL (no aggressive/findall mode).",
    "trufflehog": "Secret scan of a repository under /workspace/repos (read-only mount, no verification traffic, Raw values stripped).",
    "shell": "Fixed diagnostics: curl -sI, dig, nslookup, ping -c 3 against an allow-listed host (argv array, no shell).",
    "agent_browser": "Headless-browser page read (open + accessibility snapshot, optional screenshot hash) of an allow-listed https URL.",
    "proxy": "Read-only query of the Caido proxy history/scope inside a running Errow sandbox (no replay/intercept/modify).",
    "web_search": "Web search through the configured Exa/Perplexity key (rate limited, no page fetching).",
    "threat_model": "Read-only summary of an Errow run's .state/threat_models.json.",
    "coverage": "Read-only summary of an Errow run's coverage.json.",
}
READ_ONLY = {"threat_model", "coverage", "proxy"}

SELFTEST_CALLS: dict[str, tuple[str, dict[str, Any]]] = {
    "bbot": ("triage", {"target": "scan-target.vendetta.lab", "preset": "safe"}),
    "nmap": ("triage", {"target": "scan-target.vendetta.lab", "scan_type": "-sT", "ports": "1-1024", "timing": "-T3"}),
    "nuclei": ("triage", {"target": "https://scan-target.vendetta.lab", "tags": ["cves", "exposures"], "rate_limit": 10}),
    "gobuster": ("triage", {"target": "http://scan-target.vendetta.lab", "mode": "dir",
                            "wordlist": "/usr/share/wordlists/dirb/common.txt", "threads": 5}),
    "subfinder": ("triage", {"target": "vendetta.lab", "passive": True}),
    "wafw00f": ("triage", {"target": "https://scan-target.vendetta.lab", "passive": True}),
    "trufflehog": ("triage", {"repo_path": "/workspace/repos/demo", "mode": "filesystem", "no_verification": True}),
    "shell": ("triage", {"command": "dig", "target": "scan-target.vendetta.lab"}),
    "agent_browser": ("forensic", {"url": "https://scan-target.vendetta.lab/", "screenshot": True}),
    "proxy": ("forensic", {"target": "scan-target.vendetta.lab", "action": "list_requests", "limit": 5}),
    "web_search": ("forensic", {"query": "CVE-2024-3094 xz backdoor", "max_results": 3}),
    "threat_model": ("forensic", {"run": "demo", "format": "summary"}),
    "coverage": ("forensic", {"run": "demo", "format": "summary"}),
}


def log(level: str, msg: str, **fields: Any) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "component": "errow-mcp", "msg": msg}
    rec.update(sanitize_value(fields))
    sys.stderr.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
    sys.stderr.flush()


@dataclass
class ServerConfig:
    bind: str = "0.0.0.0"
    port: int = 9103
    policy_file: str = "/app/policy.yaml"
    pki_dir: str = "/pki"
    allowed_clients: tuple[str, ...] = ("llm-gateway", "errow", "errow-mcp")
    max_body: int = 65536
    max_connections: int = 128
    read_timeout: float = 15.0
    targets_file: str | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ServerConfig:
        e = env if env is not None else os.environ

        def num(name: str, default: Any, cast: Callable[[str], Any]) -> Any:
            try:
                return cast(e.get(name, "") or default)
            except ValueError:
                return default

        allowed = tuple(x.strip() for x in e.get("MCP_ALLOWED_CLIENTS", "llm-gateway,errow,errow-mcp").split(",") if x.strip())
        return cls(
            bind=e.get("MCP_BIND", "0.0.0.0"),
            port=num("MCP_PORT", 9103, int),
            policy_file=e.get("MCP_POLICY_FILE", "/app/policy.yaml"),
            pki_dir=e.get("MCP_PKI_DIR", "/pki"),
            allowed_clients=allowed,
            max_body=num("MCP_MAX_BODY_BYTES", 65536, int),
            max_connections=num("MCP_MAX_CONNECTIONS", 128, int),
            read_timeout=num("MCP_READ_TIMEOUT_S", 15, float),
            targets_file=e.get("MCP_TARGETS_FILE") or None,
        )

    @property
    def cert(self) -> str:
        return os.path.join(self.pki_dir, "errow-mcp.crt")

    @property
    def key(self) -> str:
        return os.path.join(self.pki_dir, "errow-mcp.key")

    @property
    def ca(self) -> str:
        return os.path.join(self.pki_dir, "ca.crt")


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls: dict[tuple[str, str], int] = {}
        self.denied: dict[tuple[str, str], int] = {}
        self.hist: dict[str, list[float]] = {}
        self.tls_failures = 0
        self.rejected_clients = 0

    def observe(self, tool: str, status: str, seconds: float) -> None:
        with self._lock:
            self.calls[(tool, status)] = self.calls.get((tool, status), 0) + 1
            h = self.hist.setdefault(tool, [0.0] * (len(BUCKETS) + 2))
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    h[i] += 1
            h[len(BUCKETS)] += 1
            h[len(BUCKETS) + 1] += seconds

    def deny(self, tool: str, reason: str) -> None:
        with self._lock:
            self.denied[(tool, reason)] = self.denied.get((tool, reason), 0) + 1

    def bump(self, name: str) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + 1)

    def render(self, *, sandbox_running: int, live: bool, event_errors: int) -> str:
        def lab(**kv: str) -> str:
            return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in kv.items()) + "}"

        out = [
            "# HELP errow_mcp_calls_total tools/call results by tool and status.",
            "# TYPE errow_mcp_calls_total counter",
        ]
        with self._lock:
            for (tool, status), n in sorted(self.calls.items()):
                out.append(f"errow_mcp_calls_total{lab(tool=tool, status=status)} {n}")
            out += ["# HELP errow_mcp_call_duration_seconds tools/call wall time.",
                    "# TYPE errow_mcp_call_duration_seconds histogram"]
            for tool, h in sorted(self.hist.items()):
                for i, bound in enumerate(BUCKETS):
                    out.append(f"errow_mcp_call_duration_seconds_bucket{lab(tool=tool, le=repr(bound))} {int(h[i])}")
                out.append(f'errow_mcp_call_duration_seconds_bucket{lab(tool=tool, le="+Inf")} {int(h[len(BUCKETS)])}')
                out.append(f"errow_mcp_call_duration_seconds_sum{lab(tool=tool)} {h[len(BUCKETS) + 1]:.6f}")
                out.append(f"errow_mcp_call_duration_seconds_count{lab(tool=tool)} {int(h[len(BUCKETS)])}")
            out += ["# HELP errow_mcp_policy_denied_total Policy denials by tool and violation category.",
                    "# TYPE errow_mcp_policy_denied_total counter"]
            for (tool, reason), n in sorted(self.denied.items()):
                out.append(f"errow_mcp_policy_denied_total{lab(tool=tool, reason=reason)} {n}")
            tls, rejected = self.tls_failures, self.rejected_clients
        out += [
            "# HELP errow_mcp_sandbox_running Sandbox executions currently in flight.",
            "# TYPE errow_mcp_sandbox_running gauge",
            f"errow_mcp_sandbox_running {sandbox_running}",
            "# HELP errow_mcp_live 1 when MCP_LIVE=true.",
            "# TYPE errow_mcp_live gauge",
            f"errow_mcp_live {1 if live else 0}",
            "# HELP errow_mcp_event_write_errors_total Failed appends to mcp_events.ndjson.",
            "# TYPE errow_mcp_event_write_errors_total counter",
            f"errow_mcp_event_write_errors_total {event_errors}",
            "# HELP errow_mcp_tls_failures_total Failed TLS handshakes (missing/invalid client cert, bad protocol).",
            "# TYPE errow_mcp_tls_failures_total counter",
            f"errow_mcp_tls_failures_total {tls}",
            "# HELP errow_mcp_client_rejected_total Valid certificates whose CN/SAN is not in MCP_ALLOWED_CLIENTS.",
            "# TYPE errow_mcp_client_rejected_total counter",
            f"errow_mcp_client_rejected_total {rejected}",
            "# TYPE errow_mcp_build_info gauge",
            f'errow_mcp_build_info{{version="{VERSION}"}} 1',
        ]
        return "\n".join(out) + "\n"


def _esc(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def reason_label(violation: str) -> str:
    """Bounded-cardinality metric label for a violation string."""
    parts = violation.split(":")
    if parts[0] == "arg":
        return f"arg:{parts[-1]}" if len(parts) > 2 else "arg"
    if parts[0] in ("forbidden_arg", "forbidden_tag"):
        return parts[0]
    return ":".join(parts[:2])


def _rpc_error(rid: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": err}


def _ident(value: Any, limit: int = 128) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return ID_RE.sub("_", value)[:limit]


class Bridge:
    """Transport-independent MCP logic (the HTTP layer only parses and frames)."""

    def __init__(
        self,
        policy: Policy,
        executor: Executor,
        events: EventLog,
        *,
        env: dict[str, str] | None = None,
        metrics: Metrics | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.executor = executor
        self.events = events
        self.env = env if env is not None else dict(os.environ)
        self.metrics = metrics or Metrics()
        self._clock = clock

    @property
    def live(self) -> bool:
        return self.policy.live_enabled(self.env)

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": VERSION,
            "live": self.live,
            "tools": len(self.policy.tools),
            "sandbox_running": self.executor.running,
            "targets_error": self.policy.targets_error,
            "event_write_errors": self.events.write_errors,
        }

    def render_metrics(self) -> str:
        return self.metrics.render(
            sandbox_running=self.executor.running, live=self.live, event_errors=self.events.write_errors
        )

    # ------------------------------------------------------------------ JSON-RPC
    def handle(self, msg: Any) -> dict[str, Any] | None:
        """One JSON-RPC message in; response out (None for notifications/responses)."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return _rpc_error(None, -32600, "Invalid Request")
        has_id = "id" in msg
        rid = msg.get("id")
        if (has_id and not (rid is None or isinstance(rid, (str, int)))) or isinstance(rid, bool):
            return _rpc_error(None, -32600, "Invalid Request: id must be a string or number")
        method = msg.get("method")
        if method is None:
            return None if ("result" in msg or "error" in msg) else _rpc_error(rid, -32600, "Invalid Request")
        if not isinstance(method, str):
            return _rpc_error(rid, -32600, "Invalid Request: method must be a string")
        params = msg.get("params")
        if params is not None and not isinstance(params, dict):
            return _rpc_error(rid, -32602, "Invalid params: params must be an object")
        params = params or {}
        if not has_id:
            return None
        try:
            if method == "initialize":
                return {"jsonrpc": "2.0", "id": rid, "result": self._initialize(params)}
            if method == "ping":
                return {"jsonrpc": "2.0", "id": rid, "result": {}}
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": rid, "result": self._tools_list(params)}
            if method == "tools/call":
                return self._tools_call(rid, params)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the peer
            log("error", "internal_error", method=method, error=type(exc).__name__)
            return _rpc_error(rid, -32603, "Internal error")
        return _rpc_error(rid, -32601, f"Method not found: {sanitize_text(method, 64)}")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        wanted = params.get("protocolVersion")
        version = wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "errow-mcp", "title": "Errow offensive-tooling MCP bridge", "version": VERSION},
            "instructions": (
                "Policy-gated Errow tools. Send _meta.role (triage|forensic) with every tools/call. Calls are "
                "dry-run plans unless the server runs with MCP_LIVE=true. Denials list `violations`."
            ),
        }

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        role = (params.get("_meta") or {}).get("role") if isinstance(params.get("_meta"), dict) else None
        tools = []
        for name, spec in self.policy.tools.items():
            if role in ("triage", "forensic") and role not in spec["roles"]:
                continue
            tools.append({
                "name": name,
                "title": name,
                "description": DESCRIPTIONS.get(name, name),
                "inputSchema": self.policy.input_schema(name),
                "annotations": {"readOnlyHint": name in READ_ONLY, "destructiveHint": False, "openWorldHint": name not in ("threat_model", "coverage")},
                "_meta": {"roles": list(spec["roles"]), "timeout_s": spec["timeout_s"]},
            })
        return {"tools": tools}

    def _tools_call(self, rid: Any, params: dict[str, Any]) -> dict[str, Any]:
        started = self._clock()
        name = params.get("name")
        args = params.get("arguments")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if not isinstance(name, str) or not name:
            return _rpc_error(rid, -32602, "Invalid params: name is required")
        args = {} if args is None else args
        role = meta.get("role")
        tenant = _ident(meta.get("tenant_id")) or "default"
        request_id = _ident(meta.get("request_id"), 64) or uuid.uuid4().hex
        incident = _ident(meta.get("incident_id"))
        rationale = meta.get("rationale") if isinstance(meta.get("rationale"), str) else None
        known = name in self.policy.tools
        label = name if known else "unknown"

        decision = self.policy.evaluate(name, args, role)
        base: dict[str, Any] = {
            "request_id": request_id, "tenant_id": tenant, "incident_id": incident,
            "role": role if isinstance(role, str) else None, "tool": sanitize_text(name, 64),
            "args": args if isinstance(args, dict) else {}, "target": decision.target_key,
            "rationale": sanitize_text(rationale, 500) if rationale else None, "live": self.live,
        }

        def finish(status: str, event_decision: str, structured: dict[str, Any], text: str, *, is_error: bool,
                   violations: list[str] | None = None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
            elapsed = self._clock() - started
            structured.update({"status": status, "tool": base["tool"], "request_id": request_id, "live": self.live})
            self.events.emit({**base, "decision": event_decision, "violations": violations or [],
                              "duration_ms": int(elapsed * 1000), **(extra or {})})
            self.metrics.observe(label, status, elapsed)
            log("info", "tools_call", tool=label, status=status, decision=event_decision, request_id=request_id,
                tenant_id=tenant, role=base["role"], duration_ms=int(elapsed * 1000), violations=len(violations or []))
            result = {"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": is_error}
            return {"jsonrpc": "2.0", "id": rid, "result": result}

        if not decision.allowed:
            for v in decision.violations:
                self.metrics.deny(label, reason_label(v))
            if not known:
                self.events.emit({**base, "decision": "denied", "violations": decision.violations, "duration_ms": 0,
                                  "result_summary": "tool:unknown"})
                self.metrics.observe(label, "policy_violation", self._clock() - started)
                return _rpc_error(rid, -32602, f"Unknown tool: {sanitize_text(name, 64)}",
                                  {"status": "policy_violation", "violations": decision.violations, "request_id": request_id})
            text = "policy_violation: " + "; ".join(decision.violations)
            return finish("policy_violation", "denied", {"violations": decision.violations}, text, is_error=True,
                          violations=decision.violations, extra={"result_summary": text[:500]})

        try:
            admission = self.policy.admit(decision, tenant)
        except RateLimited as exc:
            self.metrics.deny(label, exc.reason)
            text = f"rate_limited: {exc.reason}; retry after {int(exc.retry_after)}s"
            return finish("rate_limited", "rate_limited",
                          {"violations": [exc.reason], "retry_after_s": int(exc.retry_after)}, text, is_error=True,
                          violations=[exc.reason], extra={"result_summary": text[:500]})

        with admission:
            try:
                plan = self.executor.plan(decision)
            except ExecError as exc:
                return finish("error", "error", {"error": exc.code, "message": exc.message}, f"error: {exc.code}",
                              is_error=True, extra={"result_summary": f"error {exc.code}: {exc.message}"[:500]})
            if not self.live:
                structured = {"plan": self.executor.dry_run(plan), "violations": []}
                summary = f"dry_run {name}: " + " ".join(plan.steps[0])[:300]
                return finish("dry_run", "dry_run", structured, json.dumps(structured, sort_keys=True), is_error=False,
                              extra={"result_summary": sanitize_text(summary, 500)})
            result = self.executor.run(plan, request_id=request_id)
        ok = result.status == "executed"
        structured = {
            "exit_code": result.exit_code, "output": result.output, "stderr": result.stderr,
            "truncated": result.truncated, "output_sha256": result.output_sha256, "output_bytes": result.output_bytes,
            "duration_s": result.duration_s, "violations": [],
        }
        if result.error:
            structured["error"] = result.error
            structured["message"] = result.message
        extra = {"result_summary": result.summary, "exit_code": result.exit_code, "output_sha256": result.output_sha256,
                 "output_bytes": result.output_bytes, "truncated": result.truncated,
                 "sandbox": {"container": result.container, "network": plan.network, "kind": plan.kind}}
        text = result.output if ok and result.output else (result.summary or result.status)
        return finish("executed" if ok else "error", "executed" if ok else "error", structured, text,
                      is_error=not ok or result.exit_code not in (0, None), extra=extra)


# ---------------------------------------------------------------------- HTTP / TLS
def peer_names(cert: dict[str, Any] | None) -> set[str]:
    names: set[str] = set()
    for rdn in (cert or {}).get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                names.add(value)
    for kind, value in (cert or {}).get("subjectAltName", ()):
        if kind == "DNS":
            names.add(value)
    return names


def build_ssl_context(cfg: ServerConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(cfg.cert, cfg.key)
    ctx.load_verify_locations(cafile=cfg.ca)
    return ctx


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "errow-mcp"
    sys_version = ""
    server: McpServer  # type: ignore[assignment]

    def setup(self) -> None:
        self.timeout = self.server.cfg.read_timeout
        self.request.settimeout(self.timeout)
        self.request.do_handshake()
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return

    def _send(self, status: int, body: bytes, ctype: str = "application/json", extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Any, extra: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8"), extra=extra)

    def _client_allowed(self) -> bool:
        allowed = self.server.cfg.allowed_clients
        if "*" in allowed:
            return True
        names = peer_names(self.request.getpeercert())
        if names & set(allowed):
            return True
        self.server.bridge.metrics.bump("rejected_clients")
        log("warning", "client_not_allowed", names=sorted(names)[:5])
        return False

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        bridge = self.server.bridge
        if path == "/health":
            self._json(200, bridge.health())
        elif path == "/metrics":
            self._send(200, bridge.render_metrics().encode(), "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/mcp":
            self._json(405, {"error": "method_not_allowed"}, {"Allow": "POST"})
        else:
            self._json(404, {"error": "not_found"})

    def do_DELETE(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] == "/mcp":
            self._json(405, {"error": "method_not_allowed"}, {"Allow": "POST"})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/mcp":
            self._json(404, {"error": "not_found"})
            return
        if not self._client_allowed():
            self.close_connection = True
            self._json(403, {"error": "client_not_allowed"})
            return
        if self.headers.get("Origin"):
            self.close_connection = True
            self._json(403, {"error": "origin_not_allowed"})
            return
        version = self.headers.get("MCP-Protocol-Version")
        if version is not None and version not in SUPPORTED_VERSIONS:
            self._json(400, {"error": "unsupported_protocol_version", "supported": list(SUPPORTED_VERSIONS)})
            return
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            self._json(415, {"error": "content_type_must_be_application_json"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.close_connection = True
            self._json(411, {"error": "content_length_required"})
            return
        if length < 0 or length > self.server.cfg.max_body:
            self.close_connection = True
            self._json(413, {"error": "payload_too_large", "max_bytes": self.server.cfg.max_body})
            return
        raw = self.rfile.read(length)
        try:
            msg = json.loads(raw)
        except ValueError:
            self._json(200, _rpc_error(None, -32700, "Parse error"))
            return
        if isinstance(msg, list):
            if not msg:
                self._json(200, _rpc_error(None, -32600, "Invalid Request: empty batch"))
                return
            replies = [r for r in (self.server.bridge.handle(m) for m in msg) if r is not None]
            if replies:
                self._json(200, replies)
            else:
                self._send(202, b"")
            return
        reply = self.server.bridge.handle(msg)
        if reply is None:
            self._send(202, b"")
        else:
            self._json(200, reply)


class McpServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def __init__(self, cfg: ServerConfig, bridge: Bridge, ctx: ssl.SSLContext) -> None:
        self.cfg = cfg
        self.bridge = bridge
        self.ctx = ctx
        self._slots = threading.BoundedSemaphore(cfg.max_connections)
        super().__init__((cfg.bind, cfg.port), Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind does a reverse-DNS lookup (getfqdn); skip it, the bridge never uses server_name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.cfg.bind, self.server_address[1]

    def get_request(self) -> tuple[socket.socket, Any]:
        sock, addr = self.socket.accept()
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            self.bridge.metrics.bump("tls_failures")
            log("warning", "connection_failed", error=type(exc).__name__, reason=getattr(exc, "reason", None) or str(exc)[:120])
        else:
            log("error", "handler_error", error=type(exc).__name__)


def watch_certs(cfg: ServerConfig, ctx: ssl.SSLContext, stop: threading.Event, interval: float = 60.0) -> None:
    """Reload the server chain/CA when the PKI files change (cert-manager / bootstrap rotation)."""
    def stamp() -> tuple[float, ...]:
        return tuple(Path(p).stat().st_mtime for p in (cfg.cert, cfg.key, cfg.ca))

    last = stamp()
    while not stop.wait(interval):
        try:
            now = stamp()
            if now != last:
                ctx.load_cert_chain(cfg.cert, cfg.key)
                ctx.load_verify_locations(cafile=cfg.ca)
                last = now
                log("info", "tls_reloaded")
        except (OSError, ssl.SSLError) as exc:
            log("warning", "tls_reload_failed", error=type(exc).__name__)


def build_bridge(cfg: ServerConfig, env: dict[str, str] | None = None) -> Bridge:
    policy = Policy.load(cfg.policy_file, targets_file=cfg.targets_file)
    events = EventLog(on_error=lambda exc: log("error", "event_write_failed", error=type(exc).__name__))
    return Bridge(policy, Executor(policy, ExecConfig.from_env(env)), events, env=env)


def run_selftest(cfg: ServerConfig) -> int:
    """Offline check: policy loads, every tool plans an argv ARRAY, nothing touches DNS, Docker or disk."""
    from policy import Policy as P

    policy = P.load(cfg.policy_file, resolver=lambda host: ["10.77.0.5"])
    execu = Executor(policy, ExecConfig(image="selftest", docker_host="tcp://selftest:2376", runs_dir="/nonexistent"))
    report: dict[str, Any] = {"policy": cfg.policy_file, "tools": {}}
    failed = False
    for tool in policy.tools:
        role, args = SELFTEST_CALLS[tool]
        decision = policy.evaluate(tool, args, role)
        if not decision.allowed:
            report["tools"][tool] = {"ok": False, "violations": decision.violations}
            failed = True
            continue
        plan = execu.plan(decision)
        ok = all(isinstance(s, list) and all(isinstance(x, str) for x in s) for s in plan.steps)
        failed |= not ok
        report["tools"][tool] = {"ok": ok, "kind": plan.kind, "argv0": plan.steps[0][0]}
    report["ok"] = not failed
    print(json.dumps(report, sort_keys=True))
    return 1 if failed else 0


def run_healthcheck(cfg: ServerConfig) -> int:
    try:
        ctx = ssl.create_default_context(cafile=cfg.ca)
        ctx.load_cert_chain(cfg.cert, cfg.key)
        with urllib.request.urlopen(f"https://localhost:{cfg.port}/health", context=ctx, timeout=4) as resp:
            body = json.loads(resp.read(65536))
        return 0 if resp.status == 200 and body.get("status") == "ok" else 1
    except Exception as exc:  # noqa: BLE001 - any failure means unhealthy
        sys.stderr.write(f"unhealthy: {type(exc).__name__}\n")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="errow-mcp", description=__doc__.split("\n\n")[0])
    parser.add_argument("--healthcheck", action="store_true", help="probe https://localhost:$MCP_PORT/health with the service cert")
    parser.add_argument("--selftest", action="store_true", help="offline policy+executor plan check for every tool, then exit")
    parser.add_argument("--version", action="version", version=f"errow-mcp {VERSION}")
    args = parser.parse_args(argv)
    cfg = ServerConfig.from_env()
    if args.healthcheck:
        return run_healthcheck(cfg)
    if args.selftest:
        return run_selftest(cfg)
    try:
        bridge = build_bridge(cfg)
        bridge.executor.cfg.validate()
        ctx = build_ssl_context(cfg)
    except (PolicyError, ExecError, OSError, ssl.SSLError) as exc:
        log("error", "startup_failed", error=type(exc).__name__, detail=str(exc)[:300])
        return 2
    server = McpServer(cfg, bridge, ctx)
    stop = threading.Event()
    threading.Thread(target=watch_certs, args=(cfg, ctx, stop), daemon=True).start()
    log("info", "listening", bind=cfg.bind, port=cfg.port, live=bridge.live, tools=len(bridge.policy.tools),
        policy=cfg.policy_file, image_configured=bool(bridge.executor.cfg.image))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
