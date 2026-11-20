# Traces: PROMPT §2.3 (Errow as MCP server), §2.5 (stage-2 guardrail: policy-gated tool calls, dry-run by default),
#         CONTRACT §4.3 (cs3.ai.tool_call), §4.4 (POST /mcp/tool_call: 200 dry_run|executed, 403 policy_violation, 429 rate_limited), §4.5.
"""POST /mcp/tool_call: validate the envelope, evaluate the policy, rate-limit, then dry-run (default) or execute through errow-mcp.

Nothing is executed unless MCP_LIVE == "true"; live execution is an mTLS JSON-RPC 2.0 `tools/call` to ERROW_MCP_URL with the validated
arguments. Every outcome (allowed/denied/rate_limited/dry_run/executed/error) becomes a hash-chained cs3.ai.tool_call audit event.
For live calls the `allowed` event is made durable BEFORE the tool runs. Tool output is sanitised, redacted and truncated before it leaves.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import ssl
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

import aiohttp

from audit import TAG_TOOL_CALL, AuditEmitter, utc_now_iso
from config import Config
from guardrails import redact_credentials, sanitize_untrusted
from jsonlog import log_event
from meter import Metrics
from policy import Decision, Policy, RateLimiter, Resolver, ToolSpec, rate_requirements, system_resolver
from tlsutil import client_ssl_context

LOG = logging.getLogger("llm-gateway.mcp")

_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INCIDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ROLE_NAME = re.compile(r"^[a-z]{1,16}$")
RATIONALE_MAX = 500
ARG_STRING_MAX = 500
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MCP_PROTOCOL_VERSION = "2025-03-26"
SESSION_ERROR = -32002


@dataclass
class McpResult:
    status: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class _Context:
    request_id: str
    tenant_id: str
    incident_id: str
    role: str
    tool: str
    args: dict[str, Any]
    rationale: str


class McpTransportError(Exception):
    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def sanitize_args(value: Any, depth: int = 0) -> Any:
    """Audit-safe copy of tool arguments: secrets redacted, strings capped, structure bounded."""
    if isinstance(value, str):
        return sanitize_untrusted(redact_credentials(value), ARG_STRING_MAX).text
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else None
    if depth >= 4:
        return "[truncated]"
    if isinstance(value, list):
        return [sanitize_args(v, depth + 1) for v in value[:20]]
    if isinstance(value, dict):
        return {sanitize_untrusted(str(k), 64).text: sanitize_args(v, depth + 1) for k, v in list(value.items())[:20]}
    return sanitize_untrusted(str(value), ARG_STRING_MAX).text


def _clean_text(value: Any, limit: int) -> str:
    return sanitize_untrusted(redact_credentials(value), limit).text if isinstance(value, str) else ""


class McpService:
    def __init__(
        self,
        cfg: Config,
        policy: Policy,
        audit: AuditEmitter,
        metrics: Metrics,
        *,
        resolver: Resolver | None = None,
        clock: Callable[[], float] = time.monotonic,
        client_ssl: ssl.SSLContext | None = None,
    ) -> None:
        self._cfg = cfg
        self._policy = policy
        self._audit = audit
        self._metrics = metrics
        self._resolver = resolver or (lambda host: system_resolver(host, cfg.mcp_dns_timeout_s))
        self._limiter = RateLimiter(clock)
        self._client_ssl = client_ssl
        self._session: aiohttp.ClientSession | None = None
        self._init_lock = asyncio.Lock()
        self._mcp_session_id: str | None = None
        self._initialised = False
        self._inflight = 0

    @property
    def live(self) -> bool:
        return self._cfg.env.get(self._policy.live_env) == "true"

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def handle(self, body: Any, *, fallback_request_id: str) -> McpResult:
        if not isinstance(body, dict):
            return McpResult(400, {"status": "bad_request", "error": "body must be a JSON object"})
        ctx, problems = self._envelope(body, fallback_request_id)
        if problems:
            return await self._deny(ctx, problems, tool_spec=None)

        decision = await self._policy.evaluate(ctx.role, ctx.tool, body.get("args"), self._resolver)
        if not decision.allowed:
            return await self._deny(ctx, decision.violations, tool_spec=decision.tool)
        assert decision.tool is not None
        spec = decision.tool

        reqs = rate_requirements(self._policy, spec, ctx.tenant_id, decision.target)
        limited = self._limiter.acquire(reqs)
        if limited is not None:
            retry = self._limiter.retry_after_s(reqs)
            await self._emit(ctx, spec, decision, "rate_limited", [f"rate_limit:{limited}"], "")
            return McpResult(429, {"status": "rate_limited", "limited_by": limited, "retry_after_s": retry, "request_id": ctx.request_id}, {"Retry-After": str(retry)})

        if not self.live:
            await self._emit(ctx, spec, decision, "dry_run", [], "dry_run: not executed")
            return McpResult(200, {
                "status": "dry_run", "request_id": ctx.request_id, "tool": spec.name, "sandbox": spec.sandbox, "timeout_s": spec.timeout_s,
                "target": decision.target.raw if decision.target else None, "args": sanitize_args(decision.args), "live": False,
                "message": f"{self._policy.live_env} is not 'true'; the call passed policy and was not executed",
            })
        return await self._execute(ctx, spec, decision)

    def _envelope(self, body: Mapping[str, Any], fallback_request_id: str) -> tuple[_Context, list[str]]:
        problems: list[str] = []
        tenant = body.get("tenant_id")
        if not isinstance(tenant, str) or not _TENANT.match(tenant):
            problems.append("envelope:tenant_id_invalid")
            tenant = "invalid"
        incident = body.get("incident_id", "unspecified")
        if not isinstance(incident, str) or not _INCIDENT.match(incident):
            problems.append("envelope:incident_id_invalid")
            incident = "invalid"
        request_id = body.get("request_id")
        if request_id is None:
            request_id = fallback_request_id
        elif not isinstance(request_id, str) or not _REQUEST_ID.match(request_id):
            problems.append("envelope:request_id_invalid")
            request_id = fallback_request_id
        role, tool = body.get("role"), body.get("tool")
        if not isinstance(role, str) or not _ROLE_NAME.match(role):
            problems.append("envelope:role_invalid")
            role = "invalid"
        if not isinstance(tool, str) or not _TOOL_NAME.match(tool):
            problems.append("envelope:tool_invalid")
            tool = "invalid"
        args = body.get("args")
        if not isinstance(args, dict):
            problems.append("envelope:args_not_an_object")
        rationale = body.get("rationale")
        if rationale is not None and not isinstance(rationale, str):
            problems.append("envelope:rationale_not_a_string")
        unknown = sorted(str(k)[:32] for k in body if k not in ("tenant_id", "incident_id", "role", "tool", "args", "rationale", "request_id"))
        if unknown:
            problems.append(f"envelope:unknown_fields:{','.join(unknown[:5])}")
        ctx = _Context(request_id, tenant, incident, role, tool, sanitize_args(args) if isinstance(args, dict) else {}, _clean_text(rationale, RATIONALE_MAX))
        return ctx, problems

    async def _deny(self, ctx: _Context, violations: list[str], tool_spec: ToolSpec | None) -> McpResult:
        await self._emit(ctx, tool_spec, None, "denied", violations, "")
        return McpResult(403, {"status": "policy_violation", "violations": violations, "request_id": ctx.request_id})

    async def _emit(self, ctx: _Context, spec: ToolSpec | None, decision: Decision | None, outcome: str, violations: list[str], summary: str) -> None:
        target = decision.target.raw if decision and decision.target else None
        event = {
            "@timestamp": utc_now_iso(),
            "event_type": "tool_call",
            "request_id": ctx.request_id,
            "tenant_id": ctx.tenant_id,
            "incident_id": ctx.incident_id,
            "role": ctx.role,
            "tool": ctx.tool,
            "args": ctx.args,
            "target": sanitize_untrusted(redact_credentials(target), ARG_STRING_MAX).text if target else None,
            "decision": outcome,
            "violations": violations[:25],
            "rationale": ctx.rationale,
            "gpu_seconds": 0.0,
            "live": self.live,
            "result_summary": summary,
        }
        await self._audit.emit(TAG_TOOL_CALL, event)
        self._metrics.mcp_tool_calls_total.labels(tool=spec.name if spec else "unknown", decision=outcome).inc()
        log_event(LOG, logging.INFO, "mcp decision", request_id=ctx.request_id, tool=event["tool"], decision=outcome, violations=len(violations), tenant_id=ctx.tenant_id)

    async def _execute(self, ctx: _Context, spec: ToolSpec, decision: Decision) -> McpResult:
        if self._inflight >= self._policy.limits.max_concurrent:
            await self._emit(ctx, spec, decision, "rate_limited", ["rate_limit:concurrency"], "")
            return McpResult(429, {"status": "rate_limited", "limited_by": "concurrency", "retry_after_s": 1, "request_id": ctx.request_id}, {"Retry-After": "1"})
        self._inflight += 1
        try:
            await self._emit(ctx, spec, decision, "allowed", [], "")
            started = time.monotonic()
            try:
                result = await self._call_tool(spec, decision.args, ctx)
            except McpTransportError as exc:
                await self._emit(ctx, spec, decision, "error", [f"errow_mcp:{exc.kind}"], f"error: {exc.kind}")
                return McpResult(502, {"status": "error", "error": exc.kind, "request_id": ctx.request_id})
            duration_ms = int((time.monotonic() - started) * 1000)
            text = _output_text(result)
            cleaned = sanitize_untrusted(redact_credentials(text), self._cfg.mcp_output_max_chars)
            truncated = "input:truncated" in cleaned.violations
            digest = hashlib.sha256(cleaned.text.encode("utf-8")).hexdigest()[:16]
            is_error = result.get("isError") is True
            await self._emit(ctx, spec, decision, "executed", ["tool_reported_error"] if is_error else [], f"{'tool_error' if is_error else 'ok'} chars={len(cleaned.text)} sha256={digest}")
            return McpResult(200, {
                "status": "executed", "request_id": ctx.request_id, "tool": spec.name, "target": decision.target.raw if decision.target else None,
                "is_error": is_error, "output": cleaned.text, "truncated": truncated, "duration_ms": duration_ms,
            })
        finally:
            self._inflight -= 1

    async def _http(self) -> aiohttp.ClientSession:
        if self._session is None:
            try:
                ctx = self._client_ssl or client_ssl_context(self._cfg)
            except (OSError, ssl.SSLError) as exc:
                raise McpTransportError("tls_setup_failed") from exc
            self._session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ctx), trust_env=False)
        return self._session

    async def _rpc(self, payload: Mapping[str, Any], timeout_s: float) -> dict[str, Any] | None:
        session = await self._http()
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self._mcp_session_id:
            headers["Mcp-Session-Id"] = self._mcp_session_id
        try:
            async with session.post(self._cfg.errow_mcp_url, data=json.dumps(payload), headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_s)) as response:
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise McpTransportError("response_too_large")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                if response.headers.get("Mcp-Session-Id"):
                    self._mcp_session_id = response.headers["Mcp-Session-Id"][:256]
                if "id" not in payload:
                    return None
                if response.status == 404 and self._mcp_session_id:
                    raise _SessionExpired()
                if response.status >= 400 and not raw.strip().startswith((b"{", b"data:", b"event:")):
                    raise McpTransportError(f"http_{response.status}")
                return _parse_rpc(raw, response.headers.get("Content-Type", ""), payload["id"])
        except asyncio.TimeoutError as exc:
            raise McpTransportError("timeout") from exc
        except aiohttp.ClientError as exc:
            raise McpTransportError("unreachable") from exc

    async def _initialise(self, timeout_s: float) -> None:
        async with self._init_lock:
            if self._initialised:
                return
            self._mcp_session_id = None
            init = {"jsonrpc": "2.0", "id": f"init-{uuid.uuid4().hex[:12]}", "method": "initialize",
                    "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "vendetta-llm-gateway", "version": self._cfg.version}}}
            reply = await self._rpc(init, timeout_s)
            if reply is None or "error" in reply:
                raise McpTransportError("initialize_failed")
            await self._rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout_s)
            self._initialised = True

    async def _call_tool(self, spec: ToolSpec, args: Mapping[str, Any], ctx: _Context) -> dict[str, Any]:
        timeout_s = float(min(spec.timeout_s + 15, self._cfg.request_timeout_s))
        for attempt in (1, 2):
            if not self._initialised:
                await self._initialise(timeout_s)
            call_id = f"{ctx.request_id}-{uuid.uuid4().hex[:8]}"
            payload = {
                "jsonrpc": "2.0", "id": call_id, "method": "tools/call",
                "params": {"name": spec.name, "arguments": dict(args),
                           "_meta": {"tenant_id": ctx.tenant_id, "incident_id": ctx.incident_id, "request_id": ctx.request_id, "role": ctx.role}},
            }
            try:
                reply = await self._rpc(payload, timeout_s)
            except _SessionExpired:
                reply = {"error": {"code": SESSION_ERROR}}
            if reply is None:
                raise McpTransportError("empty_response")
            error = reply.get("error")
            if isinstance(error, dict):
                if error.get("code") == SESSION_ERROR and attempt == 1:
                    self._initialised = False
                    continue
                raise McpTransportError(f"jsonrpc_error_{error.get('code') if isinstance(error.get('code'), int) else 'unknown'}")
            result = reply.get("result")
            if not isinstance(result, dict):
                raise McpTransportError("malformed_response")
            return result
        raise McpTransportError("session_error")


class _SessionExpired(Exception):
    pass


def _parse_rpc(raw: bytes, content_type: str, call_id: Any) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    candidates: list[Any] = []
    if "text/event-stream" in content_type or text.lstrip().startswith(("data:", "event:")):
        data_lines: list[str] = []
        for line in text.splitlines() + [""]:
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif not line.strip() and data_lines:
                try:
                    candidates.append(json.loads("\n".join(data_lines)))
                except ValueError:
                    pass
                data_lines = []
    else:
        try:
            candidates.append(json.loads(text))
        except ValueError as exc:
            raise McpTransportError("malformed_response") from exc
    for message in candidates:
        if isinstance(message, dict) and message.get("id") == call_id and ("result" in message or "error" in message):
            return message
    raise McpTransportError("malformed_response")


def _output_text(result: Mapping[str, Any]) -> str:
    parts: list[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append(item["text"])
    if not parts and result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False, sort_keys=True, default=str))
    return "\n".join(parts)
