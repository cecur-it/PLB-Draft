# Traces: PROMPT §1 Tier 4 / §2.3 / §2.5 (sovereign LLM gateway, guardrails, bounded concurrency, metering);
#         CONTRACT §4.4 (routes, auth, /health + /metrics shapes, metered /v1 passthrough), §4.3 (audit events), §4.5 (MCP policy),
#         CS3 server/inference/gateway.ts (guardrailed request pipeline) + router.ts.
"""llm-gateway entrypoint: HTTPS (optional mTLS) aiohttp service.

Routes: GET /health, GET /metrics (unauthenticated); POST /triage, POST /forensic, POST /mcp/tool_call, POST /v1/chat/completions,
GET /v1/models (bearer token, constant-time comparison). Exit codes: 0 ok, 1 selftest/healthcheck failure, 2 configuration error,
3 FailClosedError (sovereign profile pointed at a hosted LLM).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Sequence
from typing import Any, Mapping

from aiohttp import web

from audit import AuditEmitter, AuditSetupError, AuditUnavailable, TAG_INFERENCE, canonical_json, utc_now_iso
from backend import BackendError, BackendTimeout, OllamaBackend
from config import ROLES, Config, ConfigError, FailClosedError
from failover import ConcurrencyGate, Overloaded, TriageEngine
from jsonlog import configure_logging, log_event
from mcp import McpService
from meter import GpuUtilReader, Metrics, gpu_seconds_for, usage_tokens
from policy import Policy, PolicyError, Resolver
from prompts import TEMPERATURE, TOP_K, TOP_P
from records import RecordError, loop_marker, parse_body, prepare_record, query_loop_marker
from tlsutil import client_ssl_context, server_ssl_context

LOG = logging.getLogger("llm-gateway")

PUBLIC_PATHS = frozenset({"/health", "/metrics"})
MIN_TOKEN_CHARS = 16
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
BEARER_RE = re.compile(r"^Bearer[ \t]+([^\s]{1,512})$", re.I)
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")
CHAT_ROLES = frozenset({"system", "user", "assistant", "tool", "developer", "function"})
PASSTHROUGH_KEYS = ("response_format", "stop", "seed", "tools", "tool_choice", "parallel_tool_calls", "frequency_penalty", "presence_penalty", "think", "reasoning_effort")
REASONING_EFFORTS = ("none", "low", "medium", "high")
MAX_CHAT_MESSAGES = 512
# Prepended for agentic calls only: the model behind this router must emit native tool calls with the bare arguments, or it writes
# the tool name back into the command string ("cmd": "exec_command cmd=\"curl ...\"") and the sandbox exits 127 on every call.
AGENTIC_PREFACE = (
    "Gateway note (overrides nothing above): answer with native tool calls, one call at a time, and pass arguments exactly as the "
    "JSON schema declares. For command tools put only the shell command in the command argument - never repeat the tool name inside it."
)
# Callers that own the conversation: the agent role always, and any caller that supplies its own tool schemas. Those get their
# messages and tools forwarded verbatim (native tool_calls); other analysis calls get the gateway's strict-JSON framing.
AGENTIC_ROLES = frozenset({"errow"})
MAX_PASSTHROUGH_TOKENS = 32768
PASSTHROUGH_ROLE = "passthrough"
# OpenAI-style aliases so Errow can pin errow_LLM=openai/cs3-errow-security instead of a raw model tag.
ROLE_ALIASES = {
    "cs3-errow-security": "errow",
    "cs3-errow": "errow",
    "cs3-security": "security",
    "cs3-vuln-analysis": "security",
    "cs3-triage": "triage",
    "cs3-reasoning": "forensic",
    "cs3-deep": "deep",
    "cs3-reasoning-deep": "deep",
}
ROUTED_ROLES = frozenset(ROLE_ALIASES)
MUTATING_TOOLS = ("isolate_host", "execute_command", "modify_firewall")
APPROVAL_HEADER = "X-CS3-Approval"


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = dict(headers or {})


class TokenAuth:
    """Bearer token from LLM_GATEWAY_TOKEN_FILE, compared in constant time and re-read when the file changes (rotation)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._digest = b""
        self._mtime_ns = -1
        self._load(initial=True)

    def _load(self, *, initial: bool) -> None:
        try:
            stat = self._path.stat()
            if stat.st_mtime_ns == self._mtime_ns and self._digest:
                return
            token = self._path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            if initial:
                raise ConfigError(f"LLM_GATEWAY_TOKEN_FILE {self._path} is not readable: {exc.__class__.__name__}") from exc
            return
        if len(token) < MIN_TOKEN_CHARS:
            if initial:
                raise ConfigError(f"LLM_GATEWAY_TOKEN_FILE {self._path} must hold a token of at least {MIN_TOKEN_CHARS} characters")
            return
        self._digest = hashlib.sha256(token.encode("utf-8")).digest()
        self._mtime_ns = stat.st_mtime_ns

    def verify(self, candidate: str) -> bool:
        self._load(initial=False)
        given = hashlib.sha256(candidate.encode("utf-8", "replace")).digest()
        return hmac.compare_digest(given, self._digest)


class ModelAllowList:
    """Model ids permitted on /v1/chat/completions: ollama/models.json (mounted) plus the configured triage/forensic tags."""

    def __init__(self, path: Path, configured: tuple[str, ...]) -> None:
        self._path = path
        self._configured = frozenset(configured)
        self._ids = self._configured
        self._mtime_ns = -1

    def ids(self) -> frozenset[str]:
        try:
            mtime_ns = self._path.stat().st_mtime_ns
        except OSError:
            self._mtime_ns = -1
            self._ids = self._configured
            return self._ids
        if mtime_ns != self._mtime_ns:
            try:
                doc = json.loads(self._path.read_text(encoding="utf-8"))
                self._ids = self._configured | self._parse(doc)
            except (OSError, ValueError):
                self._ids = self._configured
            self._mtime_ns = mtime_ns
        return self._ids

    @staticmethod
    def _parse(doc: Any) -> frozenset[str]:
        found: set[str] = set()

        def add(value: Any) -> None:
            if isinstance(value, str) and MODEL_ID_RE.match(value):
                found.add(value)
            elif isinstance(value, dict):
                add(value.get("id"))

        if isinstance(doc, list):
            for item in doc:
                add(item)
        elif isinstance(doc, dict):
            for item in doc.get("models", []) if isinstance(doc.get("models"), list) else []:
                add(item)
            tiers = doc.get("tiers")
            if isinstance(tiers, dict):
                for tier in tiers.values():
                    for item in tier.get("models", []) if isinstance(tier, dict) and isinstance(tier.get("models"), list) else []:
                        add(item)
        return frozenset(found)


@dataclass
class Services:
    cfg: Config
    metrics: Metrics
    audit: AuditEmitter
    backend: OllamaBackend
    gate: ConcurrencyGate
    engine: TriageEngine
    mcp: McpService
    policy: Policy
    auth: TokenAuth
    gpu: GpuUtilReader
    models: ModelAllowList


SERVICES = web.AppKey("services", Services)
REQUEST_ID = web.RequestKey("request_id", str)


def _request_id(request: web.Request) -> str:
    supplied = request.headers.get("X-Request-Id", "")
    return supplied if REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex


def _tenant(request: web.Request) -> str:
    value = request.headers.get("X-Tenant-Id")
    if value is None or value == "":
        return "default"
    if not TENANT_RE.match(value):
        raise ApiError(400, "invalid_tenant", "X-Tenant-Id must match ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    return value


def _error_response(request: web.Request, status: int, code: str, message: str, headers: Mapping[str, str] | None = None) -> web.Response:
    if request.path.startswith("/v1/"):
        body: dict[str, Any] = {"error": {"message": message, "type": "invalid_request_error" if status < 500 else "server_error", "code": code, "param": None}}
    else:
        body = {"error": code, "message": message, "request_id": request.get(REQUEST_ID)}
    return web.json_response(body, status=status, headers=dict(headers or {}))


@web.middleware
async def observe_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    svc = request.app[SERVICES]
    started = time.monotonic()
    request[REQUEST_ID] = _request_id(request)
    try:
        async with asyncio.timeout(svc.cfg.request_timeout_s):
            response = await handler(request)
    except ApiError as exc:
        response = _error_response(request, exc.status, exc.code, exc.message, exc.headers)
    except RecordError as exc:
        response = _error_response(request, exc.status, exc.code, exc.message)
    except Overloaded as exc:
        response = _error_response(request, 429, "overloaded", "inference queue is full; retry later", {"Retry-After": str(exc.retry_after_s)})
    except AuditUnavailable:
        response = _error_response(request, 503, "audit_unavailable", "audit spool is not writable; refusing to proceed without an audit trail", {"Retry-After": "5"})
    except web.HTTPException as exc:
        response = _error_response(request, exc.status, "http_" + str(exc.status), exc.reason or "error", {k: v for k, v in exc.headers.items() if k.lower() == "allow"})
    except asyncio.TimeoutError:
        response = _error_response(request, 504, "request_timeout", "request exceeded GATEWAY_REQUEST_TIMEOUT_S")
    except Exception as exc:  # noqa: BLE001 - last-resort handler: never leak internals to the client
        log_event(LOG, logging.ERROR, "unhandled error", request_id=request[REQUEST_ID], path=request.path,
                  error=type(exc).__name__, trace=traceback.format_exc().strip().splitlines()[-3:])
        response = _error_response(request, 500, "internal_error", "internal error")
    response.headers["X-Request-Id"] = request[REQUEST_ID]
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    log_event(
        LOG, logging.INFO, "request", method=request.method, path=request.path, status=response.status,
        duration_ms=int((time.monotonic() - started) * 1000), request_id=request[REQUEST_ID], remote=request.remote,
    )
    return response


@web.middleware
async def auth_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    if request.path in PUBLIC_PATHS:
        return await handler(request)
    match = BEARER_RE.match(request.headers.get("Authorization", ""))
    if match is None or not request.app[SERVICES].auth.verify(match.group(1)):
        raise ApiError(401, "unauthorized", "a valid bearer token is required", {"WWW-Authenticate": 'Bearer realm="llm-gateway"'})
    return await handler(request)


def _model_available(name: str, available: frozenset[str]) -> bool:
    return name in available or f"{name}:latest" in available


async def health(request: web.Request) -> web.Response:
    svc = request.app[SERVICES]
    cfg = svc.cfg
    backend = await svc.backend.probe()
    fluent_ok = await svc.audit.probe()
    chain_ok = svc.audit.chain_ok
    maintenance = svc.backend.maintenance
    degraded = not backend.reachable or not fluent_ok or not chain_ok or maintenance
    body = {
        "status": "degraded" if degraded else "ok",
        "backend": {
            "reachable": backend.reachable,
            "models": {role: cfg.chain_for(role)[0] for role in ROLES},
            "chains": {role: list(cfg.chain_for(role)) for role in ROLES},
            "available": {role: _model_available(cfg.chain_for(role)[0], backend.models) for role in ROLES},
            "maintenance": maintenance,
        },
        "fluent_bit": {"reachable": fluent_ok, "spool_depth": svc.audit.spool_depth},
        "audit": {"chain_ok": chain_ok, "chain_id": svc.audit.chain_id},
        "mcp": {"live": svc.mcp.live, "tools": sorted(svc.policy.tools)},
        "version": cfg.version,
    }
    return web.json_response(body)


async def metrics(request: web.Request) -> web.Response:
    svc = request.app[SERVICES]
    svc.metrics.gpu_memory_util.set(await svc.gpu.read())
    svc.metrics.spool_depth.set(svc.audit.spool_depth)
    svc.metrics.audit_chain_ok.set(1 if svc.audit.chain_ok else 0)
    return web.Response(body=svc.metrics.render(), headers={"Content-Type": svc.metrics.content_type})


async def _read_body(request: web.Request) -> bytes:
    return await request.read()


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8-sig"), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise ApiError(400, "invalid_json", "body must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ApiError(400, "invalid_json", "body must be a JSON object")
    return parsed


async def _analyse(request: web.Request, role: str) -> web.Response:
    svc = request.app[SERVICES]
    cfg = svc.cfg
    marker = query_loop_marker(request.query, request.headers)
    if marker:
        svc.metrics.guardrail_rejections_total.labels(kind="loop").inc()
        raise ApiError(400, "telemetry_loop_rejected", f"request is marked cs3.ai.* ({marker}); the AI tier's own telemetry is never triaged")
    tenant = _tenant(request)
    records = parse_body(await _read_body(request), cfg.max_records)
    for index, record in enumerate(records):
        marker = loop_marker(record)
        if marker:
            svc.metrics.guardrail_rejections_total.labels(kind="loop").inc()
            raise ApiError(400, "telemetry_loop_rejected", f"record {index} is marked cs3.ai.* ({marker}); the AI tier's own telemetry is never triaged")
    prepared = [prepare_record(record, cfg.message_max_chars) for record in records]
    base_id = request[REQUEST_ID]
    svc.gate.admit(len(prepared))
    try:
        outcomes = await asyncio.gather(
            *(
                svc.engine.analyze(item, role=role, request_id=base_id if len(prepared) == 1 else f"{base_id}.{index}", tenant_id=tenant)
                for index, item in enumerate(prepared)
            ),
            return_exceptions=True,
        )
    finally:
        svc.gate.release(len(prepared))
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            raise outcome
    results = [{"request_id": r.request_id, "alert_id": r.alert_id, "analysis": r.analysis, "meta": r.meta} for r in outcomes if not isinstance(r, BaseException)]
    return web.json_response({"results": results})


async def triage(request: web.Request) -> web.Response:
    role = request.query.get("role", "triage")
    if role not in ROLES:
        raise ApiError(400, "invalid_role", f"role must be one of {', '.join(ROLES)}")
    return await _analyse(request, role)


async def forensic(request: web.Request) -> web.Response:
    return await _analyse(request, "forensic")


async def security(request: web.Request) -> web.Response:
    role = request.query.get("role", "security")
    if role not in ROLES:
        raise ApiError(400, "invalid_role", f"role must be one of {', '.join(ROLES)}")
    return await _analyse(request, role)


async def mcp_tool_call(request: web.Request) -> web.Response:
    body = _json_object(await _read_body(request))
    result = await request.app[SERVICES].mcp.handle(body, fallback_request_id=request[REQUEST_ID])
    return web.json_response(result.body, status=result.status, headers=result.headers)


async def list_models(request: web.Request) -> web.Response:
    ids = sorted(request.app[SERVICES].models.ids())
    return web.json_response({"object": "list", "data": [{"id": i, "object": "model", "owned_by": "vendetta-stack"} for i in ids]})


def _clamped(body: Mapping[str, Any], key: str, ceiling: float) -> float:
    value = body.get(key)
    if value is None:
        return ceiling
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        raise ApiError(400, "invalid_parameter", f"{key} must be a number")
    return min(max(float(value), 0.0), ceiling)


def _chat_payload(body: dict[str, Any], allowed: frozenset[str]) -> tuple[dict[str, Any], str, list[Any]]:
    if body.get("stream") not in (None, False):
        raise ApiError(400, "stream_not_supported", "stream must be false; this gateway only serves non-streaming completions")
    model = body.get("model")
    if not isinstance(model, str) or not MODEL_ID_RE.match(model):
        raise ApiError(400, "invalid_model", "model must be a model id string")
    if model not in allowed:
        raise ApiError(403, "model_not_allowed", f"model {model!r} is not in the gateway allow-list")
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_CHAT_MESSAGES:
        raise ApiError(400, "invalid_messages", f"messages must be an array of 1..{MAX_CHAT_MESSAGES} items")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in CHAT_ROLES:
            raise ApiError(400, "invalid_messages", "every message must be an object with a valid role")
        if not isinstance(message.get("content", ""), (str, list, type(None))):
            raise ApiError(400, "invalid_messages", "message content must be a string or an array of parts")
    temperature = _clamped(body, "temperature", TEMPERATURE)
    top_p = _clamped(body, "top_p", TOP_P)
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "top_p": top_p,
        "top_k": TOP_K,
        "options": {"temperature": temperature, "top_p": top_p, "top_k": TOP_K},
        "n": 1,
        "stream": False,
    }
    for key in PASSTHROUGH_KEYS:
        if key in body:
            payload[key] = body[key]
    if "think" in body and not isinstance(body["think"], bool):
        raise ApiError(400, "invalid_parameter", "think must be a boolean")
    if "reasoning_effort" in body and body["reasoning_effort"] not in REASONING_EFFORTS:
        raise ApiError(400, "invalid_parameter", "reasoning_effort must be one of " + ", ".join(REASONING_EFFORTS))
    limit = body.get("max_tokens", body.get("max_completion_tokens"))
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ApiError(400, "invalid_parameter", "max_tokens must be a positive integer")
        payload["max_tokens"] = min(limit, MAX_PASSTHROUGH_TOKENS)
    return payload, model, messages


def _message_chars(messages: list[Any]) -> int:
    total = 0
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            total += sum(len(part.get("text", "")) for part in content if isinstance(part, dict) and isinstance(part.get("text"), str))
    return total


def _role_messages(body: Mapping[str, Any]) -> list[Any]:
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_CHAT_MESSAGES:
        raise ApiError(400, "invalid_messages", f"messages must be an array of 1..{MAX_CHAT_MESSAGES} items")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in CHAT_ROLES:
            raise ApiError(400, "invalid_messages", "every message must be an object with a valid role")
        if not isinstance(message.get("content", ""), (str, list, type(None))):
            raise ApiError(400, "invalid_messages", "message content must be a string or an array of parts")
    return messages


def _prompt_text(messages: list[Any]) -> str:
    chunks = [str(m["content"]) for m in messages if m.get("role") == "user" and isinstance(m.get("content"), str)]
    return "\n\n".join(chunks) or "\n".join(str(m.get("content") or "") for m in messages)


def _proposed_tools(content: str, tool_calls: Sequence[Mapping[str, Any]] = ()) -> list[str]:
    found = [name for call in tool_calls for name in [_tool_call_name(call)] if name in MUTATING_TOOLS]
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        return list(dict.fromkeys(found + [name for name in MUTATING_TOOLS if name in content]))
    if isinstance(parsed, dict):
        for call in parsed.get("toolCalls") or parsed.get("tool_calls") or []:
            name = call.get("tool") or call.get("name") if isinstance(call, dict) else None
            if isinstance(name, str) and name in MUTATING_TOOLS:
                found.append(name)
    return list(dict.fromkeys(found))


def _tool_call_name(call: Mapping[str, Any]) -> str:
    function = call.get("function")
    name = function.get("name") if isinstance(function, dict) else call.get("name")
    return name if isinstance(name, str) else ""


def _approved(request: web.Request, body: Mapping[str, Any]) -> bool:
    token = request.headers.get(APPROVAL_HEADER, "").strip() or str(body.get("approval_token") or "").strip()
    return len(token) >= 4 or body.get("human_approved") is True


async def routed_chat(request: web.Request, body: dict[str, Any], role: str) -> web.Response:
    """Chat-mode task classes (security / Errow): declared model chain, degraded flag, human-approval guard on mutating calls."""
    svc = request.app[SERVICES]
    messages = _role_messages(body)
    schemas = [t for t in body.get("tools") or [] if isinstance(t, dict)]
    tools = tuple(sorted({str(t.get("function", {}).get("name") if isinstance(t.get("function"), dict) else t.get("name")) for t in schemas} - {"None"}))
    tenant = _tenant(request)
    incident = request.headers.get("X-Incident-Id", "")
    incident_id = incident if REQUEST_ID_RE.match(incident) else role
    try:
        # Errow (agentic roles) drives its own multi-turn tool loop, so its conversation and tool schemas are forwarded verbatim;
        # analysis roles get the gateway's framed prompt because they must answer with one JSON object.
        agentic = role in AGENTIC_ROLES or bool(schemas)
        reply = await svc.engine.respond(
            _prompt_text(messages),
            role=role,
            request_id=request[REQUEST_ID],
            tenant_id=tenant,
            tools=tools,
            raw_messages=[{"role": "system", "content": AGENTIC_PREFACE}, *messages] if agentic else None,
            tools_schema=tuple(schemas) if agentic else (),
        )
    except Overloaded:
        raise
    except BackendError as exc:
        svc.metrics.requests_total.labels(role=role, engine="none", fallback="true").inc()
        raise ApiError(502, "chain_exhausted", f"every declared model for {role} failed") from exc

    meta = reply.meta
    proposed = _proposed_tools(reply.text, reply.tool_calls)
    headers = {
        "X-CS3-Model": reply.model,
        "X-CS3-Task-Class": role,
        "X-CS3-Degraded-Model-Fallback": "true" if reply.fallback else "false",
        "X-CS3-Attempted-Fallbacks": ",".join(meta["attempted_fallbacks"]),
    }
    if proposed and not _approved(request, body):
        svc.metrics.guardrail_rejections_total.labels(kind="approval").inc()
        raise ApiError(
            403, "approval_required",
            f"proposed mutating tool call(s) {', '.join(proposed)} need a human-approval token ({APPROVAL_HEADER} header or approval_token field)",
            headers,
        )
    usage = {"prompt_tokens": meta["tokens_in"], "completion_tokens": meta["tokens_out"], "total_tokens": meta["tokens_in"] + meta["tokens_out"]}
    return web.json_response(
        {
            "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": reply.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": reply.text, **({"tool_calls": list(reply.tool_calls)} if reply.tool_calls else {})},
                "finish_reason": "tool_calls" if reply.tool_calls else "stop",
            }],
            "usage": usage,
            "cs3": meta,
            "approval_required": bool(proposed),
            "proposed_tools": proposed,
        },
        headers=headers,
    )


async def chat_completions(request: web.Request) -> web.Response:
    svc = request.app[SERVICES]
    cfg = svc.cfg
    body = _json_object(await _read_body(request))
    alias = body.get("model") if isinstance(body.get("model"), str) else None
    if alias in ROLE_ALIASES:
        return await routed_chat(request, body, ROLE_ALIASES[alias])
    payload, model, messages = _chat_payload(body, svc.models.ids())
    tenant = _tenant(request)
    incident = request.headers.get("X-Incident-Id", "")
    incident_id = incident if REQUEST_ID_RE.match(incident) else "passthrough"
    timeout_s = max(1.0, min(cfg.request_timeout_s - 5.0, max(cfg.inference_timeout_s, *cfg.role_timeout_s.values(), 120.0)))

    svc.gate.admit(1)
    try:
        async with svc.gate.slot():
            try:
                # The security classes never think, so a trace must not eat the caller's token budget here either.
                response = await svc.backend.passthrough(payload, timeout_s, thinking=False if model in (cfg.model_security, cfg.model_errow_security) else None)
            except BackendTimeout as exc:
                svc.metrics.charge(role=PASSTHROUGH_ROLE, model=model, gpu_seconds=gpu_seconds_for(exc.latency_s, cfg.gpu_share, "triage"), tokens_in=0, tokens_out=0)
                raise ApiError(504, "upstream_timeout", "the model did not answer in time") from exc
            except BackendError as exc:
                raise ApiError(502, "upstream_error", "the model backend is unavailable") from exc
    finally:
        svc.gate.release(1)
    if response.body is None:
        raise ApiError(502, "bad_upstream_response", "the model backend returned a non-JSON response")

    gpu = gpu_seconds_for(response.latency_s, cfg.gpu_share, "triage")
    prompt_text = "\n".join(str(m.get("content") or "") for m in messages)
    tokens_in, tokens_out = usage_tokens(response.usage, prompt_text, response.content)
    svc.metrics.charge(role=PASSTHROUGH_ROLE, model=model, gpu_seconds=gpu, tokens_in=tokens_in, tokens_out=tokens_out)
    svc.metrics.requests_total.labels(role=PASSTHROUGH_ROLE, engine=model, fallback="false").inc()
    svc.metrics.triage_latency.observe(response.latency_s)
    await svc.audit.emit(TAG_INFERENCE, {
        "@timestamp": utc_now_iso(),
        "event_type": "inference",
        "request_id": request[REQUEST_ID],
        "tenant_id": tenant,
        "incident_id": incident_id,
        "alert_id": None,
        "model": model,
        "role": PASSTHROUGH_ROLE,
        "engine_used": model,
        "fallback": False,
        "fallback_reason": None,
        "latency_ms": int(round(response.latency_s * 1000)),
        "gpu_seconds": gpu,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "verdict": "passthrough",
        "guardrail": {"passed": True, "violations": []},
        "input_sha256": hashlib.sha256(canonical_json({"messages": messages}).encode("utf-8")).hexdigest(),
        "input_chars": _message_chars(messages),
        "analysis": None,
    })
    return web.json_response(response.body)


def build_services(
    cfg: Config,
    *,
    backend: OllamaBackend | None = None,
    resolver: Resolver | None = None,
    audit: AuditEmitter | None = None,
    client_ssl: ssl.SSLContext | None = None,
) -> Services:
    policy = Policy.load(cfg.policy_path, cfg.targets_file)
    metrics = Metrics(version=cfg.version, models=tuple(dict.fromkeys(model for role in ROLES for model in cfg.chain_for(role))))
    if audit is None:
        fluent_ssl = None
        if cfg.fluent_bit_url.startswith("https://"):
            fluent_ssl = client_ssl or client_ssl_context(cfg)
        audit = AuditEmitter(spool_dir=cfg.spool_dir, url=cfg.fluent_bit_url, metrics=metrics, max_events=cfg.spool_max_events, ssl_context=fluent_ssl)
    backend = backend or OllamaBackend(cfg)
    gate = ConcurrencyGate(cfg.max_concurrency, cfg.max_queue, metrics)
    return Services(
        cfg=cfg,
        metrics=metrics,
        audit=audit,
        backend=backend,
        gate=gate,
        engine=TriageEngine(cfg, backend, audit, metrics, gate, policy),
        mcp=McpService(cfg, policy, audit, metrics, resolver=resolver, client_ssl=client_ssl),
        policy=policy,
        auth=TokenAuth(cfg.token_file),
        gpu=GpuUtilReader(cfg.gpu_util_file),
        models=ModelAllowList(cfg.models_json_path, tuple(dict.fromkeys([*(m for role in ROLES for m in cfg.chain_for(role)), *ROUTED_ROLES]))),
    )


def create_app(
    cfg: Config,
    *,
    backend: OllamaBackend | None = None,
    resolver: Resolver | None = None,
    audit: AuditEmitter | None = None,
    client_ssl: ssl.SSLContext | None = None,
) -> web.Application:
    services = build_services(cfg, backend=backend, resolver=resolver, audit=audit, client_ssl=client_ssl)
    app = web.Application(middlewares=[observe_middleware, auth_middleware], client_max_size=cfg.max_body_bytes)
    app[SERVICES] = services
    app.add_routes([
        web.get("/health", health),
        web.get("/metrics", metrics),
        web.post("/triage", triage),
        web.post("/forensic", forensic),
        web.post("/security", security),
        web.post("/mcp/tool_call", mcp_tool_call),
        web.post("/v1/chat/completions", chat_completions),
        web.get("/v1/models", list_models),
    ])

    async def on_startup(_: web.Application) -> None:
        await services.audit.start()
        await services.backend.start()
        log_event(
            LOG, logging.INFO, "llm-gateway started", version=cfg.version, profile=cfg.profile, port=cfg.port, tls=cfg.tls, mtls=cfg.mtls,
            mcp_live=services.mcp.live, tools=len(services.policy.tools), chain_id=services.audit.chain_id,
        )

    async def on_cleanup(_: web.Application) -> None:
        await services.audit.close(5.0)
        await services.mcp.close()
        await services.backend.close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def healthcheck(cfg: Config) -> int:
    scheme = "https" if cfg.tls else "http"
    url = f"{scheme}://127.0.0.1:{cfg.port}/health"
    context: ssl.SSLContext | None = None
    try:
        if cfg.tls:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cfg.tls_ca))
            context.check_hostname = False
            if cfg.mtls != "off":
                context.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
        with urllib.request.urlopen(url, timeout=4, context=context) as response:  # noqa: S310 - fixed loopback URL
            return 0 if response.status == 200 else 1
    except (urllib.error.URLError, OSError, ssl.SSLError):
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-gateway",
        description="vendetta-stack LLM gateway: guardrailed triage/forensic analysis with Ollama failover, MCP policy enforcement, "
        "metering and a hash-chained audit trail. Configuration is read from the environment (see README.md).",
        epilog="exit codes: 0 ok, 1 selftest/healthcheck failed, 2 configuration error, 3 FailClosedError",
    )
    parser.add_argument("--selftest", action="store_true", help="run an offline self-check (policy, schema, heuristics, guardrails, audit chain, fail-closed) and exit")
    parser.add_argument("--healthcheck", action="store_true", help="probe the local /health endpoint (used by the container HEALTHCHECK) and exit")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.selftest:
        import selftest

        return selftest.run()
    try:
        cfg = Config.from_env(os.environ)
    except FailClosedError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.version:
        print(cfg.version)
        return 0
    if args.healthcheck:
        return healthcheck(cfg)

    configure_logging(cfg.log_level)
    try:
        ssl_context = server_ssl_context(cfg)
        app = create_app(cfg)
        web.run_app(app, host=cfg.host, port=cfg.port, ssl_context=ssl_context, access_log=None, print=None, shutdown_timeout=10.0)
    except (ConfigError, PolicyError, AuditSetupError, OSError, ssl.SSLError) as exc:
        log_event(LOG, logging.CRITICAL, "startup failed", error=type(exc).__name__, detail=str(exc)[:300])
        print(f"startup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
