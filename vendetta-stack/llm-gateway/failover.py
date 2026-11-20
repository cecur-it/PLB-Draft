# Traces: PROMPT §1 Tier 4 / §2.3 (triage -> forensic -> deterministic cascade, never fail), §2.5 (output guardrails);
#         CONTRACT §4.2 (AIIncidentAnalysis), §4.3 (inference/enrichment events, fallback reasons), §4.4 (metering, queue, failover metrics);
#         CS3 server/inference/router.ts (failover cascade) + gateway.ts (guardrailed call) + meter.ts.
"""Three-tier failover cascade: triage model -> forensic model -> deterministic Cecur Heuristics.

Tier 3 never fails. A model answer is accepted only if it is JSON, matches the AIIncidentAnalysis schema and passes the output
guardrails; anything else (invalid JSON, schema violation, dangerous content, 5xx, timeout, GPU maintenance) moves to the next tier.
Model-proposed toolCalls are returned verbatim for the analyst but are never executed here (execution only via /mcp/tool_call).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from collections.abc import Mapping, Sequence
from typing import Any, AsyncIterator

from audit import TAG_ENRICHMENT, TAG_INFERENCE, AuditEmitter, utc_now_iso
from backend import BackendError, BackendTimeout, BackendUnavailable, OllamaBackend
from config import ROLES, Config
from guardrails import check_output, redact_credentials
from heuristics import ENGINE_NAME, HEURISTIC_MODEL, analyze as heuristic_analyze, heuristic_severity
from jsonlog import log_event
from meter import Metrics, gpu_seconds_for, usage_tokens
from policy import Policy
from prompts import build_messages
from records import Prepared
from schema import schema_for_role, severity_rank, validate_analysis

LOG = logging.getLogger("llm-gateway.triage")

MAX_EVENT_VIOLATIONS = 25
MAX_VIOLATION_CHARS = 240
RETRY_AFTER_S = 5
_FENCED = re.compile(r"\A\s*```(?:json)?[ \t]*\r?\n?(.*?)\r?\n?[ \t]*```\s*\Z", re.S | re.I)


class Overloaded(Exception):
    """The inference queue is full; the caller answers 429 with Retry-After."""

    def __init__(self, retry_after_s: int = RETRY_AFTER_S) -> None:
        super().__init__("inference queue is full")
        self.retry_after_s = retry_after_s


class ConcurrencyGate:
    """Bounds concurrent inferences (GATEWAY_MAX_CONCURRENCY) so alert storms cannot thrash the Ollama KV cache."""

    def __init__(self, slots: int, max_queue: int, metrics: Metrics) -> None:
        self._sem = asyncio.Semaphore(slots)
        self._capacity = slots + max_queue
        self._metrics = metrics
        self._admitted = 0
        self._waiting = 0

    def admit(self, count: int) -> None:
        # An idle gate always accepts one request, however large, so a batch can never be refused forever.
        if self._admitted and self._admitted + count > self._capacity:
            raise Overloaded()
        self._admitted += count

    def release(self, count: int) -> None:
        self._admitted = max(0, self._admitted - count)

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        self._waiting += 1
        self._metrics.queue_depth.set(self._waiting)
        try:
            await self._sem.acquire()
        finally:
            self._waiting -= 1
            self._metrics.queue_depth.set(self._waiting)
        try:
            yield
        finally:
            self._sem.release()


@dataclass(frozen=True)
class Tier:
    label: str
    model: str
    kind: str = "model"


@dataclass
class TriageResult:
    request_id: str
    alert_id: str
    analysis: dict[str, Any]
    meta: dict[str, Any]


@dataclass
class ChatReply:
    """Plain-text answer from a chat-mode task class (Errow / vulnerability reasoning), with its routing provenance."""

    text: str
    model: str
    fallback: bool
    attempted: tuple[str, ...]
    meta: dict[str, Any]
    tool_calls: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class _ChatAnswer:
    text: str
    tool_calls: tuple[dict[str, Any], ...]


def _call_signature(call: Mapping[str, Any], with_args: bool = True) -> str:
    function = call.get("function") if isinstance(call.get("function"), dict) else {}
    name = str(function.get("name") or "?")
    return f"{name}{function.get('arguments') or ''}" if with_args else name


def _tool_calls_of(body: Mapping[str, Any] | None) -> tuple[dict[str, Any], ...]:
    """Native OpenAI tool_calls of the first choice, if the model emitted any."""
    choices = (body or {}).get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ()
    message = choices[0].get("message")
    calls = message.get("tool_calls") if isinstance(message, dict) else None
    return tuple(call for call in calls or [] if isinstance(call, dict))


def _flatten(messages: Sequence[Mapping[str, Any]]) -> str:
    """All message text as one string; agent conversations carry None content (tool-call turns) and array-of-parts content."""
    chunks: list[str] = []
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            chunks.extend(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return "\n".join(chunks)


@dataclass
class _Run:
    prepared: Prepared
    role: str
    violations: dict[str, None] = field(default_factory=dict)
    latency_s: float = 0.0
    gpu_seconds: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    reason: str | None = None

    def flag(self, items: list[str]) -> None:
        for item in items:
            self.violations[item[:MAX_VIOLATION_CHARS]] = None


def extract_json(content: str) -> Any:
    """Strict JSON, tolerating only a single ```json fenced block around it."""
    text = content.strip()
    match = _FENCED.match(text)
    if match:
        text = match.group(1).strip()
    return json.loads(text, parse_constant=_reject_constant)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def verdict_for(analysis: Mapping[str, Any]) -> str:
    if analysis.get("needsVerification") is True:
        return "needs_verification"
    severity = str(analysis.get("severityAssessment"))
    confidence = analysis.get("confidenceScore")
    if severity in ("HIGH", "CRITICAL") and isinstance(confidence, (int, float)) and confidence >= 70:
        return "malicious"
    if severity_rank(severity) >= severity_rank("MEDIUM"):
        return "suspicious"
    return "low_risk"


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact_credentials(value)
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    return value


def _minimal_analysis(role: str) -> dict[str, Any]:
    analysis: dict[str, Any] = {
        "triageSummary": f"[{ENGINE_NAME}] Event could not be classified automatically; manual review required.",
        "severityAssessment": "MEDIUM",
        "mitreTactic": "Execution",
        "mitreTechnique": "T1059 - Command and Scripting Interpreter",
        "probableRootCause": "Automatic classification failed; no root cause established.",
        "recommendedImmediateAction": "Escalate to an analyst for manual review.",
        "confidenceScore": 10,
        "engineUsed": ENGINE_NAME,
        "needsVerification": True,
        "gpuSeconds": 0.0,
    }
    if role == "forensic":
        analysis["proposedDetectionRule"] = "title: Manual review required\nstatus: experimental\ndetection:\n  condition: selection\n"
        analysis["proposedRemediation"] = "No automated remediation proposed; analyst review required."
    return analysis


class TriageEngine:
    def __init__(self, cfg: Config, backend: OllamaBackend, audit: AuditEmitter, metrics: Metrics, gate: ConcurrencyGate, policy: Policy) -> None:
        self._cfg = cfg
        self._backend = backend
        self._audit = audit
        self._metrics = metrics
        self._gate = gate
        self._policy = policy
        self._cache: dict[str, tuple[float, dict[str, Any], str, str, bool, str | None]] = {}

    @property
    def _legacy_roles(self) -> dict[str, str]:
        return {self._cfg.model_triage: "triage", self._cfg.model_forensic: "forensic", self._cfg.model_deep: "deep", self._cfg.model_security: "security"}

    def _label(self, role: str, model: str, index: int) -> str:
        """Triage/forensic keep the historical role labels so existing dashboards and alerts stay valid."""
        if role not in ("triage", "forensic"):
            return f"{role}-primary" if index == 0 else f"{role}-fallback-{index}"
        return {self._cfg.model_triage: "triage", self._cfg.model_forensic: "forensic", self._cfg.model_deep: "deep"}.get(
            model, f"{role}-fallback-{index}"
        )

    def tiers(self, role: str) -> list[Tier]:
        """Declared chain for the task class, terminated by the deterministic tier (analysis classes only)."""
        tiers = [Tier(self._label(role, model, index), model, "model" if index == 0 else "fallback") for index, model in enumerate(self._cfg.chain_for(role))]
        return [*tiers, Tier("heuristic", HEURISTIC_MODEL, "heuristic")]

    def _cache_key(self, role: str, text: str) -> str:
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return f"{role}:{'|'.join(self._cfg.chain_for(role))}:{digest}"

    def _cache_get(self, key: str) -> tuple[dict[str, Any], Tier, bool, str | None] | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires_at, analysis, model, label, fallback, reason = entry
        if expires_at < time.monotonic():
            self._cache.pop(key, None)
            return None
        # The label is cached with the answer: a replay must report the tier that actually answered, not re-derive it.
        return analysis, Tier(label, model, "cache"), fallback, reason

    def _cache_put(self, key: str, analysis: dict[str, Any], answered: Tier, fallback: bool, reason: str | None) -> None:
        limit = self._cfg.cache_max_entries
        if limit <= 0:
            return
        if len(self._cache) >= limit:
            for stale in [k for k, (expires_at, *_) in self._cache.items() if expires_at < time.monotonic()]:
                self._cache.pop(stale, None)
            while len(self._cache) >= limit:
                self._cache.pop(next(iter(self._cache)), None)
        self._cache[key] = (time.monotonic() + self._cfg.cache_ttl_s, dict(analysis), answered.model, answered.label, fallback, reason)

    def _tool_names(self, role: str) -> tuple[str, ...]:
        return tuple(sorted(name for name, spec in self._policy.tools.items() if role in spec.roles))

    async def analyze(self, prepared: Prepared, *, role: str, request_id: str, tenant_id: str) -> TriageResult:
        role = role if role in ROLES else "triage"
        run = _Run(prepared=prepared, role=role)
        run.flag(list(prepared.violations))
        if prepared.injection_flagged:
            self._metrics.injection_blocked.inc()
        key = self._cache_key(role, prepared.text)
        cached = self._cache_get(key) if self._cfg.caches(role) else None
        if cached is not None:
            analysis, tier, fallback, reason = cached
            run.reason = reason
            self._apply_floor(analysis, run)
            return await self._finish(run, tier, analysis, fallback, request_id, tenant_id, cache_hit=True)

        messages = build_messages(role, prepared.text, self._tool_names(role))
        tiers = self.tiers(role)

        analysis: dict[str, Any] | None = None
        answered = tiers[-1]
        for index, tier in enumerate(tiers[:-1]):
            async with self._gate.slot():
                analysis = await self._try_model(tier, run, messages)
            if analysis is not None:
                answered = tier
                break
            nxt = tiers[index + 1]
            self._metrics.failover_total.labels(**{"from": tier.label, "to": nxt.label, "reason": run.reason or "backend_unavailable"}).inc()
            log_event(LOG, logging.WARNING, "tier failed over", request_id=request_id, tier=tier.label, next_tier=nxt.label, reason=run.reason)
        if analysis is None:
            analysis = self._heuristic(run)

        if answered.kind != "heuristic":
            self._apply_floor(analysis, run)
        fallback = answered.kind != "model" or answered is not tiers[0]
        if self._cfg.caches(role) and answered.kind == "model":
            self._cache_put(key, analysis, answered, fallback, run.reason if fallback else None)
        return await self._finish(run, answered, analysis, fallback, request_id, tenant_id)

    async def respond(
        self,
        text: str,
        *,
        role: str,
        request_id: str,
        tenant_id: str,
        tools: tuple[str, ...] = (),
        raw_messages: Sequence[Mapping[str, Any]] | None = None,
        tools_schema: Sequence[Mapping[str, Any]] = (),
    ) -> ChatReply:
        """Chat-mode answer for the security/Errow classes: retries each declared tier, then fails closed (no heuristics).

        With `raw_messages` the caller's own conversation and `tools_schema` are forwarded untouched (an agent such as Errow needs
        native tool_calls, not a JSON analysis object); without them the gateway frames a single analysis prompt.
        """
        role = role if role in ROLES else "errow"
        prepared = Prepared(alert_id="-", incident_id="-", record={}, text=text, sha256=hashlib.sha256(text.encode()).hexdigest(), chars=len(text), violations=())
        run = _Run(prepared=prepared, role=role)
        messages = list(raw_messages) if raw_messages else build_messages(role, text, tools)
        extra: dict[str, Any] = {}
        if tools_schema:
            extra = {"tools": list(tools_schema), "tool_choice": "auto", "response_format": None}
        attempted: list[str] = []
        tiers = [tier for tier in self.tiers(role) if tier.kind != "heuristic"]
        for index, tier in enumerate(tiers):
            attempted.append(tier.model)
            async with self._gate.slot():
                answer = await self._try_chat(tier, run, messages, extra)
            if answer is not None:
                fallback = index > 0
                meta = await self._finish_chat(run, tier, attempted, answer.text, fallback, request_id, tenant_id, answer.tool_calls)
                return ChatReply(text=answer.text, model=tier.model, fallback=fallback, attempted=tuple(attempted), meta=meta,
                                 tool_calls=answer.tool_calls)
            if index + 1 < len(tiers):
                self._metrics.failover_total.labels(**{"from": tier.label, "to": tiers[index + 1].label, "reason": run.reason or "backend_unavailable"}).inc()
                log_event(LOG, logging.WARNING, "errow tier failed over", request_id=request_id, tier=tier.label, reason=run.reason)
        raise BackendError(f"declared chain exhausted for role {role} after {len(attempted)} models") from None

    async def _call(self, tier: Tier, run: _Run, messages: list[dict[str, Any]], extra: Mapping[str, Any] | None = None):
        """One tier with bounded retries and exponential backoff; returns None once the tier is exhausted."""
        for attempt in range(self._cfg.retry_attempts):
            if self._backend.maintenance:
                run.reason = "gpu_maintenance"
                return None
            try:
                return await self._backend.chat(
                    tier.model,
                    messages,
                    self._cfg.timeout_s_for(run.role),
                    max_tokens=self._cfg.max_tokens_for(run.role),
                    thinking=self._cfg.thinking_for(run.role, tier.model),
                    extra=extra,
                )
            except BackendTimeout as exc:
                self._charge(run, tier, exc.latency_s, "", messages, None)
                run.reason = "timeout"
            except BackendUnavailable as exc:
                run.latency_s += exc.latency_s
                run.reason = "gpu_maintenance" if exc.maintenance else "backend_unavailable"
            except BackendError as exc:
                run.latency_s += exc.latency_s
                run.reason = "backend_unavailable"
            except Exception as exc:  # noqa: BLE001 - the next tier must still get a chance
                log_event(LOG, logging.ERROR, "unexpected backend failure", tier=tier.label, error=type(exc).__name__)
                run.reason = "backend_unavailable"
            if attempt + 1 < self._cfg.retry_attempts and self._cfg.retry_backoff_s:
                await asyncio.sleep(self._cfg.retry_backoff_s * (2**attempt))
        return None

    async def _try_chat(self, tier: Tier, run: _Run, messages: list[dict[str, Any]], extra: Mapping[str, Any] | None = None) -> _ChatAnswer | None:
        response = await self._call(tier, run, messages, extra)
        if response is None:
            return None
        calls = _tool_calls_of(response.body)
        self._charge(run, tier, response.latency_s, response.content, messages, response.usage)
        text = (response.content or "").strip()
        match = _FENCED.match(text)
        if match:
            text = match.group(1).strip()
        if not text and not calls:
            run.reason = "empty_response"
            return None
        return _ChatAnswer(text, calls)

    async def _try_model(self, tier: Tier, run: _Run, messages: list[dict[str, str]]) -> dict[str, Any] | None:
        response = await self._call(tier, run, messages)
        if response is None:
            return None

        self._charge(run, tier, response.latency_s, response.content, messages, response.usage)
        try:
            parsed = extract_json(response.content)
        except (ValueError, RecursionError):
            parsed = None
        if not isinstance(parsed, dict):
            run.flag(["schema:/ model output is not a JSON object"])
            self._reject("schema", run, "schema_violation")
            return None

        analysis = dict(parsed)
        # The gateway, not the model, owns these two fields; they are set before validation so the schema can require them.
        analysis["engineUsed"] = tier.model
        analysis["gpuSeconds"] = gpu_seconds_for(response.latency_s, self._cfg.gpu_share, tier.label)
        guard = self._backend.guard if self._cfg.model_guard else None
        result = await check_output(analysis, schema_for_role(run.role), guard)
        if not result.passed:
            run.flag(result.violations)
            if any(v.startswith("schema:") for v in result.violations):
                self._reject("schema", run, "schema_violation")
            else:
                self._reject("output", run, "guardrail_rejected")
            return None
        return analysis

    def _reject(self, kind: str, run: _Run, reason: str) -> None:
        run.reason = reason
        if reason == "schema_violation":
            self._metrics.schema_violations.inc()
        self._metrics.guardrail_rejections_total.labels(kind=kind).inc()

    def _charge(self, run: _Run, tier: Tier, latency_s: float, completion: str, messages: list[dict[str, Any]], usage: Mapping[str, Any] | None) -> None:
        gpu = gpu_seconds_for(latency_s, self._cfg.gpu_share, tier.label)
        tokens_in, tokens_out = usage_tokens(usage, _flatten(messages), completion)
        run.latency_s += latency_s
        run.gpu_seconds += gpu
        run.tokens_in += tokens_in
        run.tokens_out += tokens_out
        self._metrics.charge(role=tier.label, model=tier.model, gpu_seconds=gpu, tokens_in=tokens_in, tokens_out=tokens_out)

    def _heuristic(self, run: _Run) -> dict[str, Any]:
        try:
            analysis = heuristic_analyze(run.prepared.record, run.role)
            if validate_analysis(analysis, run.role):
                raise ValueError("heuristic analysis failed its own schema")
        except Exception as exc:  # noqa: BLE001 - the deterministic tier can never fail
            log_event(LOG, logging.ERROR, "heuristic analysis failed; using static analysis", error=type(exc).__name__)
            analysis = _minimal_analysis(run.role)
        return analysis

    def _apply_floor(self, analysis: dict[str, Any], run: _Run) -> None:
        """Prompt-injected input can never push a model below the deterministic heuristic severity."""
        if not run.prepared.injection_flagged:
            return
        try:
            floor = heuristic_severity(run.prepared.record)
        except Exception as exc:  # noqa: BLE001 - an unclassifiable injected record is treated as HIGH rather than trusted
            log_event(LOG, logging.ERROR, "severity floor computation failed; using HIGH", error=type(exc).__name__)
            floor = "HIGH"
        if severity_rank(str(analysis.get("severityAssessment"))) < severity_rank(floor):
            analysis["severityAssessment"] = floor
            analysis["needsVerification"] = True
            run.flag(["output:severity_floor"])

    async def _finish(
        self, run: _Run, answered: Tier, analysis: dict[str, Any], fallback: bool, request_id: str, tenant_id: str, *, cache_hit: bool = False,
    ) -> TriageResult:
        prepared = run.prepared
        engine = str(analysis["engineUsed"])
        reason = run.reason if fallback else None
        # Errow and vulnerability runs answer from a fallback model when the security tag is unavailable: the operator must see that flag.
        degraded = fallback and run.role in ("security", "errow")
        if answered.kind == "heuristic":
            winner_role = "heuristic"
        elif run.role in ("triage", "forensic"):
            # A tier label that is already a role name wins: the security tag is the triage tag, so the model alone is ambiguous.
            winner_role = answered.label if answered.label in ROLES else self._legacy_roles.get(answered.model, answered.label)
            if answered.kind == "cache" and answered.label == "cache":
                winner_role = run.role
        else:
            winner_role = run.role
        verdict = verdict_for(analysis)
        violations = list(run.violations)
        guardrail = {"passed": not [v for v in violations if v != "input:truncated"], "violations": violations[:MAX_EVENT_VIOLATIONS]}
        latency_ms = int(round(run.latency_s * 1000))
        gpu_seconds = round(run.gpu_seconds, 3)

        self._metrics.requests_total.labels(role=winner_role, engine=engine, fallback="true" if fallback else "false").inc()
        if run.latency_s > 0:
            self._metrics.triage_latency.observe(run.latency_s)

        meta = {
            "model": answered.model,
            "role": winner_role,
            "task_class": run.role,
            "fallback": fallback,
            "fallback_reason": reason,
            "degraded_model_fallback": degraded,
            "cache_hit": cache_hit,
            "latency_ms": latency_ms,
            "gpu_seconds": gpu_seconds,
            "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out,
            "guardrail": guardrail,
        }
        event = {
            "@timestamp": utc_now_iso(),
            "event_type": "inference",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "incident_id": prepared.incident_id,
            "alert_id": prepared.alert_id,
            "model": answered.model,
            "role": winner_role,
            "task_class": run.role,
            "engine_used": engine,
            "fallback": fallback,
            "fallback_reason": reason,
            "degraded_model_fallback": degraded,
            "cache_hit": cache_hit,
            "latency_ms": latency_ms,
            "gpu_seconds": gpu_seconds,
            "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out,
            "verdict": verdict,
            "guardrail": guardrail,
            "input_sha256": prepared.sha256,
            "input_chars": prepared.chars,
            "analysis": _scrub(analysis),
        }
        await self._audit.emit(TAG_INFERENCE, event)
        await self._audit.emit(TAG_ENRICHMENT, {
            "@timestamp": utc_now_iso(),
            "id": prepared.alert_id,
            "ai": {
                "engine": engine,
                "role": winner_role,
                "confidence": analysis["confidenceScore"],
                "verdict": verdict,
                "fallback": fallback,
                "cost": {"gpu_seconds": gpu_seconds},
            },
            "severity": str(analysis["severityAssessment"]).lower(),
            "mitre": {"tactic": [_scrub(analysis["mitreTactic"])], "technique": [_scrub(analysis["mitreTechnique"])]},
            "root_cause": _scrub(analysis["probableRootCause"]),
            "recommended_action": _scrub(analysis["recommendedImmediateAction"]),
        })
        log_event(
            LOG, logging.INFO, "record analysed", request_id=request_id, tenant_id=tenant_id, role=winner_role, task_class=run.role,
            model=answered.model, fallback=fallback, fallback_reason=reason, degraded_model_fallback=degraded, cache_hit=cache_hit,
            latency_ms=latency_ms, verdict=verdict, input_sha256=prepared.sha256,
        )
        return TriageResult(request_id=request_id, alert_id=prepared.alert_id, analysis=analysis, meta=meta)

    async def _finish_chat(
        self, run: _Run, tier: Tier, attempted: list[str], answer: str, fallback: bool, request_id: str, tenant_id: str,
        tool_calls: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        degraded = fallback
        latency_ms = int(round(run.latency_s * 1000))
        gpu_seconds = round(run.gpu_seconds, 3)
        self._metrics.requests_total.labels(role=run.role, engine=tier.model, fallback="true" if fallback else "false").inc()
        event = {
            "@timestamp": utc_now_iso(),
            "event_type": "inference",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "model": tier.model,
            "role": run.role,
            "task_class": run.role,
            "fallback": fallback,
            "fallback_reason": run.reason or ("declared_fallback" if fallback else None),
            "degraded_model_fallback": degraded,
            "attempted_fallbacks": attempted[1:],
            "latency_ms": latency_ms,
            "gpu_seconds": gpu_seconds,
            "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out,
            "input_sha256": run.prepared.sha256,
            "input_chars": run.prepared.chars,
            # A tool-calling turn answers with empty content, so the calls themselves are the auditable decision.
            "answer": _scrub(answer) or " ".join(_call_signature(call) for call in tool_calls),
            "tool_calls": [{"tool": _call_signature(call, with_args=False)} for call in tool_calls],
        }
        await self._audit.emit(TAG_INFERENCE, event)
        log_event(
            LOG, logging.WARNING if fallback else logging.INFO, "chat answered", request_id=request_id, tenant_id=tenant_id,
            role=run.role, primary_model=self._cfg.chain_for(run.role)[0], attempted_fallbacks=attempted[1:], final_model=tier.model,
            degraded_model_fallback=degraded, latency_ms=latency_ms, input_sha256=run.prepared.sha256,
            tool_calls=[_call_signature(call, with_args=False) for call in tool_calls],
        )
        return {
            "role": run.role,
            "task_class": run.role,
            "model": tier.model,
            "primary_model": self._cfg.chain_for(run.role)[0],
            "attempted_fallbacks": attempted[1:],
            "fallback": fallback,
            "degraded_model_fallback": degraded,
            "fallback_reason": run.reason or ("declared_fallback" if fallback else None),
            "latency_ms": latency_ms,
            "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out,
            "needs_analyst_review": fallback,
        }
