# Traces: PROMPT §1 Tier 4 (metering / observability); CONTRACT §4.4 (metric names, metering rule);
#         CS3 demo-100226/server/inference/meter.ts (gpu_seconds = latency * share, tokens from backend usage).
"""Metering arithmetic and the Prometheus registry. Metric names are fixed by CONTRACT §4.4; extras are namespaced llm_gateway_*."""
from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path
from typing import Mapping

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

ROLES = ("triage", "forensic", "heuristic")
FALLBACK_REASONS = ("timeout", "schema_violation", "backend_unavailable", "guardrail_rejected", "gpu_maintenance")
MCP_DECISIONS = ("allowed", "denied", "rate_limited", "dry_run", "executed", "error")
LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0)
GPU_UTIL_CACHE_S = 5.0


def gpu_seconds_for(latency_s: float, gpu_share: float, role: str) -> float:
    """CONTRACT §4.4: gpu_seconds = latency_s * INFERENCE_GPU_SHARE; heuristics never touch the GPU."""
    if role == "heuristic" or latency_s <= 0:
        return 0.0
    return round(latency_s * gpu_share, 3)


def estimate_tokens(text: str) -> int:
    """Fallback when the backend reports no usage: ~4 characters per token (same heuristic as meter.ts)."""
    return max(1, (len(text) + 3) // 4) if text else 0


def usage_tokens(usage: Mapping[str, object] | None, prompt_text: str, completion_text: str) -> tuple[int, int]:
    if usage:
        prompt = usage.get("prompt_tokens")
        completion = usage.get("completion_tokens")
        if isinstance(prompt, int) and isinstance(completion, int) and not isinstance(prompt, bool) and not isinstance(completion, bool) and prompt >= 0 and completion >= 0:
            return prompt, completion
    return estimate_tokens(prompt_text), estimate_tokens(completion_text)


class Metrics:
    def __init__(self, *, version: str, models: tuple[str, ...] = ()) -> None:
        self.registry = CollectorRegistry()
        reg = self.registry
        self.requests_total = Counter("llm_gateway_requests_total", "Analysed records by answering role, engine and fallback flag.", ("role", "engine", "fallback"), registry=reg)
        self.triage_latency = Histogram("llm_gateway_triage_latency_seconds", "Backend latency per analysed record (queue wait excluded).", buckets=LATENCY_BUCKETS, registry=reg)
        self.failover_total = Counter("llm_gateway_failover_total", "Tier transitions in the triage -> forensic -> heuristics cascade.", ("from", "to", "reason"), registry=reg)
        self.queue_depth = Gauge("llm_gateway_queue_depth", "Records waiting for an inference slot.", registry=reg)
        self.schema_violations = Counter("llm_gateway_output_schema_violations_total", "Model outputs that failed JSON-schema validation.", registry=reg)
        self.injection_blocked = Counter("llm_gateway_prompt_injection_blocked_total", "Inputs that matched an injection signature (triaged defensively).", registry=reg)
        self.gpu_seconds_total = Counter("llm_gateway_gpu_seconds_total", "Metered GPU seconds.", ("role", "model"), registry=reg)
        self.tokens_total = Counter("llm_gateway_tokens_total", "Tokens processed.", ("direction", "role", "model"), registry=reg)
        self.mcp_tool_calls_total = Counter("llm_gateway_mcp_tool_calls_total", "MCP tool-call decisions.", ("tool", "decision"), registry=reg)
        self.audit_chain_ok = Gauge("llm_gateway_audit_chain_ok", "1 while the local audit hash chain is intact and fully spooled.", registry=reg)
        self.spool_depth = Gauge("llm_gateway_spool_depth", "Audit/enrichment events waiting in the durable spool.", registry=reg)
        self.gpu_memory_util = Gauge("ollama_gpu_memory_util", "GPU memory utilisation 0-1 (OLLAMA_GPU_UTIL_FILE or nvidia-smi, else 0).", registry=reg)
        self.audit_events_total = Counter("llm_gateway_audit_events_total", "Events accepted into the spool.", ("tag",), registry=reg)
        self.audit_dropped_total = Counter("llm_gateway_audit_dropped_total", "Unchained events dropped because the spool is full.", ("tag",), registry=reg)
        self.audit_quarantined_total = Counter("llm_gateway_audit_quarantined_total", "Events moved to quarantine after repeated 4xx from Fluent Bit.", ("tag",), registry=reg)
        self.guardrail_rejections_total = Counter("llm_gateway_guardrail_rejections_total", "Model outputs rejected by output guardrails.", ("kind",), registry=reg)
        self.build_info = Gauge("llm_gateway_build_info", "Build information.", ("version",), registry=reg)
        self.build_info.labels(version=version).set(1)
        self.audit_chain_ok.set(1)
        self.spool_depth.set(0)
        self.queue_depth.set(0)
        self.gpu_memory_util.set(0)
        self._prime(models)

    def _prime(self, models: tuple[str, ...]) -> None:
        """Series exist from the first scrape so dashboards and alert rules never see 'no data'."""
        for reason in FALLBACK_REASONS:
            self.failover_total.labels(**{"from": "triage", "to": "forensic", "reason": reason})
            self.failover_total.labels(**{"from": "forensic", "to": "heuristics", "reason": reason})
        for decision in MCP_DECISIONS:
            self.mcp_tool_calls_total.labels(tool="unknown", decision=decision)
        for model in models:
            for role in ("triage", "forensic"):
                self.gpu_seconds_total.labels(role=role, model=model)
                for direction in ("in", "out"):
                    self.tokens_total.labels(direction=direction, role=role, model=model)
        self.requests_total.labels(role="heuristic", engine="Cecur Heuristics", fallback="true")
        for kind in ("schema", "output", "guard", "loop"):
            self.guardrail_rejections_total.labels(kind=kind)

    def render(self) -> bytes:
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST

    def charge(self, *, role: str, model: str, gpu_seconds: float, tokens_in: int, tokens_out: int) -> None:
        if gpu_seconds > 0:
            self.gpu_seconds_total.labels(role=role, model=model).inc(gpu_seconds)
        if tokens_in:
            self.tokens_total.labels(direction="in", role=role, model=model).inc(tokens_in)
        if tokens_out:
            self.tokens_total.labels(direction="out", role=role, model=model).inc(tokens_out)


def _parse_util(text: str) -> float:
    value = float(text.strip().split()[0].rstrip("%"))
    if value > 1.0:
        value /= 100.0
    return min(max(value, 0.0), 1.0)


class GpuUtilReader:
    """GPU memory utilisation in 0-1. Never raises: any problem reads as 0 (CONTRACT §4.4)."""

    def __init__(self, util_file: Path | None) -> None:
        self._file = util_file
        self._cached = 0.0
        self._at = 0.0

    async def read(self) -> float:
        now = time.monotonic()
        if self._at and now - self._at < GPU_UTIL_CACHE_S:
            return self._cached
        self._cached = await self._sample()
        self._at = now
        return self._cached

    async def _sample(self) -> float:
        if self._file is not None:
            try:
                return _parse_util(self._file.read_text(encoding="ascii", errors="replace"))
            except (OSError, ValueError, IndexError):
                return 0.0
        smi = shutil.which("nvidia-smi")
        if not smi:
            return 0.0
        try:
            proc = await asyncio.create_subprocess_exec(
                smi, "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
            if proc.returncode != 0:
                return 0.0
            ratios = []
            for line in out.decode("ascii", "replace").splitlines():
                used, total = (float(x) for x in line.split(","))
                if total > 0:
                    ratios.append(used / total)
            return min(max(max(ratios), 0.0), 1.0) if ratios else 0.0
        except (OSError, ValueError, asyncio.TimeoutError):
            return 0.0
