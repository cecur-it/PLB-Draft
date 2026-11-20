# Traces: PROMPT §2.5 (stage-2 guardrails on every record), §4.3 telemetry-loop prevention (cs3.ai.ollama never reaches /triage);
#         CONTRACT §3 (streams), §4.4 (POST /triage body: one record | JSON array | NDJSON; alert_id derivation).
"""Request-body parsing, telemetry-loop guard, alert_id derivation and the sanitised prompt view of a record.

Raw telemetry never leaves this module except as the sanitised/redacted/framed prompt text; the audit trail only receives
input_sha256 + input_chars of that text.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from audit import canonical_json
from guardrails import detect_injection, redact_credentials, sanitize_untrusted, strip_invisible

LOOP_PREFIX = "cs3.ai."
TAG_KEYS = ("stream", "tag", "_tag", "fluent_tag", "fluentd_tag", "@tag")
QUERY_TAG_KEYS = ("tag", "stream", "_tag")
HEADER_TAG_KEYS = ("X-Fluentd-Tag", "X-Fluent-Tag", "X-Tag", "Fluentd-Tag")
SELF_EVENT_TYPES = ("inference", "tool_call", "enrichment")
PRIORITY_KEYS = (
    "@timestamp", "id", "doc_id", "source", "rule", "ruleId", "level", "severity", "anomaly_score", "anomalyScore", "title", "description",
    "message", "mitre", "agent", "manager", "location", "locations", "properties", "errow", "cwe", "syscheck", "vulnerability", "full_log", "data",
)
MAX_DEPTH = 6
MAX_DICT_ITEMS = 80
MAX_LIST_ITEMS = 40
MAX_KEY_CHARS = 128


class RecordError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Prepared:
    alert_id: str
    incident_id: str
    record: Mapping[str, Any]
    text: str
    sha256: str
    chars: int
    violations: tuple[str, ...]

    @property
    def injection_flagged(self) -> bool:
        return any(v.startswith("input:") and v != "input:truncated" for v in self.violations)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _loads(text: str) -> Any:
    return json.loads(text, parse_constant=_reject_constant)


def parse_body(raw: bytes, max_records: int) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RecordError(400, "invalid_encoding", "body must be UTF-8") from exc
    stripped = text.strip()
    if not stripped:
        raise RecordError(400, "empty_body", "body is empty")
    try:
        if stripped[0] == "[":
            parsed: list[Any] = _loads(stripped)
        else:
            try:
                parsed = [_loads(stripped)]
            except ValueError:
                lines = [line for line in stripped.splitlines() if line.strip()]
                if len(lines) < 2:
                    raise
                parsed = [_loads(line) for line in lines]
    except (ValueError, RecursionError) as exc:
        raise RecordError(400, "invalid_json", "body is not a JSON object, JSON array or NDJSON") from exc
    if len(parsed) > max_records:
        raise RecordError(413, "too_many_records", f"at most {max_records} records per request")
    if not parsed:
        raise RecordError(400, "no_records", "the request contains no records")
    if any(not isinstance(item, dict) for item in parsed):
        raise RecordError(400, "invalid_record", "every record must be a JSON object")
    return [unwrap_source(item) for item in parsed]


def unwrap_source(record: dict[str, Any]) -> dict[str, Any]:
    """OpenSearch hits ({_id, _source}) are analysed as the document they carry."""
    source = record.get("_source")
    if isinstance(source, dict) and "rule" not in record and "message" not in record:
        merged = dict(source)
        if record.get("_id") is not None:
            merged.setdefault("_id", record["_id"])
        return merged
    return record


def _is_loop_value(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold().startswith(LOOP_PREFIX)


def loop_marker(record: Mapping[str, Any]) -> str | None:
    """Telemetry-loop guard: records produced by the AI tier itself (or journald ollama logs) are never triaged."""
    for key in TAG_KEYS:
        if _is_loop_value(record.get(key)):
            return key
    source = record.get("source")
    if isinstance(source, Mapping):
        if _is_loop_value(source.get("stream")):
            return "source.stream"
        if isinstance(source.get("system"), str) and source["system"].strip().casefold() == "cs3-ai":
            return "source.system"
    if record.get("event_type") in SELF_EVENT_TYPES and "chain_id" in record:
        return "event_type"
    return None


def query_loop_marker(query: Mapping[str, str], headers: Mapping[str, str]) -> str | None:
    for key in QUERY_TAG_KEYS:
        if _is_loop_value(query.get(key)):
            return f"query:{key}"
    for key in HEADER_TAG_KEYS:
        if _is_loop_value(headers.get(key)):
            return f"header:{key}"
    return None


def derive_alert_id(record: Mapping[str, Any]) -> str:
    for key in ("id", "doc_id", "_id"):
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        text = strip_invisible(str(value)).strip()
        if text:
            return text[:256]
    digest = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
    return digest


def derive_incident_id(record: Mapping[str, Any], alert_id: str) -> str:
    value = record.get("incident_id")
    if isinstance(value, str) and value.strip():
        return strip_invisible(value).strip()[:128]
    return alert_id[:128]


class _Collector:
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.found: dict[str, None] = {}

    def add(self, violations: Iterable[str]) -> None:
        for item in violations:
            self.found[item] = None

    def string(self, value: str) -> str:
        self.add(detect_injection(value))
        result = sanitize_untrusted(redact_credentials(strip_invisible(value)), self.cap)
        self.add(result.violations)
        return result.text

    def clean(self, value: Any, depth: int = 0) -> Any:
        if isinstance(value, str):
            return self.string(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if depth >= MAX_DEPTH:
            self.add(["input:truncated"])
            return "[truncated]"
        if isinstance(value, dict):
            items = list(value.items())
            if len(items) > MAX_DICT_ITEMS:
                self.add(["input:truncated"])
            return {sanitize_untrusted(str(k), MAX_KEY_CHARS).text: self.clean(v, depth + 1) for k, v in items[:MAX_DICT_ITEMS]}
        if isinstance(value, (list, tuple)):
            if len(value) > MAX_LIST_ITEMS:
                self.add(["input:truncated"])
            return [self.clean(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]
        return self.string(str(value))


def prepare_record(record: Mapping[str, Any], max_chars: int) -> Prepared:
    """Builds the sanitised, redacted, size-capped prompt body (the text that will be wrapped in <untrusted_data>)."""
    collector = _Collector(max_chars)
    view = {key: record[key] for key in PRIORITY_KEYS if key in record} or dict(record)
    serialised = json.dumps(collector.clean(view), ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    final = sanitize_untrusted(redact_credentials(serialised), max_chars)
    collector.add(final.violations)
    alert_id = derive_alert_id(record)
    return Prepared(
        alert_id=alert_id,
        incident_id=derive_incident_id(record, alert_id),
        record=record,
        text=final.text,
        sha256=hashlib.sha256(final.text.encode("utf-8")).hexdigest(),
        chars=len(final.text),
        violations=tuple(collector.found),
    )
