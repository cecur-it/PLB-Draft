# Traces: PROMPT §1 Tier 4 (observability); CONTRACT §0 (structured logging, never log raw telemetry or secrets).
"""Structured JSON logging. Field names that look like secrets are redacted before they reach stdout."""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEY = re.compile(r"(pass(word|wd)?|secret|token|authorization|api[_-]?key|bearer|cookie|credential)", re.I)
_MAX_VALUE_CHARS = 300


def _coerce(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= _MAX_VALUE_CHARS else value[:_MAX_VALUE_CHARS] + "...[truncated]"
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_coerce(v) for v in list(value)[:20]]
    if isinstance(value, dict):
        return {str(k)[:64]: _coerce(v) for k, v in list(value.items())[:20]}
    return _coerce(str(value))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                payload[key] = "[REDACTED]" if _SENSITIVE_KEY.search(key) else _coerce(value)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc_type"] = record.exc_info[0].__name__
            payload["exc"] = _coerce(str(record.exc_info[1]))
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())


def log_event(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    logger.log(level, msg, extra={"fields": fields})
