"""Edge sanitisation for shipper records, plus guards that keep exploit payloads off the wire.

Port of the algorithm in deployment/agents/templates/gateway.d/cs3-otlp-normalize.lua
(CONTRACT §3 "Edge sanitization"): strip C0 controls except \\t \\n plus DEL, UTF-8-safe
truncate at CS3_MESSAGE_MAX_CHARS (byte budget, like the Lua) appending "...[truncated]",
then redact Bearer tokens and secret-looking key/value pairs.

The payload guards are shipper-specific: ``poc_script_code`` is dropped from every record at any depth,
fenced code blocks in analysis text are replaced by a length marker, and the arguments of tool calls
that carry code/payload bodies are replaced by ``[omitted:N chars]``.

Traces: PROMPT §2.3, CONTRACT §3 (edge sanitization), §15 (findings: poc_script_code/payload bodies NEVER emitted).
"""

from __future__ import annotations

import os
import re
from typing import Any

TRUNCATED = "...[truncated]"
REDACTED = "[REDACTED]"

NEVER_EMIT_KEYS = frozenset({"poc_script_code"})
TOOL_ARG_OMIT_KEYS = frozenset(
    {"script", "code", "python_code", "file_text", "new_str", "old_str", "content", "payload", "exploit",
     "exploit_code", "poc_code", "poc_script_code", "body", "data"}
)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BEARER = re.compile(r"(bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE | re.ASCII)
_KV = re.compile(
    r"((?:password|passwd|secret|token|api[_-]?key|apikey|authorization)[\"']?\s*[:=]\s*[\"']?)"
    r"[^\s\"',&;]+",
    re.IGNORECASE | re.ASCII,
)
_FENCE = re.compile(r"(```|~~~)[^\n]*\n.*?(?:\1|\Z)", re.DOTALL)


def max_chars() -> int:
    try:
        value = int(os.environ.get("CS3_MESSAGE_MAX_CHARS", "8000"))
    except ValueError:
        return 8000
    return value if value > 0 else 8000


def redact(text: str) -> str:
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    return _KV.sub(lambda m: m.group(1) + REDACTED, text)


def clean(text: str, limit: int | None = None) -> str:
    """Strip control characters and truncate on a UTF-8 boundary (Lua `clean`)."""
    limit = limit or max_chars()
    text = _CONTROL.sub("", text)
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return raw.decode("utf-8", errors="replace")
    cut = raw[:limit]
    i = len(cut)
    while i > 0:
        b = cut[i - 1]
        if 0x80 <= b < 0xC0:
            i -= 1
            continue
        if b >= 0xC0:
            i -= 1
        break
    return cut[:i].decode("utf-8", errors="replace") + TRUNCATED


def sanitize_text(text: str, limit: int | None = None) -> str:
    return redact(clean(text, limit))


def elide_code(text: str) -> str:
    """Replace fenced code blocks (``` or ~~~, also an unterminated last one) with a length marker."""
    return _FENCE.sub(lambda m: f"[code block omitted: {len(m.group(0))} chars]", text)


def drop_keys(value: Any, keys: frozenset[str] = NEVER_EMIT_KEYS) -> Any:
    """Remove the given keys at any depth of a JSON-like structure."""
    if isinstance(value, dict):
        return {k: drop_keys(v, keys) for k, v in value.items() if k not in keys}
    if isinstance(value, (list, tuple)):
        return [drop_keys(v, keys) for v in value]
    return value


def omit_tool_args(value: Any) -> Any:
    """Replace the values of code/payload-bearing keys of tool-call arguments by ``[omitted:N chars]``."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in TOOL_ARG_OMIT_KEYS:
                size = len(v) if isinstance(v, str) else len(str(v))
                out[k] = f"[omitted:{size} chars]"
            else:
                out[k] = omit_tool_args(v)
        return out
    if isinstance(value, (list, tuple)):
        return [omit_tool_args(v) for v in value]
    return value


def sanitize_value(value: Any, limit: int | None = None) -> Any:
    """Apply sanitize_text to every string in a JSON-like structure (keys included)."""
    if isinstance(value, str):
        return sanitize_text(value, limit)
    if isinstance(value, dict):
        return {sanitize_text(str(k), limit): sanitize_value(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_value(v, limit) for v in value]
    return value
