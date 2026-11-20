"""errow-mcp audit trail: `mcp_exec` events as NDJSON for Fluent Bit (tag errow.mcp_events).

Append-only file (default /var/log/errow/mcp_events.ndjson), one JSON object per line, fsync after every
record, size-based self-rotation (rename to .1 and shift older files; keep MCP_EVENTS_KEEP) when the file
reaches MCP_EVENTS_MAX_BYTES. Rotation never truncates in place, so a `tail` input following the inode
sees a clean rename. A write failure is counted and logged, never raised into the request path.
`doc_id` is sha256 of the canonical record without doc_id (idempotent ingest key).

Traces: PROMPT §2.3; CONTRACT §3 (edge sanitization), §8.4 (shipper file names), §15 (record envelope).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from sanitize import sanitize_value

DECISIONS = ("allowed", "denied", "rate_limited", "dry_run", "executed", "error")


def utc_now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


class EventLog:
    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        max_bytes: int | None = None,
        keep: int | None = None,
        on_error: Callable[[Exception], None] | None = None,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.path = Path(path or os.environ.get("MCP_EVENTS_FILE", "/var/log/errow/mcp_events.ndjson"))
        self.max_bytes = max_bytes if max_bytes is not None else _int_env("MCP_EVENTS_MAX_BYTES", 52_428_800)
        self.keep = keep if keep is not None else _int_env("MCP_EVENTS_KEEP", 5)
        self._on_error = on_error
        self._now = now
        self._lock = threading.Lock()
        self.write_errors = 0

    def emit(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = {
            "@timestamp": self._now(),
            "stream": "mcp_events",
            "source": "errow",
            "run": "mcp",
            "event_type": "mcp_exec",
            **sanitize_value(record),
        }
        rec["doc_id"] = hashlib.sha256(
            json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        line = (json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            try:
                self._append(line)
            except OSError as exc:
                self.write_errors += 1
                if self._on_error:
                    self._on_error(exc)
        return rec

    def _append(self, line: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            size = 0
        if self.max_bytes > 0 and size > 0 and size + len(line) > self.max_bytes:
            self._rotate()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _rotate(self) -> None:
        for index in range(self.keep - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{index}")
            if src.exists():
                os.replace(src, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.keep > 0:
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        else:
            self.path.unlink(missing_ok=True)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default
