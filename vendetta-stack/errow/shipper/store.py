"""Durable state and append-only NDJSON output for the errow shipper.

* ``atomic_write`` / ``read_json_stable``: tmp+fsync+rename writes; reads that retry once on half-written JSON.
* ``State``: ``/var/lib/errow-shipper/state.json`` (content hashes, file cursors, docker cursors) plus a
  write-ahead ``inflight`` marker.
* ``Sink``: appends whole batches to ``<out>/<stream>.ndjson`` (one write + fsync per stream), rotates by
  size (rename to ``.1`` and create a new file, keep N), and recovers an interrupted commit on start-up.

Delivery is at-least-once with deterministic ``doc_id``s: a crash can only repeat a batch, never lose it,
and the write-ahead marker lets the next start tell "written" from "not written" so the common crash
windows do not even repeat.

Traces: PROMPT §2.3 (errow-shipper), CONTRACT §8.4 (stream files), §15 (record shapes), §12 (hygiene).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

STATE_VERSION = 1


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def dumps_line(record: dict[str, Any]) -> str:
    """One JSON object without raw newlines or Unicode line separators."""
    text = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
    return text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(path.parent)


def open_regular(path: Path, flags: int = os.O_RDONLY) -> int:
    """Open without following symlinks and insist on a regular file."""
    fd = os.open(path, flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path.name}")
    except OSError:
        os.close(fd)
        raise
    return fd


def read_bytes(path: Path, max_bytes: int) -> tuple[bytes, os.stat_result]:
    fd = open_regular(path)
    try:
        st = os.fstat(fd)
        if st.st_size > max_bytes:
            raise OSError(f"file larger than {max_bytes} bytes: {path.name}")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise OSError(f"file larger than {max_bytes} bytes: {path.name}")
    return data, st


def read_json_stable(
    path: Path,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    retry_delay: float = 0.25,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, Any, str]:
    """Return ``(status, value, sha256)``; status is ok | missing | unreadable.

    Errow rewrites its JSON atomically, but a reader can still catch a half-written file on filesystems
    without atomic rename semantics: parse failures and files that changed while being read get one retry.
    """
    for attempt in (0, 1):
        try:
            data, st = read_bytes(path, max_bytes)
            after = path.stat()
        except FileNotFoundError:
            return "missing", None, ""
        except OSError:
            if attempt == 0:
                sleep(retry_delay)
                continue
            return "unreadable", None, ""
        unchanged = (st.st_size, st.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
        try:
            value = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            if attempt == 0:
                sleep(retry_delay)
                continue
            return "unreadable", None, ""
        if not unchanged and attempt == 0:
            sleep(retry_delay)
            continue
        return "ok", value, sha256_hex(data)
    return "unreadable", None, ""


def fresh_data() -> dict[str, Any]:
    return {
        "hashes": {},
        "findings": {},
        "threat_models": {},
        "agent_state": {},
        "cursors": {},
        "tool_names": {},
        "telemetry": {},
        "docker": {},
        "counts": {},
    }


class State:
    """``{"version", "data", "inflight"}`` JSON document, replaced atomically."""

    def __init__(self, path: Path, log: Callable[..., None]) -> None:
        self.path = path
        self.log = log
        self.data: dict[str, Any] = fresh_data()
        self.inflight: dict[str, Any] | None = None

    def load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return
        try:
            doc = json.loads(raw.decode("utf-8"))
            data = doc["data"]
            if not isinstance(data, dict) or doc.get("version") != STATE_VERSION:
                raise ValueError("unexpected state layout")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            quarantine = self.path.with_name(self.path.name + ".corrupt")
            os.replace(self.path, quarantine)
            self.log("warning", "state_corrupt", reason=type(exc).__name__, moved_to=quarantine.name)
            return
        merged = fresh_data()
        merged.update(data)
        self.data = merged
        inflight = doc.get("inflight")
        self.inflight = inflight if isinstance(inflight, dict) else None

    def save(self) -> None:
        doc = {"version": STATE_VERSION, "data": self.data, "inflight": self.inflight}
        atomic_write(self.path, canonical(doc).encode("utf-8"), 0o640)


class Sink:
    """The NDJSON stream files under ``out_dir``."""

    def __init__(self, out_dir: Path, streams: tuple[str, ...], state: State, *, max_bytes: int, keep: int,
                 max_line_bytes: int, log: Callable[..., None]) -> None:
        self.out_dir = out_dir
        self.streams = streams
        self.state = state
        self.max_bytes = max(1024, max_bytes)
        self.keep = max(1, keep)
        self.max_line_bytes = max(1024, max_line_bytes)
        self.log = log

    def path(self, stream: str) -> Path:
        return self.out_dir / f"{stream}.ndjson"

    def ensure_files(self) -> None:
        for stream in self.streams:
            fd = os.open(self.path(stream), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            os.close(fd)

    def sizes(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for stream in self.streams:
            try:
                out[stream] = self.path(stream).stat().st_size
            except OSError:
                out[stream] = 0
        return out

    def encode(self, record: dict[str, Any]) -> bytes:
        line = dumps_line(record)
        raw = line.encode("utf-8") + b"\n"
        if len(raw) <= self.max_line_bytes:
            return raw
        stub = {k: record.get(k) for k in ("@timestamp", "stream", "run", "source", "doc_id")}
        stub.update({"truncated_record": True, "original_bytes": len(raw)})
        self.log("warning", "record_too_large", stream=record.get("stream"), bytes=len(raw))
        return dumps_line(stub).encode("utf-8") + b"\n"

    def rotate(self, stream: str) -> None:
        base = self.path(stream)
        oldest = base.with_name(f"{base.name}.{self.keep}")
        oldest.unlink(missing_ok=True)
        for i in range(self.keep - 1, 0, -1):
            src = base.with_name(f"{base.name}.{i}")
            if src.exists():
                os.replace(src, base.with_name(f"{base.name}.{i + 1}"))
        os.replace(base, base.with_name(f"{base.name}.1"))
        fd = os.open(base, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
        fsync_dir(self.out_dir)
        self.log("info", "stream_rotated", stream=stream, keep=self.keep)

    def _verified(self, stream: str, rec: dict[str, Any]) -> bool:
        try:
            st = self.path(stream).stat()
            if st.st_ino != rec["ino"] or st.st_size < rec["size"] + rec["len"]:
                return False
            with open(self.path(stream), "rb") as fh:
                fh.seek(rec["size"])
                return sha256_hex(fh.read(rec["len"])) == rec["sha"]
        except OSError:
            return False

    def recover(self) -> str:
        """Settle an interrupted commit: ``none`` | ``committed`` | ``rolled_back``."""
        inflight = self.state.inflight
        if not inflight:
            return "none"
        streams: dict[str, Any] = inflight.get("streams", {})
        if all(self._verified(s, r) for s, r in streams.items()):
            self.state.data = inflight["next"]
            self.state.inflight = None
            self.state.save()
            self.log("info", "inflight_committed", streams=sorted(streams))
            return "committed"
        for stream, rec in streams.items():
            try:
                st = self.path(stream).stat()
                if st.st_ino == rec["ino"] and st.st_size > rec["size"]:
                    os.truncate(self.path(stream), rec["size"])
            except OSError:
                pass
        self.state.inflight = None
        self.state.save()
        self.log("warning", "inflight_rolled_back", streams=sorted(streams))
        return "rolled_back"

    def commit(self, batch: dict[str, list[dict[str, Any]]], next_data: dict[str, Any]) -> dict[str, dict[str, int]]:
        """Append ``batch`` and make ``next_data`` the committed state; returns per-stream records/bytes."""
        payloads: dict[str, bytes] = {}
        for stream, records in batch.items():
            if records:
                payloads[stream] = b"".join(self.encode(r) for r in records)
        stats = {s: {"records": len(batch[s]), "bytes": len(p)} for s, p in payloads.items()}
        if not payloads:
            self.state.data = next_data
            self.state.save()
            return stats

        wal: dict[str, Any] = {}
        for stream, payload in payloads.items():
            path = self.path(stream)
            if not path.exists():
                os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644))
            if 0 < path.stat().st_size and path.stat().st_size + len(payload) > self.max_bytes:
                self.rotate(stream)
            st = path.stat()
            wal[stream] = {"ino": st.st_ino, "size": st.st_size, "len": len(payload), "sha": sha256_hex(payload)}
        self.state.inflight = {"streams": wal, "next": next_data}
        self.state.save()
        for stream, payload in payloads.items():
            self._append(stream, payload)
        self.state.data = next_data
        self.state.inflight = None
        self.state.save()
        return stats

    def _append(self, stream: str, payload: bytes) -> None:
        """One O_APPEND write loop + fsync, so concurrent readers (Fluent Bit) only ever see whole batches or a prefix."""
        fd = os.open(self.path(stream), os.O_WRONLY | os.O_APPEND)
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
