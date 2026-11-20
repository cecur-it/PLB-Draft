# Traces: PROMPT §1 Tier 4 / NIST AU-9 (tamper-evident AI audit trail); CONTRACT §4.3 (event shapes, hash chain, durable spool),
#         §3 (cs3.ai.inference -> cs3-ai-audit-*), §4.4 (llm_gateway_audit_chain_ok, llm_gateway_spool_depth).
"""Hash-chained audit emitter with a durable write-ahead spool.

hash = sha256(prev_hash + canonical_json(event without "hash")); genesis prev_hash = 64 zeros; one chain per replica (chain_id),
persisted in <spool>/chain-state.json so restarts continue the chain. Every event is fsynced into the spool BEFORE the caller
continues; a background task replays the spool to Fluent Bit strictly in order with exponential backoff.

canonical_json: sorted keys, no whitespace, UTF-8 (ensure_ascii=False, lone surrogates replaced), NaN/Infinity rejected, integral
floats written as integers (so 0.0 and 0 hash identically across Python/jq/JS verifiers). tools/verify_audit_chain.py implements
the same function.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import json
import logging
import os
import random
import re
import socket
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

import aiohttp

from jsonlog import log_event
from meter import Metrics

LOG = logging.getLogger("llm-gateway.audit")

GENESIS_HASH = "0" * 64
TAG_INFERENCE = "cs3.ai.inference"
TAG_TOOL_CALL = "cs3.ai.tool_call"
TAG_ENRICHMENT = "cs3.ai.enrichment"
CHAINED_TAGS = frozenset({TAG_INFERENCE, TAG_TOOL_CALL})
ALL_TAGS = CHAINED_TAGS | {TAG_ENRICHMENT}
CHAIN_FIELDS = ("chain_id", "seq", "prev_hash", "hash")
STATE_FILE = "chain-state.json"
QUARANTINE_DIR = "quarantine"
MAX_CLIENT_ERRORS = 5
_SPOOL_NAME = re.compile(r"^ev-(\d{16})\.json$")
_INT_LIMIT = 10**15


class AuditUnavailable(RuntimeError):
    """The event could not be made durable; the caller must not proceed with the audited action."""


class AuditSetupError(RuntimeError):
    """The spool directory is unusable (read-only, locked by another replica, ...)."""


def utc_now_iso(ts: float | None = None) -> str:
    moment = datetime.fromtimestamp(ts, tz=timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


_SURROGATES = re.compile("[\ud800-\udfff]")


def _normalise(value: Any) -> Any:
    if isinstance(value, str):
        return _SURROGATES.sub("\ufffd", value) if _SURROGATES.search(value) else value
    if isinstance(value, float) and value == value and abs(value) < _INT_LIMIT and value == int(value):
        return int(value)
    if isinstance(value, dict):
        return {(_normalise(k) if isinstance(k, str) else k): _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    return value


def canonical_json(event: Mapping[str, Any]) -> str:
    return json.dumps(_normalise(dict(event)), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_hash(prev_hash: str, event_without_hash: Mapping[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(event_without_hash)).encode("utf-8")).hexdigest()


class HashChain:
    def __init__(self, chain_id: str, seq: int = 0, prev_hash: str = GENESIS_HASH) -> None:
        self.chain_id = chain_id
        self.seq = seq
        self.prev_hash = prev_hash

    def seal(self, event: Mapping[str, Any]) -> dict[str, Any]:
        sealed = {k: v for k, v in event.items() if k not in CHAIN_FIELDS}
        sealed.update(chain_id=self.chain_id, seq=self.seq + 1, prev_hash=self.prev_hash)
        sealed["hash"] = compute_hash(self.prev_hash, sealed)
        return sealed

    def advance(self, sealed: Mapping[str, Any]) -> None:
        self.seq = int(sealed["seq"])
        self.prev_hash = str(sealed["hash"])


@dataclass
class VerifyResult:
    ok: bool
    checked: int = 0
    errors: list[str] = field(default_factory=list)
    chains: dict[str, tuple[int, str]] = field(default_factory=dict)


def verify_chain(events: Iterable[Mapping[str, Any]], *, require_genesis: bool = False) -> VerifyResult:
    """Verifies hash, prev linkage and seq continuity per chain_id. Input order within a chain must be ascending seq."""
    result = VerifyResult(ok=True)
    tails: dict[str, tuple[int, str]] = {}
    for index, event in enumerate(events):
        result.checked += 1
        chain_id, seq, prev, digest = event.get("chain_id"), event.get("seq"), event.get("prev_hash"), event.get("hash")
        if not isinstance(chain_id, str) or not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(prev, str) or not isinstance(digest, str):
            result.errors.append(f"event {index}: missing or malformed chain fields")
            continue
        body = {k: v for k, v in event.items() if k != "hash"}
        if compute_hash(prev, body) != digest:
            result.errors.append(f"event {index} chain={chain_id} seq={seq}: hash mismatch")
        tail = tails.get(chain_id)
        if tail is None:
            if require_genesis and (seq != 1 or prev != GENESIS_HASH):
                result.errors.append(f"event {index} chain={chain_id} seq={seq}: chain does not start at genesis")
        else:
            if seq != tail[0] + 1:
                result.errors.append(f"event {index} chain={chain_id}: seq {seq} does not follow {tail[0]}")
            if prev != tail[1]:
                result.errors.append(f"event {index} chain={chain_id} seq={seq}: prev_hash does not match previous event")
        tails[chain_id] = (seq, digest)
    result.chains = tails
    result.ok = not result.errors
    return result


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".tmp-{path.name}")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def _safe_hostname() -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname())[:40] or "gateway"


class AuditEmitter:
    def __init__(
        self,
        *,
        spool_dir: Path,
        url: str,
        metrics: Metrics,
        max_events: int = 100_000,
        ssl_context: ssl.SSLContext | None = None,
        post_timeout_s: float = 5.0,
        backoff_base_s: float = 1.0,
        backoff_max_s: float = 60.0,
    ) -> None:
        self._dir = spool_dir
        self._url = url.rstrip("/")
        self._metrics = metrics
        self._max_events = max_events
        self._ssl = ssl_context
        self._post_timeout = post_timeout_s
        self._backoff_base = backoff_base_s
        self._backoff_max = backoff_max_s
        self._pending: deque[Path] = deque()
        self._chain: HashChain | None = None
        self._spool_n = 1
        self._chain_ok = True
        self._lock = asyncio.Lock()
        self._lock_fd: int | None = None
        self._wake = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._session: aiohttp.ClientSession | None = None
        self._last_send_ok: float = 0.0
        self._probe_at = 0.0
        self._probe_ok = False
        self._delivering = True

    @property
    def chain_id(self) -> str:
        assert self._chain is not None
        return self._chain.chain_id

    @property
    def chain_ok(self) -> bool:
        return self._chain_ok

    @property
    def spool_depth(self) -> int:
        return len(self._pending)

    def _set_chain_ok(self, ok: bool) -> None:
        self._chain_ok = ok
        self._metrics.audit_chain_ok.set(1 if ok else 0)

    def _set_depth(self) -> None:
        self._metrics.spool_depth.set(len(self._pending))

    def open(self) -> None:
        """Creates/locks the spool, loads chain state and recovers any events that were spooled but not yet acknowledged."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            (self._dir / QUARANTINE_DIR).mkdir(exist_ok=True)
            fd = os.open(str(self._dir / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise AuditSetupError(f"spool directory {self._dir} is not writable: {exc.strerror or exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise AuditSetupError(f"spool directory {self._dir} is locked by another process; one spool volume per replica") from exc
        self._lock_fd = fd

        for stale in self._dir.glob(".tmp-*"):
            with contextlib.suppress(OSError):
                stale.unlink()
        files = sorted(p for p in self._dir.iterdir() if _SPOOL_NAME.match(p.name))
        self._pending = deque(files)
        highest_n = max((int(_SPOOL_NAME.match(p.name).group(1)) for p in files), default=0)  # type: ignore[union-attr]

        state = self._load_state()
        pending_chained = self._pending_chained()
        if state is None:
            chain_id = f"{_safe_hostname()}-{os.urandom(4).hex()}"
            chain = HashChain(chain_id)
            if (self._dir / STATE_FILE).exists():
                self._set_chain_ok(False)
                log_event(LOG, logging.ERROR, "audit chain state unreadable; started a new chain", chain_id=chain_id)
            spool_n = 1
        else:
            chain = HashChain(state["chain_id"], state["seq"], state["prev_hash"])
            spool_n = state["spool_n"]

        mine = [e for e in pending_chained if e.get("chain_id") == chain.chain_id and isinstance(e.get("seq"), int) and isinstance(e.get("hash"), str)]
        if mine:
            verdict = verify_chain(mine)
            intact = verdict.ok
            # A crash between the spool write and the state write leaves spooled events newer than the state: adopt them.
            newer = [e for e in mine if e["seq"] > chain.seq]
            if newer:
                if newer[0]["seq"] != chain.seq + 1 or newer[0].get("prev_hash") != chain.prev_hash:
                    intact = False
                chain.seq, chain.prev_hash = int(newer[-1]["seq"]), str(newer[-1]["hash"])
            if not intact:
                self._set_chain_ok(False)
                log_event(LOG, logging.ERROR, "spooled audit events do not verify", chain_id=chain.chain_id, errors=verdict.errors[:5])
        self._chain = chain
        self._spool_n = max(spool_n, highest_n + 1)
        self._persist_state()
        self._set_depth()
        self._metrics.audit_chain_ok.set(1 if self._chain_ok else 0)

    def _load_state(self) -> dict[str, Any] | None:
        try:
            raw = json.loads((self._dir / STATE_FILE).read_text(encoding="utf-8"))
            if (isinstance(raw.get("chain_id"), str) and isinstance(raw.get("seq"), int) and isinstance(raw.get("prev_hash"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", raw["prev_hash"]) and isinstance(raw.get("spool_n"), int)):
                return raw
        except (OSError, ValueError, AttributeError):
            pass
        return None

    def _persist_state(self) -> None:
        assert self._chain is not None
        data = {"version": 1, "chain_id": self._chain.chain_id, "seq": self._chain.seq, "prev_hash": self._chain.prev_hash, "spool_n": self._spool_n}
        _atomic_write(self._dir / STATE_FILE, json.dumps(data, sort_keys=True).encode("ascii"))

    def _pending_chained(self) -> list[dict[str, Any]]:
        events = []
        for path in self._pending:
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if item.get("tag") in CHAINED_TAGS and isinstance(item.get("event"), dict):
                events.append(item["event"])
        return events

    async def start(self) -> None:
        if self._chain is None:
            self.open()
        timeout = aiohttp.ClientTimeout(total=self._post_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout, trust_env=False, connector=aiohttp.TCPConnector(ssl=self._ssl) if self._ssl else None)
        self._stop.clear()
        self._task = asyncio.create_task(self._sender(), name="audit-sender")
        if self._pending:
            self._wake.set()

    async def close(self, flush_timeout_s: float = 3.0) -> None:
        if self._task is not None:
            await self.flush(flush_timeout_s)
            self._stop.set()
            self._wake.set()
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._session is not None:
            await self._session.close()
            self._session = None
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            self._lock_fd = None

    async def emit(self, tag: str, event: Mapping[str, Any]) -> dict[str, Any]:
        """Seals (for chained tags), fsyncs into the spool and wakes the sender. Raises AuditUnavailable when not durable."""
        if tag not in ALL_TAGS:
            raise ValueError(f"unsupported audit tag {tag!r}")
        if self._chain is None:
            raise AuditUnavailable("audit emitter is not open")
        chained = tag in CHAINED_TAGS
        async with self._lock:
            if len(self._pending) >= self._max_events:
                if not chained:
                    self._metrics.audit_dropped_total.labels(tag=tag).inc()
                    return dict(event)
                raise AuditUnavailable("audit spool is full")
            payload = dict(event)
            payload.setdefault("@timestamp", utc_now_iso())
            sealed = self._chain.seal(payload) if chained else payload
            number = self._spool_n
            path = self._dir / f"ev-{number:016d}.json"
            blob = json.dumps({"tag": tag, "event": _normalise(sealed)}, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
            try:
                await asyncio.to_thread(self._write_durable, path, blob, number, sealed if chained else None)
            except OSError as exc:
                if chained:
                    self._set_chain_ok(False)
                raise AuditUnavailable(f"audit spool write failed: {exc.strerror or exc}") from exc
            if chained:
                self._chain.advance(sealed)
            self._spool_n = number + 1
            self._pending.append(path)
            self._set_depth()
            self._metrics.audit_events_total.labels(tag=tag).inc()
        self._wake.set()
        return _normalise(sealed)

    def _write_durable(self, path: Path, blob: bytes, number: int, sealed: Mapping[str, Any] | None) -> None:
        _atomic_write(path, blob)
        if sealed is not None:
            assert self._chain is not None
            data = {"version": 1, "chain_id": self._chain.chain_id, "seq": int(sealed["seq"]), "prev_hash": str(sealed["hash"]), "spool_n": number + 1}
            _atomic_write(self._dir / STATE_FILE, json.dumps(data, sort_keys=True).encode("ascii"))

    async def flush(self, timeout_s: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout_s
        self._wake.set()
        while self._pending and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        return not self._pending

    async def probe(self) -> bool:
        """Fluent Bit reachability: a recent successful POST, else a cached TCP connect."""
        now = time.monotonic()
        if not self._delivering:
            return False
        if self._last_send_ok and now - self._last_send_ok < 5.0:
            return True
        if self._probe_at and now - self._probe_at < 5.0:
            return self._probe_ok
        parts = urlsplit(self._url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(parts.hostname, port), timeout=1.0)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self._probe_ok = True
        except (OSError, asyncio.TimeoutError):
            self._probe_ok = False
        self._probe_at = now
        return self._probe_ok

    async def _post(self, tag: str, event: Mapping[str, Any]) -> int:
        assert self._session is not None
        body = json.dumps(event, ensure_ascii=True, allow_nan=False)
        async with self._session.post(f"{self._url}/{tag}", data=body, headers={"Content-Type": "application/json"}) as response:
            await response.read()
            return response.status

    def _quarantine(self, path: Path, tag: str | None) -> None:
        with contextlib.suppress(OSError):
            os.replace(path, self._dir / QUARANTINE_DIR / path.name)
        self._pending.popleft()
        self._set_depth()
        self._metrics.audit_quarantined_total.labels(tag=tag or "unknown").inc()
        if tag in CHAINED_TAGS or tag is None:
            self._set_chain_ok(False)
        log_event(LOG, logging.ERROR, "audit event quarantined", file=path.name, tag=tag)

    async def _sleep_or_stop(self, delay: float) -> None:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=delay)

    async def _sender(self) -> None:
        delay = self._backoff_base
        client_errors = 0
        while not self._stop.is_set():
            if not self._pending:
                self._wake.clear()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=2.0)
                continue
            path = self._pending[0]
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                tag, event = item["tag"], item["event"]
                if tag not in ALL_TAGS or not isinstance(event, dict):
                    raise ValueError("bad spool entry")
            except (OSError, ValueError, KeyError):
                self._quarantine(path, None)
                continue
            try:
                status = await self._post(tag, event)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._delivering = False
                log_event(LOG, logging.WARNING, "fluent-bit unreachable; will retry", error=type(exc).__name__, spool_depth=len(self._pending), retry_in_s=round(delay, 2))
                await self._sleep_or_stop(delay + random.uniform(0, delay / 4))
                delay = min(delay * 2, self._backoff_max)
                continue
            if 200 <= status < 300:
                with contextlib.suppress(OSError):
                    path.unlink()
                _fsync_quiet(self._dir)
                self._pending.popleft()
                self._set_depth()
                self._last_send_ok = time.monotonic()
                self._delivering = True
                delay, client_errors = self._backoff_base, 0
            elif status in (408, 425, 429) or status >= 500:
                self._delivering = False
                log_event(LOG, logging.WARNING, "fluent-bit rejected event; will retry", status=status, spool_depth=len(self._pending))
                await self._sleep_or_stop(delay + random.uniform(0, delay / 4))
                delay = min(delay * 2, self._backoff_max)
            else:
                client_errors += 1
                if client_errors >= MAX_CLIENT_ERRORS:
                    self._quarantine(path, tag)
                    client_errors = 0
                else:
                    await self._sleep_or_stop(self._backoff_base)


def _fsync_quiet(path: Path) -> None:
    with contextlib.suppress(OSError):
        _fsync_dir(path)
