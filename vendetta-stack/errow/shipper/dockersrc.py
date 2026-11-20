"""Optional Docker API source for the errow shipper: Caido/sandbox container logs and lifecycle events.

Caido runs *inside* the per-run Errow sandbox containers on :48080 with ``--no-logging``, so there is no
Caido log file to tail; the only trace is the sandbox container's own stdout/stderr and the Docker events
for that container. When ``DOCKER_HOST`` is set (compose: errow-dind over TLS; ``DOCKER_TLS_VERIFY`` /
``DOCKER_CERT_PATH`` are honoured by ``docker.from_env``) the shipper reads both through the Docker API,
read-only, for containers labelled ``errow-run-id``. Without ``DOCKER_HOST`` (or without the SDK) the source
is disabled and the reason is logged once and reported in ``status.json``.

Lines are cursor-tracked per container, so a restart does not replay them, and ``doc_id`` is deterministic
(container id + timestamp + line hash) so a replay would dedupe anyway.

Limit: a sandbox removed (``AutoRemove``) between two polls takes its unread log lines with it.

Traces: PROMPT §2.3 (errow-shipper), CONTRACT §8.4 (``proxy``, ``runtime_events``), §15; errow/errow/runtime/docker_connection.py.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sanitize import sanitize_text
from store import sha256_hex
from streams import epoch_iso, make_record

RUN_LABEL = "errow-run-id"
LIFECYCLE_ACTIONS = frozenset({"create", "start", "die", "kill", "oom", "stop", "restart", "destroy", "health_status"})
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def norm_ts(value: str) -> str | None:
    """Docker log timestamps normalised to a fixed 9-digit fraction so they compare lexicographically."""
    m = _TS.match(value)
    if not m:
        return None
    return f"{m.group(1)}.{(m.group(2) or '').ljust(9, '0')[:9]}Z"


def split_log_line(raw: str) -> tuple[str, str] | None:
    head, _, text = raw.partition(" ")
    ts = norm_ts(head)
    return (ts, text) if ts else None


def _epoch(ts: str) -> int:
    return int(datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC).timestamp())


class DockerSource:
    def __init__(self, host: str, log: Callable[..., None], *, client_factory: Callable[[], Any] | None = None,
                 max_lines: int = 2000, timeout: int = 10) -> None:
        self.host = host
        self.log = log
        self.max_lines = max_lines
        self._factory = client_factory
        self._timeout = timeout
        self._client: Any = None
        self.enabled = bool(host) or client_factory is not None
        self.reason: str | None = None if self.enabled else "DOCKER_HOST is not set"
        self._announced: str | None = None
        if not self.enabled:
            self._announce("disabled", self.reason or "")

    def status(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "reason": self.reason}

    def _announce(self, kind: str, reason: str) -> None:
        marker = f"{kind}:{reason}"
        if marker != self._announced:
            self._announced = marker
            self.log("info" if kind == "disabled" else "warning", f"docker_source_{kind}", reason=reason)

    def _connect(self) -> Any:
        if self._client is None:
            if self._factory is not None:
                self._client = self._factory()
            else:
                import docker

                self._client = docker.from_env(timeout=self._timeout)
        return self._client

    def collect(self, dstate: dict[str, Any], now_epoch: float, run_names: dict[str, str]) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any]]:
        """Return ``(records, new_docker_state)``; ``dstate`` is never mutated and is returned unchanged on error."""
        if not self.enabled:
            return [], dstate
        try:
            client = self._connect()
            records, new_state = self._collect(client, dstate, now_epoch, run_names)
        except Exception as exc:  # docker.errors.*, requests.*, OSError: all mean "daemon not usable right now"
            self._client = None
            self.reason = f"{type(exc).__name__}: {sanitize_text(str(exc), 200)}"
            self._announce("error", self.reason)
            return [], dstate
        self.reason = None
        self._announced = None
        return records, new_state

    def _collect(self, client: Any, dstate: dict[str, Any], now_epoch: float, run_names: dict[str, str]):
        records: list[tuple[str, dict[str, Any]]] = []
        cursors: dict[str, Any] = dict(dstate.get("containers") or {})
        live: set[str] = set()
        for container in client.containers.list(all=True, filters={"label": RUN_LABEL}):
            cid = str(container.id)
            live.add(cid)
            labels = container.labels or {}
            run = run_names.get(str(labels.get(RUN_LABEL)), str(labels.get(RUN_LABEL)))
            attrs = container.attrs if isinstance(container.attrs, dict) else {}
            image = str((attrs.get("Config") or {}).get("Image") or "")
            cursor = cursors.get(cid) or {"ts": "", "seen": []}
            kwargs: dict[str, Any] = {"timestamps": True, "stdout": True, "stderr": True}
            if cursor["ts"]:
                kwargs["since"] = _epoch(cursor["ts"])
            else:
                kwargs["tail"] = self.max_lines
            raw = container.logs(**kwargs)
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
            lines = [p for p in (split_log_line(line) for line in text.splitlines()) if p]
            seen = set(cursor["seen"])
            fresh = [(ts, body) for ts, body in lines
                     if ts > cursor["ts"] or (ts == cursor["ts"] and sha256_hex(body)[:16] not in seen)]
            fresh.sort(key=lambda p: p[0])
            fresh = fresh[: self.max_lines]
            for ts, body in fresh:
                message = sanitize_text(_ANSI.sub("", body))
                doc_id = sha256_hex(f"{cid}|{ts}|{sha256_hex(body)}")
                records.append(("proxy", make_record("proxy", run, f"{ts[:23]}Z", doc_id, {
                    "level": "INFO", "tool": "caido", "container": str(container.name), "container_id": cid[:12],
                    "image": image, "port": 48080, "message": message,
                })))
            if fresh:
                last_ts = fresh[-1][0]
                same = [sha256_hex(b)[:16] for t, b in fresh if t == last_ts]
                keep = same + (cursor["seen"] if cursor["ts"] == last_ts else [])
                cursors[cid] = {"ts": last_ts, "seen": sorted(set(keep))[-64:]}
            else:
                cursors.setdefault(cid, cursor)
        cursors = {cid: c for cid, c in cursors.items() if cid in live}

        since = float(dstate.get("events_until") or max(0.0, now_epoch - 300))
        until = float(now_epoch)
        if until > since:
            stream = client.events(since=since, until=until, decode=True,
                                   filters={"type": "container", "label": RUN_LABEL})
            for event in stream:
                rec = self._event_record(event, run_names)
                if rec:
                    records.append(rec)
        return records, {"containers": cursors, "events_until": until}

    @staticmethod
    def _event_record(event: Any, run_names: dict[str, str]) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(event, dict):
            return None
        action = str(event.get("Action") or event.get("status") or "").split(":")[0]
        if action not in LIFECYCLE_ACTIONS:
            return None
        actor = event.get("Actor") if isinstance(event.get("Actor"), dict) else {}
        attrs = actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
        cid = str(actor.get("ID") or event.get("id") or "")
        run_id = str(attrs.get(RUN_LABEL) or "")
        run = run_names.get(run_id, run_id)
        nano = event.get("timeNano")
        when = float(event.get("time") or 0)
        ts = epoch_iso(float(nano) / 1e9 if isinstance(nano, int) else when)
        content: dict[str, Any] = {
            "level": "WARNING" if action in ("oom", "kill") else "INFO", "logger": "docker.events",
            "event_type": f"container_{action}", "action": action, "container": str(attrs.get("name") or ""),
            "container_id": cid[:12], "image": str(attrs.get("image") or ""),
            "run_type": attrs.get("errow-run-type"), "message": f"container {attrs.get('name') or cid[:12]} {action}",
        }
        if "exitCode" in attrs:
            content["exit_code"] = attrs["exitCode"]
        doc_id = sha256_hex(f"{cid}|{nano or when}|{action}")
        return "runtime_events", make_record("runtime_events", run, ts, doc_id, content)
