#!/usr/bin/env python3
"""errow-shipper: Errow run artifacts -> NDJSON streams for Fluent Bit.

Errow writes its run artifacts as atomically *rewritten* JSON files (run.json, vulnerabilities.json,
findings.sarif, coverage.json, .state/threat_models.json, .state/agents.json) plus an append-only
errow.log and a SQLite agents.db. Nothing is JSONL, so this service watches ``ERROW_RUNS_DIR`` read-only
and turns every change into append-only NDJSON under ``SHIPPER_OUT_DIR`` (``<stream>.ndjson``, 16 streams,
record shapes per CONTRACT §15), which Fluent Bit tails.

* Idempotent: a content-hash/cursor state (``state.json``, atomic) means an unchanged file emits nothing and
  a changed file emits only the changed records; ``doc_id`` is deterministic so a crash can only repeat.
* Exploit payloads never leave: ``poc_script_code`` is dropped everywhere, vulnerabilities.json and the
  per-finding Markdown are only hashed, fenced code is elided, tool-call code/payload arguments are omitted.
* Secrets are redacted and long strings truncated with the same algorithm as the edge Lua filter.
* ``mcp_events.ndjson`` is created but never written here (errow-mcp and the gateway write it).

Usage: ``shipper.py [--once] | --healthcheck | --selftest | --version``.

Traces: PROMPT §2.3 (errow-shipper), CONTRACT §2 (paths), §8.4 (stream names), §11, §12, §15.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import signal
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import streams as S
from dockersrc import DockerSource
from sanitize import redact, sanitize_text
from store import Sink, State, atomic_write, open_regular, read_json_stable, sha256_hex

VERSION = "1.0.0"
COMPONENT = "errow-shipper"
FALSEY = frozenset({"0", "false", "f", "no", "n", "off"})
TOOL_NAME_CAP = 20000
LOG_READ_CAP = 8 * 1024 * 1024
LOG_HEAD_BYTES = 256
ARTIFACT_MAX_DEPTH = 3


def make_logger(out: Any = None) -> Callable[..., None]:
    def log(level: str, msg: str, **fields: Any) -> None:
        rec: dict[str, Any] = {"ts": S.now_iso(), "level": level.upper(), "component": COMPONENT, "msg": msg}
        for key, value in fields.items():
            rec[key] = sanitize_text(value, 500) if isinstance(value, str) else value
        stream = out if out is not None else sys.stdout
        stream.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
        stream.flush()

    return log


def _int(env: dict[str, str], key: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(env.get(key, "") or default))
    except ValueError:
        return default


def _float(env: dict[str, str], key: str, default: float) -> float:
    try:
        return max(0.0, float(env.get(key, "") or default))
    except ValueError:
        return default


def _flag(env: dict[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    return default if raw is None or raw.strip() == "" else raw.strip().lower() not in FALSEY


@dataclass(frozen=True)
class Config:
    runs_dir: Path
    out_dir: Path
    state_dir: Path
    interval: float
    max_bytes: int
    keep: int
    max_line_bytes: int
    max_file_bytes: int
    retry_delay: float
    max_lines: int
    max_messages: int
    include_coverage: bool
    telemetry: bool
    health_max_age: int
    docker_host: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        e = dict(os.environ if env is None else env)
        return cls(
            runs_dir=Path(e.get("ERROW_RUNS_DIR") or "/workspace/errow_runs"),
            out_dir=Path(e.get("SHIPPER_OUT_DIR") or "/var/log/errow"),
            state_dir=Path(e.get("SHIPPER_STATE_DIR") or "/var/lib/errow-shipper"),
            interval=_float(e, "SHIPPER_INTERVAL", 10.0),
            max_bytes=_int(e, "SHIPPER_MAX_BYTES", 52428800, 1024),
            keep=_int(e, "SHIPPER_KEEP", 5, 1),
            max_line_bytes=_int(e, "SHIPPER_MAX_LINE_BYTES", 262144, 1024),
            max_file_bytes=_int(e, "SHIPPER_MAX_FILE_BYTES", 64 * 1024 * 1024, 1024),
            retry_delay=_float(e, "SHIPPER_RETRY_DELAY", 0.25),
            max_lines=_int(e, "SHIPPER_MAX_LINES_PER_CYCLE", 5000, 1),
            max_messages=_int(e, "SHIPPER_MAX_MESSAGES_PER_CYCLE", 5000, 1),
            include_coverage=_flag(e, "SHIPPER_INCLUDE_COVERAGE_RESULTS", False),
            telemetry=_flag(e, "errow_TELEMETRY", True) and _flag(e, "SHIPPER_TELEMETRY_MIRROR", True),
            health_max_age=_int(e, "SHIPPER_HEALTH_MAX_AGE", 120, 5),
            docker_host=(e.get("DOCKER_HOST") or "").strip(),
        )


class Shipper:
    def __init__(self, cfg: Config, *, log: Callable[..., None] | None = None, docker: DockerSource | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.log = log or make_logger()
        self.sleep = sleep
        self.clock = clock
        self.state = State(cfg.state_dir / "state.json", self.log)
        self.sink = Sink(cfg.out_dir, S.STREAMS, self.state, max_bytes=cfg.max_bytes, keep=cfg.keep,
                         max_line_bytes=cfg.max_line_bytes, log=self.log)
        self.docker = docker or DockerSource(cfg.docker_host, self.log)
        self.stop = threading.Event()
        self.cycles = 0
        self.errors = 0
        self.last_ok: float | None = None
        self.pending_since: float | None = None
        self.skipped: dict[str, int] = {}
        self.sources: dict[str, Any] = {}
        self._more = False
        self._pending = False

    # ------------------------------------------------------------------ lifecycle
    def setup(self) -> None:
        for directory in (self.cfg.out_dir, self.cfg.state_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.state.load()
        outcome = self.sink.recover()
        self.sink.ensure_files()
        self.log("info", "started", version=VERSION, runs_dir=str(self.cfg.runs_dir), out_dir=str(self.cfg.out_dir),
                 recovered=outcome, telemetry_mirror=self.cfg.telemetry, docker=self.docker.status())

    def once(self, max_passes: int = 200) -> dict[str, int]:
        """Cycle until nothing is left to do (budgets can split a backlog over several passes)."""
        totals: dict[str, int] = {}
        for _ in range(max_passes):
            stats = self.cycle()
            for stream, st in stats.items():
                totals[stream] = totals.get(stream, 0) + st["records"]
            if not self._more:
                break
        return totals

    def run_forever(self) -> None:
        while not self.stop.is_set():
            try:
                self.cycle()
            except Exception as exc:  # keep shipping: one bad cycle must not stop the service
                self.errors += 1
                self.log("error", "cycle_failed", error=f"{type(exc).__name__}: {exc}")
                self.write_status()
            self.stop.wait(0 if self._more else self.cfg.interval)

    # ------------------------------------------------------------------ one pass
    def cycle(self) -> dict[str, dict[str, int]]:
        started = self.clock()
        now = S.epoch_iso(started)
        self.cycles += 1
        self._more = False
        self._pending = False
        self.skipped = {}
        nxt = copy.deepcopy(self.state.data)
        batch: dict[str, list[dict[str, Any]]] = {s: [] for s in S.SHIPPER_WRITES}
        run_names: dict[str, str] = {}
        run_dirs = self._run_dirs()
        for run_dir in run_dirs:
            self._process_run(run_dir, nxt, batch, now, run_names)
        for stream, record in self._docker_records(nxt, started, run_names):
            batch[stream].append(record)
        stats = self.sink.commit(batch, nxt)
        self._bump_counts(stats, now)
        self.last_ok = started
        self.pending_since = (self.pending_since or started) if (self._pending or self._more) else None
        self.write_status(len(run_dirs))
        for stream, st in stats.items():
            if st["records"]:
                self.log("info", "emitted", stream=stream, records=st["records"], bytes=st["bytes"])
        return stats

    def _docker_records(self, nxt: dict[str, Any], started: float, run_names: dict[str, str]):
        records, new_state = self.docker.collect(nxt.get("docker") or {}, started, run_names)
        nxt["docker"] = new_state
        self.sources["docker"] = self.docker.status()
        return records

    def _bump_counts(self, stats: dict[str, dict[str, int]], now: str) -> None:
        counts = self.state.data.setdefault("counts", {})
        for stream, st in stats.items():
            if st["records"]:
                cur = counts.setdefault(stream, {"records": 0, "bytes": 0, "last_emit": None})
                cur["records"] += st["records"]
                cur["bytes"] += st["bytes"]
                cur["last_emit"] = now
        if stats:
            self.state.save()

    def _run_dirs(self) -> list[Path]:
        try:
            entries = sorted(self.cfg.runs_dir.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            self.sources["runs_dir"] = {"readable": False, "reason": f"{type(exc).__name__}"}
            return []
        self.sources["runs_dir"] = {"readable": True, "reason": None}
        return [p for p in entries if not p.name.startswith(".") and p.is_dir() and not p.is_symlink()]

    def _skip(self, what: str) -> None:
        self.skipped[what] = self.skipped.get(what, 0) + 1
        self._pending = True

    def _read(self, path: Path, name: str) -> tuple[str, Any, str]:
        status, value, sha = read_json_stable(path, max_bytes=self.cfg.max_file_bytes, retry_delay=self.cfg.retry_delay,
                                              sleep=self.sleep)
        if status == "unreadable":
            self._skip(name)
            self.log("warning", "artifact_unreadable", artifact=name, run=path.parent.name)
        return status, value, sha

    # ------------------------------------------------------------------ one run directory
    def _process_run(self, run_dir: Path, nxt: dict[str, Any], batch: dict[str, list[dict[str, Any]]], now: str,
                     run_names: dict[str, str]) -> None:
        run = run_dir.name
        hashes: dict[str, str] = nxt["hashes"].setdefault(run, {})
        cursors: dict[str, Any] = nxt["cursors"].setdefault(run, {})

        status, run_json, _ = self._read(run_dir / "run.json", "run.json")
        run_doc: dict[str, Any] = run_json if status == "ok" and isinstance(run_json, dict) else {}
        for key in ("run_id", "run_name"):
            if isinstance(run_doc.get(key), str):
                run_names[run_doc[key]] = run
        if run_doc:
            rec = S.run_record(run, run_doc, now)
            if rec and hashes.get("run.json") != rec[0]:
                hashes["run.json"] = rec[0]
                batch["runs"].append(rec[1])

        finding_counts, new_findings = self._findings(run_dir, run, nxt, batch, now)
        status, cov, _ = self._read(run_dir / "coverage.json", "coverage.json")
        if status == "ok":
            crec = S.coverage_record(run, cov, now)
            if crec and hashes.get("coverage.json") != crec[0]:
                hashes["coverage.json"] = crec[0]
                batch["coverage"].append(crec[1])

        state_dir = run_dir / ".state"
        status, tms, _ = self._read(state_dir / "threat_models.json", "threat_models.json")
        if status == "ok":
            known = nxt["threat_models"].setdefault(run, {})
            for identity, h, rec in S.threat_model_records(run, tms, now):
                if known.get(identity) != h:
                    known[identity] = h
                    batch["threat_models"].append(rec)

        self._agents(state_dir, run, run_doc, nxt, batch, now, cursors)
        self._errow_log(run_dir / "errow.log", run, cursors, batch, now)
        self._artifacts(run_dir, run, cursors, batch, now)
        if self.cfg.telemetry and run_doc:
            self._telemetry(run, run_doc, finding_counts, new_findings, nxt, batch, now)

    def _findings(self, run_dir: Path, run: str, nxt: dict[str, Any], batch: dict[str, list[dict[str, Any]]],
                  now: str) -> tuple[dict[str, int], list[dict[str, Any]]]:
        """Emit new/changed findings; returns ``(severity_counts, newly_seen_records)`` for the telemetry mirror."""
        tele: dict[str, Any] = nxt["telemetry"].setdefault(run, {})
        status, sarif, _ = self._read(run_dir / "findings.sarif", "findings.sarif")
        if status != "ok":
            return dict(tele.get("counts") or {}), []
        known: dict[str, str] = nxt["findings"].setdefault(run, {})
        counts: dict[str, int] = {}
        new_recs: list[dict[str, Any]] = []
        for doc_id, h, rec in S.finding_records(run, sarif, now, include_coverage=self.cfg.include_coverage):
            props = rec.get("properties") if isinstance(rec.get("properties"), dict) else {}
            errow = props.get("errow") if isinstance(props.get("errow"), dict) else {}
            if "coverage_outcome" not in errow:
                sev = str(errow.get("severity") or "info").lower()
                counts[sev] = counts.get(sev, 0) + 1
            if known.get(doc_id) == h:
                continue
            if doc_id not in known:
                new_recs.append(rec)
            known[doc_id] = h
            batch["findings"].append(rec)
        tele["counts"] = counts
        return counts, new_recs

    def _telemetry(self, run: str, run_doc: dict[str, Any], counts: dict[str, int], new_findings: list[dict[str, Any]],
                   nxt: dict[str, Any], batch: dict[str, list[dict[str, Any]]], now: str) -> None:
        tele = nxt["telemetry"].setdefault(run, {})
        seen = tele.setdefault("seen", {})
        emitted = tele.setdefault("emitted", [])
        for event, props in S.telemetry_events(run, run_doc, new_findings, counts, seen):
            name = event.split(":", 1)[0]
            if event in emitted:
                continue
            emitted.append(event)
            if name == "scan_started":
                seen["started"] = True
            elif name == "scan_ended":
                seen["ended"] = True
            stamp = (S.parse_ts(run_doc.get("start_time")) if name == "scan_started"
                     else S.parse_ts(run_doc.get("end_time")) if name == "scan_ended" else None) or now
            batch["telemetry"].append(S.make_record("telemetry", run, stamp, sha256_hex(run + "telemetry" + event), {
                "event": name, "properties": S.scrub(props), "mirrored": True,
                "derived_from": "run artifacts (Errow keeps no local telemetry file)",
            }))
        del emitted[:-5000]

    # ------------------------------------------------------------------ agents.json + agents.db
    def _agents(self, state_dir: Path, run: str, run_doc: dict[str, Any], nxt: dict[str, Any],
                batch: dict[str, list[dict[str, Any]]], now: str, cursors: dict[str, Any]) -> None:
        status, graph, _ = self._read(state_dir / "agents.json", "agents.json")
        graph_doc: dict[str, Any] = graph if status == "ok" and isinstance(graph, dict) else {}
        usage = run_doc.get("llm_usage") if isinstance(run_doc.get("llm_usage"), dict) else {}
        usage_agents = usage.get("agents") if isinstance(usage.get("agents"), list) else []
        names = dict(graph_doc.get("names") or {}) if isinstance(graph_doc.get("names"), dict) else {}
        for u in usage_agents:
            if isinstance(u, dict) and u.get("agent_id") and u.get("agent_name"):
                names.setdefault(str(u["agent_id"]), str(u["agent_name"]))

        db_path = state_dir / "agents.db"
        db_stats: dict[str, dict[str, Any]] = {}
        rows: list[tuple[int, str, Any, Any]] = []
        cur = cursors.setdefault("agents.db", {"last_id": 0})
        if db_path.exists() or db_path.is_symlink():
            result = self._read_db(db_path, int(cur.get("last_id") or 0))
            if result is not None:
                db_stats, rows, max_id = result
                cur["last_id"] = min(int(cur.get("last_id") or 0), max_id)
        if status == "ok" or db_stats or usage_agents:
            known = nxt["agent_state"].setdefault(run, {})
            for agent_id, h, rec in S.agent_state_records(run, graph_doc, usage_agents, db_stats, now):
                if known.get(agent_id) != h:
                    known[agent_id] = h
                    batch["agent_state"].append(rec)
        tool_names: dict[str, str] = nxt["tool_names"]
        for row_id, session_id, raw, created in rows:
            for stream, rec in S.message_records(run, row_id, session_id, created, raw,
                                                 str(names.get(session_id) or session_id), tool_names, now):
                batch[stream].append(rec)
            cur["last_id"] = row_id
        if len(rows) >= self.cfg.max_messages:
            self._more = True
        while len(tool_names) > TOOL_NAME_CAP:
            tool_names.pop(min(tool_names))

    def _read_db(self, path: Path, after_id: int) -> tuple[dict[str, dict[str, Any]], list[tuple[int, str, Any, Any]], int] | None:
        try:
            os.close(open_regular(path))
        except OSError as exc:
            self._skip("agents.db")
            self.log("warning", "agents_db_unreadable", reason=type(exc).__name__)
            return None
        base = f"file:{quote(str(path))}?mode=ro"
        last_exc: Exception | None = None
        for uri in (base, base + "&immutable=1"):
            try:
                con = sqlite3.connect(uri, uri=True, timeout=2.0)
            except sqlite3.Error as exc:
                last_exc = exc
                continue
            try:
                con.execute("PRAGMA query_only=ON")
                stats = {
                    str(sid): {"messages": int(n), "last_message_at": S.parse_ts(last)}
                    for sid, n, last in con.execute(
                        "SELECT session_id, COUNT(*), MAX(created_at) FROM agent_messages GROUP BY session_id")
                }
                max_id = int(con.execute("SELECT COALESCE(MAX(id), 0) FROM agent_messages").fetchone()[0])
                rows = [(int(i), str(s), d, c) for i, s, d, c in con.execute(
                    "SELECT id, session_id, message_data, created_at FROM agent_messages WHERE id > ? ORDER BY id LIMIT ?",
                    (after_id if after_id <= max_id else 0, self.cfg.max_messages))]
                return stats, rows, max_id
            except sqlite3.Error as exc:
                last_exc = exc
            finally:
                con.close()
        self._skip("agents.db")
        self.log("warning", "agents_db_unreadable", reason=type(last_exc).__name__ if last_exc else "unknown")
        return None

    # ------------------------------------------------------------------ errow.log
    def _errow_log(self, path: Path, run: str, cursors: dict[str, Any], batch: dict[str, list[dict[str, Any]]],
                   now: str) -> None:
        try:
            fd = open_regular(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            self._skip("errow.log")
            self.log("warning", "errow_log_unreadable", run=run, reason=type(exc).__name__)
            return
        try:
            st = os.fstat(fd)
            cur = cursors.get("errow.log") or {"ino": st.st_ino, "offset": 0, "head": "", "head_len": 0}
            offset = int(cur["offset"])
            restart = cur["ino"] != st.st_ino or st.st_size < offset
            if not restart and cur["head_len"]:
                restart = sha256_hex(os.pread(fd, cur["head_len"], 0)) != cur["head"]
            if restart:
                offset = 0
            data = os.pread(fd, LOG_READ_CAP, offset)
            overlong = len(data) == LOG_READ_CAP and b"\n" not in data  # one line bigger than the read window
            if overlong:
                lines_raw = [data]
            else:
                cut = data.rfind(b"\n") + 1
                lines_raw = data[:cut].split(b"\n")[:-1] if cut else []
            lines: list[tuple[int, str]] = []
            pos = offset
            headers = 0
            for raw in lines_raw:
                text = raw.decode("utf-8", errors="replace").rstrip("\r")
                is_header = S.parse_log_line(text) is not None
                # stop only at a record boundary so a traceback is never split across passes
                if headers >= self.cfg.max_lines and is_header:
                    self._more = True
                    break
                headers += is_header
                lines.append((pos, text))
                pos += len(raw) + (0 if overlong else 1)
            consumed = pos - offset
            head_len = min(LOG_HEAD_BYTES, st.st_size)
            head = sha256_hex(os.pread(fd, head_len, 0)) if head_len else ""
        finally:
            os.close(fd)
        for stream, rec in S.log_events(run, lines, now):
            batch[stream].append(rec)
        cursors["errow.log"] = {"ino": st.st_ino, "offset": offset + consumed, "head": head, "head_len": head_len}

    # ------------------------------------------------------------------ report artifacts (hash only)
    def _artifacts(self, run_dir: Path, run: str, cursors: dict[str, Any], batch: dict[str, list[dict[str, Any]]],
                   now: str) -> None:
        cache: dict[str, Any] = cursors.setdefault("artifacts", {})
        present: set[str] = set()
        for rel, path in self._walk(run_dir):
            present.add(rel)
            try:
                st = path.lstat()
            except OSError:
                continue
            entry = cache.get(rel)
            if entry and entry["size"] == st.st_size and entry["mtime"] == st.st_mtime_ns:
                continue
            sha = self._hash_file(path, st)
            if sha is None:
                self._skip("artifact")
                continue
            if not entry or entry["sha"] != sha:
                batch["report_artifacts"].append(S.artifact_record(run, rel, sha, st.st_size, now))
            cache[rel] = {"size": st.st_size, "mtime": st.st_mtime_ns, "sha": sha}
        for rel in [r for r in cache if r not in present]:
            del cache[rel]

    def _walk(self, root: Path):
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                if entry.name.startswith(".") or entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 < ARTIFACT_MAX_DEPTH:
                        stack.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False) and S.artifact_kind(entry.name):
                    yield Path(entry.path).relative_to(root).as_posix(), Path(entry.path)

    @staticmethod
    def _hash_file(path: Path, before: os.stat_result) -> str | None:
        digest = hashlib.sha256()
        try:
            fd = open_regular(path)
        except OSError:
            return None
        try:
            while chunk := os.read(fd, 1 << 20):
                digest.update(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
            return None
        return digest.hexdigest()

    # ------------------------------------------------------------------ status.json
    def write_status(self, runs: int | None = None) -> None:
        now = self.clock()
        counts = self.state.data.get("counts", {})
        sizes = self.sink.sizes()
        streams = {
            s: {
                "records_total": int((counts.get(s) or {}).get("records", 0)),
                "bytes_total": int((counts.get(s) or {}).get("bytes", 0)),
                "last_emit": (counts.get(s) or {}).get("last_emit"),
                "file_bytes": sizes.get(s, 0),
            }
            for s in S.STREAMS
        }
        doc = {
            "component": COMPONENT, "version": VERSION, "ts": S.epoch_iso(now), "ts_epoch": round(now, 3),
            "last_ok": S.epoch_iso(self.last_ok) if self.last_ok else None,
            "last_ok_epoch": round(self.last_ok, 3) if self.last_ok else None,
            "lag_seconds": round(max(0.0, now - self.pending_since), 3) if self.pending_since else 0.0,
            "cycles": self.cycles, "errors": self.errors, "runs": runs, "streams": streams,
            "sources": self.sources, "skipped": self.skipped,
            "telemetry_mirror": self.cfg.telemetry,
        }
        try:
            atomic_write(self.cfg.state_dir / "status.json", json.dumps(doc, separators=(",", ":")).encode("utf-8"), 0o644)
        except OSError as exc:
            self.log("warning", "status_write_failed", reason=type(exc).__name__)


# ---------------------------------------------------------------------- CLI
def healthcheck(cfg: Config, clock: Callable[[], float] = time.time) -> int:
    try:
        doc = json.loads((cfg.state_dir / "status.json").read_text("utf-8"))
        age = clock() - float(doc["ts_epoch"])
        ok_age = clock() - float(doc["last_ok_epoch"])
    except (OSError, ValueError, KeyError, TypeError):
        return 1
    return 0 if age <= cfg.health_max_age and ok_age <= cfg.health_max_age * 5 else 1


def selftest(cfg: Config) -> int:
    problems: list[str] = []
    probe = redact("Authorization: Bearer abc.def password=hunter2")
    if "hunter2" in probe or "abc.def" in probe:
        problems.append("redaction")
    if S.parse_log_line("2026-01-02 03:04:05.678 INFO    - - errow.core: hello") is None:
        problems.append("log_parser")
    for label, directory in (("out_dir", cfg.out_dir), ("state_dir", cfg.state_dir)):
        try:
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / f".selftest.{os.getpid()}"
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            target.unlink()
        except OSError as exc:
            problems.append(f"{label}_not_writable:{type(exc).__name__}")
    if not cfg.runs_dir.is_dir():
        problems.append("runs_dir_missing")
    sys.stdout.write(json.dumps({"selftest": "fail" if problems else "ok", "problems": problems, "uid": os.getuid(),
                                 "runs_dir": str(cfg.runs_dir)}) + "\n")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=COMPONENT, description="Errow run artifacts -> NDJSON streams for Fluent Bit.")
    parser.add_argument("--once", action="store_true", help="ship everything pending, then exit")
    parser.add_argument("--healthcheck", action="store_true", help="exit 0 when status.json is fresh")
    parser.add_argument("--selftest", action="store_true", help="check sanitiser, parser and directories")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    cfg = Config.from_env()
    if args.version:
        sys.stdout.write(f"{COMPONENT} {VERSION}\n")
        return 0
    if args.healthcheck:
        return healthcheck(cfg)
    if args.selftest:
        return selftest(cfg)
    shipper = Shipper(cfg)
    shipper.setup()
    if args.once:
        shipper.once()
        return 0
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: shipper.stop.set())
    shipper.run_forever()
    shipper.log("info", "stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
