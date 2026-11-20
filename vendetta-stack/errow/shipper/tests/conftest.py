"""Shared fixtures: a copy of the real-shape Errow run, a real SQLite agents.db, and a shipper factory.

Traces: PROMPT §2.3 (errow-shipper), CONTRACT §15.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import shipper as shp  # noqa: E402
import streams as S  # noqa: E402

FIXTURE_RUN = "scan-target-vendetta-lab_7f3a"
FIXTURES = HERE / "fixtures"

# openai-agents SQLiteSession schema (agents/memory/sqlite_session.py), as used by errow's .state/agents.db
AGENTS_DB_SCHEMA = """
CREATE TABLE agent_sessions (
    session_id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE agent_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    message_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES agent_sessions (session_id) ON DELETE CASCADE
);
CREATE INDEX idx_agent_messages_session_id ON agent_messages (session_id, id);
"""

LONG_OUTPUT = "A" * 9500

MESSAGES: list[tuple[str, dict, str]] = [
    ("agent-root-1", {"role": "system", "content": "You are errow. SYSTEM-PROMPT-MARKER internal instructions."}, "2026-11-12 09:10:00"),
    ("agent-root-1", {"role": "user", "content": "Assess http://scan-target.vendetta.lab with password=hunter2"}, "2026-11-12 09:10:01"),
    ("agent-root-1", {"type": "message", "role": "assistant",
                      "content": [{"type": "output_text", "text": "Starting recon.\n```bash\nnmap PAYLOAD-MARKER\n```\nDone."}]},
     "2026-11-12 09:10:02"),
    ("agent-root-1", {"type": "reasoning", "summary": [{"type": "summary_text", "text": "REASONING-MARKER"}]}, "2026-11-12 09:10:03"),
    ("agent-root-1", {"type": "function_call", "name": "terminal_execute", "call_id": "call_1",
                      "arguments": json.dumps({"command": "nmap -sT scan-target.vendetta.lab", "timeout": 60})},
     "2026-11-12 09:10:04"),
    ("agent-root-1", {"type": "function_call_output", "call_id": "call_1",
                      "output": "22/tcp open ssh\nAuthorization: Bearer sk-live-abcdef0123456789\n" + LONG_OUTPUT},
     "2026-11-12 09:10:05"),
    ("agent-root-1", {"type": "function_call", "name": "python_action", "call_id": "call_2",
                      "arguments": json.dumps({"action": "run", "code": "print('PAYLOAD-MARKER')"})},
     "2026-11-12 09:10:06"),
    ("agent-root-1", {"type": "function_call_output", "call_id": "call_2", "output": "ok\n"}, "2026-11-12 09:10:07"),
    ("agent-sub-2", {"role": "user", "content": "Test object level authorization on the orders API."}, "2026-11-12 09:40:00"),
    ("agent-sub-2", {"type": "message", "role": "assistant", "content": "Found a BOLA on /api/orders/{id}."}, "2026-11-12 09:41:00"),
]


def build_agents_db(path: Path, messages: list[tuple[str, dict, str]] | None = None) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(AGENTS_DB_SCHEMA)
        for agent_id in sorted({m[0] for m in (messages or MESSAGES)}):
            con.execute("INSERT INTO agent_sessions (session_id) VALUES (?)", (agent_id,))
        add_messages(con, messages or MESSAGES)
        con.commit()
    finally:
        con.close()


def add_messages(con: sqlite3.Connection, messages: list[tuple[str, dict, str]]) -> None:
    for session_id, item, created in messages:
        con.execute("INSERT INTO agent_messages (session_id, message_data, created_at) VALUES (?, ?, ?)",
                    (session_id, json.dumps(item), created))


@pytest.fixture
def runs_dir(tmp_path: Path) -> Path:
    root = tmp_path / "errow_runs"
    run = root / FIXTURE_RUN
    shutil.copytree(FIXTURES / FIXTURE_RUN, run)
    build_agents_db(run / ".state" / "agents.db")
    return root


@pytest.fixture
def run_dir(runs_dir: Path) -> Path:
    return runs_dir / FIXTURE_RUN


class Env:
    """Dirs + a Shipper factory; every ``make()`` is a fresh process over the same state."""

    def __init__(self, tmp_path: Path, runs: Path) -> None:
        self.runs = runs
        self.out = tmp_path / "out"
        self.state = tmp_path / "state"
        self.logs: list[dict] = []
        self.env = {
            "ERROW_RUNS_DIR": str(runs), "SHIPPER_OUT_DIR": str(self.out), "SHIPPER_STATE_DIR": str(self.state),
            "SHIPPER_RETRY_DELAY": "0", "errow_TELEMETRY": "true",
        }

    def log(self, level: str, msg: str, **fields) -> None:
        self.logs.append({"level": level, "msg": msg, **fields})

    def make(self, docker=None, sleep=None, **overrides: str) -> shp.Shipper:
        cfg = shp.Config.from_env({**self.env, **overrides})
        sh = shp.Shipper(cfg, log=self.log, docker=docker, sleep=sleep or (lambda _s: None))
        sh.setup()
        return sh

    def lines(self, stream: str) -> list[dict]:
        path = self.out / f"{stream}.ndjson"
        return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]

    def counts(self) -> dict[str, int]:
        return {s: len(self.lines(s)) for s in S.STREAMS}

    def delta(self, before: dict[str, int]) -> dict[str, int]:
        now = self.counts()
        return {s: now[s] - before[s] for s in S.STREAMS if now[s] != before[s]}

    def all_text(self) -> str:
        return "\n".join((self.out / f"{s}.ndjson").read_text("utf-8") for s in S.STREAMS)


@pytest.fixture
def env(tmp_path: Path, runs_dir: Path) -> Env:
    return Env(tmp_path, runs_dir)
