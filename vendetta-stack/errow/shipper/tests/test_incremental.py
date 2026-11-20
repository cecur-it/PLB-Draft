"""Idempotency, incremental diffs, half-written JSON, crash safety and rotation.

Traces: PROMPT §2.3 (errow-shipper: idempotent, crash-safe, tolerant of atomically replaced JSON, self-rotating),
CONTRACT §8.4, §15.
"""

from __future__ import annotations

import copy
import json
import os
import sqlite3
from pathlib import Path

import pytest
import store
import streams as S
from conftest import FIXTURE_RUN, MESSAGES, Env, add_messages


class Crash(BaseException):
    """Simulated process death (not an Exception, so nothing in the shipper can swallow it)."""


def replace_json(path: Path, doc) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc), "utf-8")
    os.replace(tmp, path)


def doc_ids(env: Env) -> dict[str, list[str]]:
    return {s: sorted(r["doc_id"] for r in env.lines(s)) for s in S.STREAMS}


def baseline(tmp_path: Path, runs_dir: Path, **overrides: str) -> dict[str, list[str]]:
    other = Env(tmp_path / "baseline", runs_dir)
    other.make(**overrides).once()
    return doc_ids(other)


def test_second_pass_and_a_restart_emit_nothing(env):
    env.make().once()
    before = env.counts()
    env.make().once()
    env.make().once()
    assert env.delta(before) == {}


def test_changed_run_json_emits_only_that_record(env, run_dir):
    env.make().once()
    before = env.counts()
    run = json.loads((run_dir / "run.json").read_text())
    run["llm_usage"]["requests"] = 43
    replace_json(run_dir / "run.json", run)
    env.make().once()
    assert env.delta(before) == {"runs": 1, "report_artifacts": 1}
    assert env.lines("runs")[-1]["llm_usage"]["requests"] == 43


def test_coverage_generated_at_alone_does_not_re_emit(env, run_dir):
    env.make().once()
    before = env.counts()
    cov = json.loads((run_dir / "coverage.json").read_text())
    cov["generated_at"] = "2026-11-12 11:00:00 UTC"
    replace_json(run_dir / "coverage.json", cov)
    env.make().once()
    assert env.delta(before) == {"report_artifacts": 1}
    cov["entries"][0]["outcome_label"] = "Ruled out"
    replace_json(run_dir / "coverage.json", cov)
    env.make().once()
    assert env.delta(before) == {"report_artifacts": 2, "coverage": 1}


def test_new_and_changed_findings_emit_only_the_difference(env, run_dir):
    env.make().once()
    before = env.counts()
    sarif = json.loads((run_dir / "findings.sarif").read_text())
    results = sarif["runs"][0]["results"]
    results[1]["message"]["text"] += " (updated)"
    extra = copy.deepcopy(results[0])
    extra["partialFingerprints"]["primaryLocationLineHash"] = "f00d" * 16
    extra["properties"]["errow"].update(id="vuln-0003", severity="low")
    results.insert(2, extra)
    replace_json(run_dir / "findings.sarif", sarif)
    env.make().once()
    assert env.delta(before) == {"findings": 2, "report_artifacts": 1, "telemetry": 1}
    new = env.lines("findings")[-2:]
    changed = next(f for f in new if f["ruleId"] == "CWE-639")
    original = next(f for f in env.lines("findings")[:2] if f["ruleId"] == "CWE-639")
    assert changed["doc_id"] == original["doc_id"] and changed["message"]["text"].endswith("(updated)")
    assert env.lines("telemetry")[-1]["properties"]["severity"] == "low"


def test_changed_threat_model_re_emits_only_that_entry(env, run_dir):
    env.make().once()
    before = env.counts()
    tms = json.loads((run_dir / ".state" / "threat_models.json").read_text())
    tms["scan-target.vendetta.lab:8443"]["amendments"] = [{"at": "2026-11-12T10:00:00+00:00", "by": "agent-1", "content": "more"}]
    replace_json(run_dir / ".state" / "threat_models.json", tms)
    env.make().once()
    assert env.delta(before) == {"threat_models": 1}
    assert env.lines("threat_models")[-1]["amendment_count"] == 1


def test_new_agent_messages_are_incremental(env, run_dir):
    env.make().once()
    before = env.counts()
    con = sqlite3.connect(run_dir / ".state" / "agents.db")
    add_messages(con, [("agent-sub-2", {"type": "message", "role": "assistant", "content": "One more."}, "2026-11-12 09:50:00")])
    con.commit()
    con.close()
    env.make().once()
    assert env.delta(before) == {"transcripts": 1, "agent_state": 1}
    assert env.lines("transcripts")[-1]["message_id"] == len(MESSAGES) + 1
    assert env.lines("agent_state")[-1]["messages"] == 3


def test_errow_log_is_tailed_incrementally_and_waits_for_complete_lines(env, run_dir):
    env.make().once()
    before = env.counts()
    log = run_dir / "errow.log"
    with log.open("a") as fh:
        fh.write("2026-11-12 09:11:00.000 INFO    - - errow.core.runner: part")
    env.make().once()
    assert env.delta(before) == {}
    with log.open("a") as fh:
        fh.write("ial\n2026-11-12 09:11:01.000 INFO    - - errow.interface.tui: tui resized\n")
    env.make().once()
    assert env.delta(before) == {"runtime_events": 1, "tui_events": 1}
    assert env.lines("runtime_events")[-1]["message"] == "partial"


def test_rotated_errow_log_is_read_from_the_start(env, run_dir):
    env.make().once()
    before = env.counts()
    log = run_dir / "errow.log"
    os.replace(log, run_dir / "errow.log.1")
    log.write_text("2026-11-12 09:12:00.000 INFO    - - errow.core.runner: fresh file\n")
    env.make().once()
    assert env.delta(before) == {"runtime_events": 1}


def test_line_budget_splits_a_backlog_without_losing_or_duplicating(tmp_path, runs_dir):
    want = baseline(tmp_path, runs_dir)
    env = Env(tmp_path / "budget", runs_dir)
    sh = env.make(SHIPPER_MAX_LINES_PER_CYCLE="2")
    first = sh.cycle()
    assert sh._more is True and sum(v["records"] for k, v in first.items() if k.endswith("events") or k == "llm_logs") < 8
    sh.once()
    assert doc_ids(env) == want
    assert any("Traceback" in r["message"] for r in env.lines("runtime_events"))


def test_unreadable_json_is_skipped_then_picked_up(env, run_dir):
    good = (run_dir / "run.json").read_text()
    (run_dir / "run.json").write_text(good[: len(good) // 2])
    sh = env.make()
    sh.cycle()
    assert env.lines("runs") == [] and sh.skipped == {"run.json": 1}
    assert any(entry["msg"] == "artifact_unreadable" for entry in env.logs)
    assert json.loads((env.state / "status.json").read_text())["skipped"] == {"run.json": 1}
    (run_dir / "run.json").write_text(good)
    sh.cycle()
    assert len(env.lines("runs")) == 1 and sh.skipped == {}
    assert [e["event"] for e in env.lines("telemetry")][0] == "scan_started"


def test_half_written_json_is_retried_once_within_the_same_pass(env, run_dir):
    good = (run_dir / "run.json").read_text()
    (run_dir / "run.json").write_text(good[:40])
    delays: list[float] = []

    def writer_finishes(delay: float) -> None:
        delays.append(delay)
        (run_dir / "run.json").write_text(good)

    sh = env.make(sleep=writer_finishes, SHIPPER_RETRY_DELAY="0.25")
    sh.cycle()
    assert delays == [0.25] and len(env.lines("runs")) == 1 and sh.skipped == {}


def test_symlinked_artifacts_and_runs_are_never_followed(env, run_dir, tmp_path):
    secret = tmp_path / "outside.json"
    secret.write_text(json.dumps({"schema_version": 1, "entries": [], "summary": {}, "scope": {}, "leak": "OUTSIDE"}))
    (run_dir / "coverage.json").unlink()
    (run_dir / "coverage.json").symlink_to(secret)
    (env.runs / "linked-run").symlink_to(tmp_path)
    sh = env.make()
    sh.once()
    assert env.lines("coverage") == [] and "OUTSIDE" not in env.all_text()
    assert {r["run"] for s in S.STREAMS for r in env.lines(s)} == {FIXTURE_RUN}


# ---------------------------------------------------------------- crash safety
@pytest.fixture
def clean(tmp_path, runs_dir):
    return baseline(tmp_path, runs_dir)


def recovered(env: Env, clean_ids: dict[str, list[str]], outcome: str) -> None:
    sh = env.make()
    assert [e for e in env.logs if e["msg"] == "started"][-1]["recovered"] == outcome
    sh.once()
    assert doc_ids(env) == clean_ids  # exactly once: nothing lost, nothing duplicated
    for s in S.STREAMS:
        for line in (env.out / f"{s}.ndjson").read_text("utf-8").splitlines():
            json.loads(line)  # no torn line survives
    before = env.counts()
    env.make().once()
    assert env.delta(before) == {}


def test_crash_after_wal_before_any_append(env, clean, monkeypatch):
    sh = env.make()

    def die(self, stream, payload):
        raise Crash

    with monkeypatch.context() as m, pytest.raises(Crash):
        m.setattr(store.Sink, "_append", die)
        sh.once()
    assert json.loads((env.state / "state.json").read_text())["inflight"] is not None
    recovered(env, clean, "rolled_back")


def test_crash_after_append_before_state_commit(env, clean, monkeypatch):
    sh = env.make()
    real_save = store.State.save
    calls = {"n": 0}

    def flaky(self):
        calls["n"] += 1
        if calls["n"] == 2:  # 1 = write-ahead marker, 2 = commit
            raise Crash
        real_save(self)

    with monkeypatch.context() as m, pytest.raises(Crash):
        m.setattr(store.State, "save", flaky)
        sh.once()
    assert sum(len(env.lines(s)) for s in S.STREAMS) == sum(len(v) for v in clean.values())
    recovered(env, clean, "committed")


def test_crash_with_a_torn_append(env, clean, monkeypatch):
    sh = env.make()

    def torn(self, stream, payload):
        fd = os.open(self.path(stream), os.O_WRONLY | os.O_APPEND)
        os.write(fd, payload[: len(payload) // 2])
        os.close(fd)
        raise Crash

    with monkeypatch.context() as m, pytest.raises(Crash):
        m.setattr(store.Sink, "_append", torn)
        sh.once()
    assert any(not (env.out / f"{s}.ndjson").read_bytes().endswith(b"\n")
               for s in S.STREAMS if (env.out / f"{s}.ndjson").stat().st_size)
    recovered(env, clean, "rolled_back")


def test_crash_between_streams_rolls_back_the_streams_already_written(env, clean, monkeypatch):
    sh = env.make()
    real_append = store.Sink._append
    calls = {"n": 0}

    def second_dies(self, stream, payload):
        calls["n"] += 1
        if calls["n"] == 2:
            raise Crash
        real_append(self, stream, payload)

    with monkeypatch.context() as m, pytest.raises(Crash):
        m.setattr(store.Sink, "_append", second_dies)
        sh.once()
    recovered(env, clean, "rolled_back")


def test_corrupt_state_file_is_quarantined_and_rebuilt(env):
    env.make().once()
    (env.state / "state.json").write_text("{not json")
    env.make()
    assert (env.state / "state.json.corrupt").read_text() == "{not json"
    assert any(e["msg"] == "state_corrupt" for e in env.logs)


# ---------------------------------------------------------------- rotation
def test_streams_rotate_by_size_with_rename_and_keep_n(env, run_dir):
    sh = env.make(SHIPPER_MAX_BYTES="2048", SHIPPER_KEEP="2")
    sh.once()
    base = env.out / "transcripts.ndjson"
    con = sqlite3.connect(run_dir / ".state" / "agents.db")
    inodes = []
    for n in range(12):
        inodes.append(base.stat().st_ino)
        add_messages(con, [("agent-root-1", {"role": "user", "content": f"msg-{n} " + "x" * 400}, "2026-11-12 09:30:00")])
        con.commit()
        sh.cycle()
    con.close()
    names = sorted(p.name for p in env.out.glob("transcripts.ndjson*"))
    assert names == ["transcripts.ndjson", "transcripts.ndjson.1", "transcripts.ndjson.2"]
    assert (env.out / "transcripts.ndjson.1").stat().st_ino in set(inodes)  # renamed, not copied
    assert (env.out / "transcripts.ndjson.2").stat().st_ino in set(inodes)
    assert base.stat().st_ino != (env.out / "transcripts.ndjson.1").stat().st_ino and base.stat().st_size <= 2048
    kept = [json.loads(line) for n in names for line in (env.out / n).read_text().splitlines()]
    ids = [r["message_id"] for r in kept]
    assert max(ids) == len(MESSAGES) + 12 and len(ids) == len(set(ids)) and len(ids) < 12 + len(MESSAGES)
    assert any(e["msg"] == "stream_rotated" for e in env.logs)


def test_rotation_leaves_the_next_pass_idempotent(env, run_dir):
    sh = env.make(SHIPPER_MAX_BYTES="1024", SHIPPER_KEEP="3")
    sh.once()
    before = env.counts()
    env.make(SHIPPER_MAX_BYTES="1024", SHIPPER_KEEP="3").once()
    assert env.delta(before) == {}
