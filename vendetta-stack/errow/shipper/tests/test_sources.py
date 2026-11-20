"""Docker source (fake client), read-only agents.db access, status.json, health check, config and CLI.

Traces: PROMPT §2.3 (errow-shipper: Caido/runtime capture via the Docker API, agents.db mode=ro, status.json for
Fluent Bit's exec input), CONTRACT §8.4, §11, §15.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest
import shipper as shp
from conftest import FIXTURE_RUN
from dockersrc import DockerSource, norm_ts

CID = "c0ffee" * 10 + "abcd"


class FakeContainer:
    def __init__(self, logs: bytes, run: str = FIXTURE_RUN, name: str = "errow-sandbox-1") -> None:
        self.id = CID
        self.name = name
        self.labels = {"errow-run-id": run}
        self.attrs = {"Config": {"Image": "errow-sandbox:1.1.0"}}
        self.log_bytes = logs
        self.log_calls: list[dict] = []

    def logs(self, **kwargs):
        self.log_calls.append(kwargs)
        return self.log_bytes


class FakeClient:
    def __init__(self, container: FakeContainer, events: list[dict] | None = None) -> None:
        self.container = container
        self.event_list = events or []
        self.event_calls: list[dict] = []
        self.list_calls: list[dict] = []
        self.containers = SimpleNamespace(list=self._list)

    def _list(self, **kwargs):
        self.list_calls.append(kwargs)
        return [self.container]

    def events(self, **kwargs):
        self.event_calls.append(kwargs)
        return iter(self.event_list)


CAIDO_LOG = (b"2026-11-12T09:20:01.123456789Z \x1b[32mcaido listening on 0.0.0.0:48080\x1b[0m\n"
         b"2026-11-12T09:20:02Z proxy request GET http://scan-target.vendetta.lab/ token=abc123secret\n"
         b"not a timestamped line\n")

EVENTS = [
    {"Action": "start", "time": 1794474000, "timeNano": 1794474000500000000,
     "Actor": {"ID": CID, "Attributes": {"name": "errow-sandbox-1", "image": "errow-sandbox:1.1.0",
                                        "errow-run-id": FIXTURE_RUN, "errow-run-type": "scan"}}},
    {"Action": "exec_start: sh -c nmap", "time": 1794474001,
     "Actor": {"ID": CID, "Attributes": {"errow-run-id": FIXTURE_RUN}}},
    {"Action": "oom", "time": 1794474002, "timeNano": 1794474002000000000,
     "Actor": {"ID": CID, "Attributes": {"name": "errow-sandbox-1", "errow-run-id": FIXTURE_RUN}}},
    {"Action": "die", "time": 1794474003, "timeNano": 1794474003000000000,
     "Actor": {"ID": CID, "Attributes": {"name": "errow-sandbox-1", "errow-run-id": FIXTURE_RUN, "exitCode": "137"}}},
]


def source(env, container: FakeContainer, events=None) -> tuple[DockerSource, FakeClient]:
    client = FakeClient(container, EVENTS if events is None else events)
    return DockerSource("tcp://errow-dind:2376", env.log, client_factory=lambda: client), client


def test_caido_log_lines_and_lifecycle_events_are_shipped(env):
    src, client = source(env, FakeContainer(CAIDO_LOG))
    env.make(docker=src).once()
    proxy = env.lines("proxy")
    assert [p["message"] for p in proxy] == [
        "caido listening on 0.0.0.0:48080",
        "proxy request GET http://scan-target.vendetta.lab/ token=[REDACTED]",
    ]
    first = proxy[0]
    assert (first["tool"], first["port"], first["container"], first["container_id"], first["image"]) == (
        "caido", 48080, "errow-sandbox-1", CID[:12], "errow-sandbox:1.1.0")
    assert first["run"] == FIXTURE_RUN and first["@timestamp"] == "2026-11-12T09:20:01.123Z"
    assert "abc123secret" not in env.all_text()
    runtime = [r for r in env.lines("runtime_events") if r["logger"] == "docker.events"]
    assert [(r["action"], r["level"]) for r in runtime] == [("start", "INFO"), ("oom", "WARNING"), ("die", "INFO")]
    assert runtime[2]["exit_code"] == "137" and runtime[0]["run_type"] == "scan"
    assert client.list_calls == [{"all": True, "filters": {"label": "errow-run-id"}}]
    assert client.event_calls[0]["filters"] == {"type": "container", "label": "errow-run-id"}


def test_docker_cursor_prevents_replays_and_ships_only_new_lines(env):
    container = FakeContainer(CAIDO_LOG)
    src, _ = source(env, container, events=[])
    sh = env.make(docker=src)
    sh.once()
    before = env.counts()
    sh.once()
    env.make(docker=source(env, container, events=[])[0]).once()
    assert env.delta(before) == {}
    assert container.log_calls[0]["tail"] == src.max_lines and "since" in container.log_calls[1]
    container.log_bytes = CAIDO_LOG + b"2026-11-12T09:20:02Z second line same second\n2026-11-12T09:21:00Z later\n"
    sh.once()
    assert env.delta(before) == {"proxy": 2}
    assert [p["message"] for p in env.lines("proxy")[-2:]] == ["second line same second", "later"]


def test_docker_api_failure_degrades_with_a_reason_and_keeps_shipping_files(env):
    def broken():
        raise ConnectionError("tls handshake failed for tcp://errow-dind:2376 password=hunter2")

    src = DockerSource("tcp://errow-dind:2376", env.log, client_factory=broken)
    sh = env.make(docker=src)
    sh.once()
    assert len(env.lines("findings")) == 2 and env.lines("proxy") == []
    status = json.loads((env.state / "status.json").read_text())["sources"]["docker"]
    assert status["enabled"] is True and status["reason"].startswith("ConnectionError: tls handshake failed")
    assert "hunter2" not in json.dumps(env.logs) and "hunter2" not in status["reason"]
    assert [e["msg"] for e in env.logs if e["msg"].startswith("docker_source_")] == ["docker_source_error"]


def test_docker_source_recovers_after_an_outage(env):
    container = FakeContainer(CAIDO_LOG)
    state = {"up": False}

    def factory():
        if not state["up"]:
            raise OSError("daemon down")
        return FakeClient(container, [])

    sh = env.make(docker=DockerSource("tcp://x:2376", env.log, client_factory=factory))
    sh.once()
    assert env.lines("proxy") == []
    state["up"] = True
    sh.once()
    assert len(env.lines("proxy")) == 2
    assert json.loads((env.state / "status.json").read_text())["sources"]["docker"] == {"enabled": True, "reason": None}


def test_docker_is_disabled_with_a_logged_reason_without_docker_host(env):
    sh = env.make()
    sh.once()
    assert env.lines("proxy") == []
    started = [e for e in env.logs if e["msg"] == "started"][0]
    assert started["docker"] == {"enabled": False, "reason": "DOCKER_HOST is not set"}
    assert [e["msg"] for e in env.logs].count("docker_source_disabled") == 1
    assert json.loads((env.state / "status.json").read_text())["sources"]["docker"]["enabled"] is False


def test_docker_timestamps_are_normalised_for_ordering():
    assert norm_ts("2026-11-12T09:20:02Z") == "2026-11-12T09:20:02.000000000Z"
    assert norm_ts("2026-11-12T09:20:02.5Z") > norm_ts("2026-11-12T09:20:02.123456789Z")
    assert norm_ts("garbage") is None


# ---------------------------------------------------------------- agents.db is opened read-only
def test_agents_db_is_opened_mode_ro_and_never_modified(env, run_dir, monkeypatch):
    db = run_dir / ".state" / "agents.db"
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    uris: list[str] = []
    real = sqlite3.connect

    def spy(target, *args, **kwargs):
        uris.append(str(target))
        return real(target, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", spy)
    env.make().once()
    assert uris and all(u.startswith("file:") and "mode=ro" in u for u in uris)
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert not list((run_dir / ".state").glob("agents.db-*"))


def test_agents_db_falls_back_to_immutable_when_ro_open_fails(env, monkeypatch):
    real = sqlite3.connect
    uris: list[str] = []

    def picky(target, *args, **kwargs):
        uris.append(str(target))
        if "immutable=1" not in str(target):
            raise sqlite3.OperationalError("unable to open database file")
        return real(target, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", picky)
    env.make().once()
    assert len(uris) == 2 and uris[1].endswith("&immutable=1")
    assert len(env.lines("transcripts")) == 9


def test_unreadable_agents_db_is_skipped_not_fatal(env, run_dir):
    (run_dir / ".state" / "agents.db").write_bytes(b"this is not a sqlite database" * 20)
    sh = env.make()
    sh.once()
    assert env.lines("transcripts") == [] and len(env.lines("findings")) == 2
    assert [e for e in env.logs if e["msg"] == "agents_db_unreadable"]
    assert len(env.lines("agent_state")) == 2  # still derived from agents.json and run.json


def test_replaced_agents_db_is_re_read_from_the_start(env, run_dir):
    env.make().once()
    db = run_dir / ".state" / "agents.db"
    db.unlink()
    from conftest import MESSAGES, build_agents_db
    build_agents_db(db, MESSAGES[:3])
    before = env.counts()
    env.make().once()
    assert env.delta(before)["transcripts"] == 3  # ids restart at 1 (< last seen id 10): re-read from the start


# ---------------------------------------------------------------- status.json / health / config / CLI
def test_status_json_reports_streams_counts_lag_and_sources(env):
    sh = env.make()
    sh.once()
    doc = json.loads((env.state / "status.json").read_text())
    assert doc["component"] == "errow-shipper" and doc["runs"] == 1 and doc["errors"] == 0 and doc["lag_seconds"] == 0.0
    assert doc["last_ok"] and doc["last_ok_epoch"] and doc["telemetry_mirror"] is True
    assert set(doc["streams"]) == {"findings", "runs", "transcripts", "threat_models", "coverage", "llm_logs", "mcp_events",
                                   "runtime_events", "tui_events", "cloud_events", "telemetry", "agent_state",
                                   "report_artifacts", "proxy", "tooling", "viewer"}
    findings = doc["streams"]["findings"]
    assert findings["records_total"] == 2 and findings["bytes_total"] > 0 and findings["last_emit"]
    assert findings["file_bytes"] == (env.out / "findings.ndjson").stat().st_size
    assert doc["streams"]["mcp_events"]["records_total"] == 0
    assert doc["sources"]["runs_dir"] == {"readable": True, "reason": None}
    assert not list(env.state.glob("*.tmp"))


def test_lag_grows_while_a_source_stays_unreadable(env, run_dir):
    (run_dir / "run.json").write_text("{")
    now = {"t": 1_800_000_000.0}
    cfg = shp.Config.from_env(env.env)
    sh = shp.Shipper(cfg, log=env.log, sleep=lambda _s: None, clock=lambda: now["t"])
    sh.setup()
    sh.cycle()
    now["t"] += 45
    sh.cycle()
    assert json.loads((env.state / "status.json").read_text())["lag_seconds"] == 45.0
    (run_dir / "run.json").write_text(json.dumps({"run_id": FIXTURE_RUN, "status": "completed"}))
    now["t"] += 5
    sh.cycle()
    assert json.loads((env.state / "status.json").read_text())["lag_seconds"] == 0.0


def test_missing_runs_dir_is_reported_not_fatal(env, tmp_path):
    sh = env.make(ERROW_RUNS_DIR=str(tmp_path / "nope"))
    sh.once()
    doc = json.loads((env.state / "status.json").read_text())
    assert doc["runs"] == 0 and doc["sources"]["runs_dir"] == {"readable": False, "reason": "FileNotFoundError"}
    assert all((env.out / f"{s}.ndjson").is_file() for s in doc["streams"])


@pytest.mark.parametrize(("age", "ok_age", "expected"), [(5, 5, 0), (119, 10, 0), (121, 10, 1), (10, 700, 1), (10, 500, 0)])
def test_healthcheck_uses_status_freshness(env, age, ok_age, expected):
    env.make().once()
    doc = json.loads((env.state / "status.json").read_text())
    now = doc["ts_epoch"] + age
    doc["last_ok_epoch"] = now - ok_age
    (env.state / "status.json").write_text(json.dumps(doc))
    assert shp.healthcheck(shp.Config.from_env(env.env), clock=lambda: now) == expected


def test_healthcheck_fails_without_or_with_garbage_status(env):
    cfg = shp.Config.from_env(env.env)
    assert shp.healthcheck(cfg) == 1
    env.state.mkdir(parents=True)
    (env.state / "status.json").write_text("not json")
    assert shp.healthcheck(cfg) == 1


def test_config_defaults_and_overrides():
    cfg = shp.Config.from_env({})
    assert (str(cfg.runs_dir), str(cfg.out_dir), str(cfg.state_dir)) == (
        "/workspace/errow_runs", "/var/log/errow", "/var/lib/errow-shipper")
    assert (cfg.interval, cfg.max_bytes, cfg.keep, cfg.telemetry, cfg.include_coverage, cfg.docker_host) == (
        10.0, 52428800, 5, True, False, "")
    cfg = shp.Config.from_env({"SHIPPER_MAX_BYTES": "5", "SHIPPER_KEEP": "junk", "SHIPPER_INTERVAL": "x", "errow_TELEMETRY": "Off",
                               "SHIPPER_INCLUDE_COVERAGE_RESULTS": "yes", "DOCKER_HOST": " tcp://d:2376 "})
    assert (cfg.max_bytes, cfg.keep, cfg.interval, cfg.telemetry, cfg.include_coverage, cfg.docker_host) == (
        1024, 5, 10.0, False, True, "tcp://d:2376")


def test_cli_version_selftest_and_once(env, capsys, monkeypatch):
    for key, value in env.env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    assert shp.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "errow-shipper 1.0.0"
    assert shp.main(["--selftest"]) == 0
    assert json.loads(capsys.readouterr().out)["selftest"] == "ok"
    assert shp.main(["--once"]) == 0
    assert (env.out / "findings.ndjson").read_text().count("\n") == 2
    assert shp.main(["--healthcheck"]) == 0
    stdout = capsys.readouterr().out
    assert stdout and all(json.loads(line)["component"] == "errow-shipper" for line in stdout.splitlines())
    assert "hunter2" not in stdout


def test_selftest_fails_when_the_runs_dir_is_missing(env, tmp_path, capsys):
    cfg = shp.Config.from_env({**env.env, "ERROW_RUNS_DIR": str(tmp_path / "absent")})
    assert shp.selftest(cfg) == 1
    assert "runs_dir_missing" in capsys.readouterr().out


def test_service_loop_survives_a_failing_cycle(env, monkeypatch):
    sh = env.make(SHIPPER_INTERVAL="0.01")
    calls = {"n": 0}
    real = sh.cycle

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        sh.stop.set()
        return real()

    monkeypatch.setattr(sh, "cycle", flaky)
    sh.run_forever()
    assert sh.errors == 1 and len(env.lines("findings")) == 2
    assert [e for e in env.logs if e["msg"] == "cycle_failed"][0]["error"] == "RuntimeError: boom"
    assert json.loads((env.state / "status.json").read_text())["errors"] == 1


def test_logger_emits_one_redacted_json_object_per_line(capsys):
    shp.make_logger()("info", "x", detail="password=hunter2 ok", n=3)
    rec = json.loads(capsys.readouterr().out)
    assert rec["component"] == "errow-shipper" and rec["level"] == "INFO" and rec["n"] == 3
    assert rec["detail"] == "password=[REDACTED] ok" and rec["ts"].endswith("Z")
