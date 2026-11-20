"""Schema, content-safety and redaction checks for every shipper stream.

Traces: CONTRACT §8.4 (stream names), §15 (record shapes), §3 (sanitisation); PROMPT §2.3 (errow-shipper).
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest
import streams as S
from conftest import FIXTURE_RUN

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

REQUIRED = {
    "findings": {"ruleId", "ruleIndex", "level", "message", "locations", "partialFingerprints", "properties", "rule"},
    "runs": {"run_id", "status", "llm_usage", "targets_info"},
    "coverage": {"schema_version", "summary", "entries", "scope"},
    "threat_models": {"identity", "target", "written_at", "written_by", "content", "amendments", "amendment_count"},
    "agent_state": {"agent_id", "agent_name", "status", "role", "parent_id", "tokens", "cost", "messages", "model"},
    "transcripts": {"agent", "agent_id", "message_id", "role", "type", "content"},
    "tooling": {"agent", "agent_id", "message_id", "event_type", "tool", "call_id"},
    "llm_logs": {"level", "logger", "route", "provider", "model", "api_host", "outcome", "status_code", "duration_ms",
                 "tokens", "cost_usd", "agent_id", "attempt", "streaming"},
    "runtime_events": {"level", "logger", "message"},
    "tui_events": {"level", "logger", "message"},
    "cloud_events": {"level", "logger", "message"},
    "viewer": {"level", "logger", "message"},
    "telemetry": {"event", "properties", "mirrored"},
    "report_artifacts": {"artifact", "path", "sha256", "bytes", "kind"},
}


@pytest.fixture
def shipped(env):
    env.make().once()
    return env


def test_every_contract_stream_file_exists_and_mcp_events_stays_empty(shipped):
    assert set(S.STREAMS) == {
        "findings", "runs", "transcripts", "threat_models", "coverage", "llm_logs", "mcp_events", "runtime_events",
        "tui_events", "cloud_events", "telemetry", "agent_state", "report_artifacts", "proxy", "tooling", "viewer",
    }
    for stream in S.STREAMS:
        assert (shipped.out / f"{stream}.ndjson").is_file(), stream
    assert (shipped.out / "mcp_events.ndjson").read_bytes() == b""


@pytest.mark.parametrize("stream", sorted(REQUIRED))
def test_stream_record_schema(shipped, stream):
    records = shipped.lines(stream)
    assert records, f"fixture should populate {stream}"
    seen = set()
    for rec in records:
        assert ISO.match(rec["@timestamp"]), rec["@timestamp"]
        assert rec["stream"] == stream
        assert rec["run"] == FIXTURE_RUN
        assert rec["source"] == "errow"
        assert HEX64.match(rec["doc_id"])
        assert REQUIRED[stream] <= set(rec), REQUIRED[stream] - set(rec)
        assert rec["doc_id"] not in seen
        seen.add(rec["doc_id"])


def test_every_line_is_one_json_object(shipped):
    for stream in S.STREAMS:
        for line in (shipped.out / f"{stream}.ndjson").read_text("utf-8").splitlines():
            assert isinstance(json.loads(line), dict)


def test_findings_are_sarif_results_with_rule_and_contract_doc_id(shipped):
    findings = shipped.lines("findings")
    assert [f["ruleId"] for f in findings] == ["CWE-89", "CWE-639"]
    first = findings[0]
    assert first["rule"]["id"] == "CWE-89" and first["rule"]["properties"]["security-severity"] == "8.1"
    fp = first["partialFingerprints"]["primaryLocationLineHash"]
    assert first["doc_id"] == hashlib.sha256((FIXTURE_RUN + "CWE-89" + fp).encode()).hexdigest()
    errow = first["properties"]["errow"]
    assert errow["poc"] == {"description": "Send a single quote in q and observe the SQL error.", "script_available": True}
    assert errow["id"] == "vuln-0001" and errow["cwe"] == "CWE-89" and first["properties"]["security-severity"] == "8.1"
    assert first["@timestamp"] == "2026-11-12T09:15:30.000Z"


def test_coverage_results_stay_out_of_findings_unless_enabled(env):
    env.make(SHIPPER_INCLUDE_COVERAGE_RESULTS="true").once()
    findings = env.lines("findings")
    assert len(findings) == 5
    cov = [f for f in findings if f["ruleId"].startswith("errow-coverage/")]
    assert {f["kind"] for f in cov} == {"pass", "notApplicable", "open"}
    surface = cov[0]["properties"]["errow"]["surface"]
    assert cov[0]["doc_id"] == hashlib.sha256((FIXTURE_RUN + cov[0]["ruleId"] + surface).encode()).hexdigest()


def test_no_exploit_payload_or_secret_reaches_any_stream(shipped):
    text = shipped.all_text()
    for needle in ("PAYLOAD-MARKER", "poc_script_code", "hunter2", "sk-live-abcdef", "SYSTEM-PROMPT-MARKER",
                   "REASONING-MARKER"):
        assert needle not in text, needle
    assert "password=[REDACTED]" in text


def test_vulnerabilities_json_and_finding_markdown_are_only_hashed(shipped, run_dir):
    arts = {a["path"]: a for a in shipped.lines("report_artifacts")}
    names = {p.split("/", 1)[1] for p in arts}
    assert names == {"run.json", "vulnerabilities.json", "findings.sarif", "coverage.json",
                     "penetration_test_report.md", "vulnerabilities/vuln-0001.md"}
    vuln = arts[f"{FIXTURE_RUN}/vulnerabilities.json"]
    assert vuln["sha256"] == hashlib.sha256((run_dir / "vulnerabilities.json").read_bytes()).hexdigest()
    assert vuln["bytes"] == (run_dir / "vulnerabilities.json").stat().st_size and vuln["kind"] == "json"
    assert {a["kind"] for a in arts.values()} == {"json", "sarif", "md"}
    assert all(set(a) <= {"@timestamp", "stream", "run", "source", "doc_id", "artifact", "path", "sha256", "bytes", "kind"}
               for a in arts.values())
    assert not any(".state" in p for p in arts)


def test_transcripts_system_reasoning_code_and_truncation(shipped):
    msgs = shipped.lines("transcripts")
    assert len(msgs) == 9  # 10 rows minus the reasoning item
    by_id = {m["message_id"]: m for m in msgs}
    assert by_id[1]["role"] == "system" and by_id[1]["content"].startswith("[omitted:")
    assert by_id[2]["content"] == "Assess http://scan-target.vendetta.lab with password=[REDACTED]"
    assert by_id[3]["content"] == "Starting recon.\n[code block omitted: 31 chars]\nDone."
    assert 4 not in by_id
    call = by_id[5]
    assert call["tool"] == "terminal_execute" and call["call_id"] == "call_1" and call["agent"] == "errowAgent"
    out = by_id[6]
    assert out["role"] == "tool" and out["tool"] == "terminal_execute"
    assert out["content"].endswith("...[truncated]") and len(out["content"]) <= 8000 + len("...[truncated]")
    assert "sk-live" not in out["content"]
    assert by_id[7]["content"] == 'python_action({"action":"run","code":"[omitted:23 chars]"})'
    assert by_id[10]["agent"] == "AuthzAgent"


def test_tooling_records_call_arguments_and_result_digest(shipped):
    tooling = shipped.lines("tooling")
    assert [t["event_type"] for t in tooling] == ["tool_call", "tool_result", "tool_call", "tool_result"]
    call, result, py_call, py_result = tooling
    assert call["arguments"] == {"command": "nmap -sT scan-target.vendetta.lab", "timeout": 60}
    assert result["tool"] == "terminal_execute" and result["output_chars"] > 9000
    assert HEX64.match(result["output_sha256"]) and len(result["output_preview"]) <= 500 + len("...[truncated]")
    assert py_call["arguments"] == {"action": "run", "code": "[omitted:23 chars]"}
    assert py_result["tool"] == "python_action"


def test_llm_logs_carry_request_metrics_without_bodies(shipped):
    ok, err = shipped.lines("llm_logs")
    assert (ok["provider"], ok["model"], ok["api_host"], ok["outcome"], ok["status_code"]) == (
        "openai", "gpt-5.5", "api.openai.com", "ok", 200)
    assert ok["tokens"] == {"input": 5100, "output": 210, "cached": 4000, "total": 5310}
    assert ok["duration_ms"] == ok["latency_ms"] == 1840 and ok["ttft_ms"] == 412 and ok["streaming"] is True
    assert ok["cost_usd"] == 0.0123 and ok["agent_id"] == "agent-root-1" and ok["finish_reason"] == "stop"
    assert ok["provider_request_id"] == "req_abc123" and ok["request_bytes"] == 20211
    assert err["status_code"] == 429 and err["upstream_error"] == "rate_limit" and err["ttft_ms"] is None
    assert err["attempt"] == 2 and err["error"].startswith("RateLimitError:") and "sk-live" not in err["error"]
    assert ok["@timestamp"] == "2026-11-12T09:10:02.250Z"
    for rec in (ok, err):
        assert not {"prompt", "messages", "input", "response", "content", "body"} & set(rec)


def test_errow_log_lines_are_classified_into_event_streams(shipped):
    runtime = shipped.lines("runtime_events")
    assert [r["logger"] for r in runtime] == ["errow.core.runner", "errow.runtime.docker_runtime", "errow.tools.proxy"]
    assert "password=[REDACTED]" in runtime[1]["message"] and runtime[1]["level"] == "WARNING"
    assert runtime[2]["message"].splitlines()[0] == "proxy call failed"
    assert runtime[2]["message"].endswith("RuntimeError: boom") and "Traceback" in runtime[2]["message"]
    assert runtime[2]["agent_id"] == "agent-sub-2" and runtime[0]["agent_id"] is None
    assert shipped.lines("tui_events")[0]["message"] == "tui connected fd=3"
    assert shipped.lines("cloud_events")[0]["message"] == "cloud session synced"
    assert shipped.lines("viewer")[0]["message"].startswith("GET /api/runs/")


def test_runs_and_coverage_are_snapshots_of_the_rewritten_json(shipped):
    run = shipped.lines("runs")[0]
    assert run["run_id"] == FIXTURE_RUN and run["llm_usage"]["requests"] == 42 and run["status"] == "completed"
    cov = shipped.lines("coverage")[0]
    assert cov["schema_version"] == 1 and len(cov["entries"]) == 3 and cov["summary"]["gaps"] == 1


def test_threat_models_one_record_per_entry(shipped):
    tms = {t["identity"]: t for t in shipped.lines("threat_models")}
    main = tms["http://scan-target.vendetta.lab"]
    assert main["written_by"] == "agent-root-1" and main["amendment_count"] == 1
    assert main["amendments"][0]["by"] == "agent-sub-2"
    assert main["@timestamp"] == "2026-11-12T09:45:00.000Z"
    assert tms["scan-target.vendetta.lab:8443"]["amendments"] == []


def test_agent_state_joins_graph_usage_and_db(shipped):
    agents = {a["agent_id"]: a for a in shipped.lines("agent_state")}
    root, sub = agents["agent-root-1"], agents["agent-sub-2"]
    assert (root["role"], root["parent_id"], root["status"], root["agent_name"]) == ("root", None, "completed", "errowAgent")
    assert (sub["role"], sub["parent_id"]) == ("subagent", "agent-root-1")
    assert root["tokens"] == {"input": 150000, "output": 7000, "total": 157000, "cached": 110000, "requests": 30}
    assert sub["tokens"]["cached"] == 40000  # list-shaped input_tokens_details
    assert root["messages"] == 8 and sub["messages"] == 2 and sub["last_message_at"] == "2026-11-12T09:41:00.000Z"
    assert root["skills"] == ["sql_injection"] and root["model"] == "gpt-5.5" and root["cost"] == 0.34


def test_telemetry_mirrors_posthog_event_shapes(shipped):
    events = shipped.lines("telemetry")
    assert [e["event"] for e in events] == ["scan_started", "finding_reported", "finding_reported", "scan_ended"]
    started, f1, f2, ended = events
    assert started["properties"] == {"model": "gpt-5.5", "auth_mode": "api_key", "scan_mode": "standard",
                                     "scan_type": "blackbox", "has_instructions": True}
    assert {(f["properties"]["severity"], f["properties"]["cwe"], f["properties"]["is_cve"]) for f in (f1, f2)} == {
        ("high", "cwe-89", False), ("medium", "cwe-639", False)}
    p = ended["properties"]
    assert p["exit_reason"] == "completed" and p["duration_seconds"] == 3330 and p["vulnerabilities_total"] == 2
    assert p["vulnerabilities_high"] == 1 and p["vulnerabilities_medium"] == 1 and p["vulnerabilities_critical"] == 0
    assert p["llm_requests"] == 42 and p["llm_tokens"] == 219800 and p["llm_cost"] == 0.4821
    assert all(e["mirrored"] is True for e in events)
    assert started["@timestamp"] == "2026-11-12T09:10:00.000Z" and ended["@timestamp"] == "2026-11-12T10:05:30.000Z"


@pytest.mark.parametrize("flag", [{"errow_TELEMETRY": "false"}, {"errow_TELEMETRY": "0"}, {"errow_TELEMETRY": "off"},
                                  {"SHIPPER_TELEMETRY_MIRROR": "false"}])
def test_telemetry_is_not_mirrored_when_disabled(env, flag):
    env.make(**flag).once()
    assert env.lines("telemetry") == []
    assert env.lines("findings")


def test_oversized_record_becomes_a_stub(env, run_dir):
    cov = json.loads((run_dir / "coverage.json").read_text())
    cov["entries"] = [{**cov["entries"][0], "surface": f"GET /s/{i}", "evidence": "e" * 500} for i in range(400)]
    (run_dir / "coverage.json").write_text(json.dumps(cov))
    env.make(SHIPPER_MAX_LINE_BYTES="1024").once()
    rec = env.lines("coverage")[0]
    assert rec["truncated_record"] is True and rec["original_bytes"] > 1024
    assert set(rec) == {"@timestamp", "stream", "run", "source", "doc_id", "truncated_record", "original_bytes"}
