# Traces: PROMPT §2.3 (Errow as MCP server), §2.5 (stage-2 guardrail: default-deny tool policy, dry-run by default, rate limits);
#         CONTRACT §4.3 (cs3.ai.tool_call), §4.4 (POST /mcp/tool_call: 200 dry_run|executed, 403 policy_violation, 429 rate_limited), §4.5 (mcp_policy.yaml).
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from conftest import ROOT, Gateway, lab_resolver, metric_value
from policy import Policy, PolicyError

TARGET = "scan-target.vendetta.lab"
APP = "https://app.vendetta.lab/"

VALID_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    ("triage", "nmap", {"target": TARGET, "scan_type": "-sT"}),
    ("triage", "nmap", {"target": TARGET, "scan_type": "-sV", "ports": "1-1024", "timing": "-T2"}),
    ("triage", "bbot", {"target": "vendetta.lab", "preset": "safe", "flags": ["passive"]}),
    ("triage", "nuclei", {"target": APP, "tags": ["cves"], "severity": ["high", "critical"], "rate_limit": 20}),
    ("triage", "gobuster", {"target": APP, "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt", "threads": 10}),
    ("triage", "subfinder", {"target": "vendetta.lab", "passive": True}),
    ("triage", "wafw00f", {"target": APP, "passive": True}),
    ("triage", "trufflehog", {"repo_path": "/workspace/repos/vendetta-core", "no_verification": True}),
    ("triage", "shell", {"command": "dig", "target": TARGET}),
    ("forensic", "agent_browser", {"url": "https://app.vendetta.lab/login", "screenshot": True}),
    ("forensic", "proxy", {"target": TARGET, "action": "list_requests", "limit": 50}),
    ("forensic", "web_search", {"query": "CVE-2024-3094 xz backdoor indicators", "max_results": 5}),
    ("forensic", "threat_model", {"run": "run-2026-02-14", "format": "summary"}),
]

DENIED_CALLS: list[tuple[str, str, str, dict[str, Any], str]] = [
    ("loopback ip", "triage", "nmap", {"target": "127.0.0.1", "scan_type": "-sT"}, "target:denied_cidr:127.0.0.0/8"),
    ("link-local metadata ip", "triage", "nmap", {"target": "169.254.169.254", "scan_type": "-sn"}, "target:denied_cidr:169.254.0.0/16"),
    ("metadata hostname", "triage", "nmap", {"target": "metadata.google.internal", "scan_type": "-sT"}, "target:denied_hostname:metadata.google.internal"),
    ("internal wildcard", "triage", "shell", {"command": "dig", "target": "vault.internal"}, "target:denied_hostname:*.internal"),
    ("localhost", "triage", "nmap", {"target": "localhost", "scan_type": "-sT"}, "target:denied_hostname:localhost"),
    ("public ip not allow-listed", "triage", "nmap", {"target": "8.8.8.8", "scan_type": "-sT"}, "target:not_allowlisted"),
    ("host outside the zone", "triage", "nuclei", {"target": "https://example.org/", "tags": ["cves"]}, "target:not_allowlisted"),
    ("nmap script engine", "triage", "nmap", {"target": TARGET, "scan_type": "-sT", "--script": "vuln"}, "forbidden_arg:--script"),
    ("nmap aggressive flag", "triage", "nmap", {"target": TARGET, "scan_type": "-sT", "-A": True}, "forbidden_arg:-A"),
    ("nmap syn scan", "triage", "nmap", {"target": TARGET, "scan_type": "-sS"}, "args:scan_type:not_in_enum"),
    ("nuclei dos tag", "triage", "nuclei", {"target": APP, "tags": ["dos"]}, "forbidden_tag:dos"),
    ("nuclei dos tag with a legal one", "triage", "nuclei", {"target": APP, "tags": ["cves", "dos"]}, "forbidden_tag:dos"),
    ("nuclei custom templates", "triage", "nuclei", {"target": APP, "tags": ["cves"], "-t": "/tmp/x.yaml"}, "forbidden_arg:-t"),
    ("gobuster 11 threads", "triage", "gobuster", {"target": APP, "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt", "threads": 11}, "args:threads:above_max"),
    ("elasticsearch port in target", "triage", "nmap", {"target": f"{TARGET}:9200", "scan_type": "-sT"}, "target:denied_port:9200"),
    ("ollama port in url", "triage", "nuclei", {"target": "https://app.vendetta.lab:11434/", "tags": ["cves"]}, "target:denied_port:11434"),
    ("unknown tool", "triage", "metasploit", {"target": TARGET}, "tool:unknown"),
    ("forensic calling nmap", "forensic", "nmap", {"target": TARGET, "scan_type": "-sT"}, "role:forensic_not_permitted_for_nmap"),
    ("triage calling web_search", "triage", "web_search", {"query": "x"}, "role:triage_not_permitted_for_web_search"),
    ("unknown role", "admin", "nmap", {"target": TARGET, "scan_type": "-sT"}, "role:admin_not_permitted_for_nmap"),
    ("missing required argument", "triage", "nmap", {"target": TARGET}, "args:scan_type:required"),
    ("undeclared argument", "triage", "nmap", {"target": TARGET, "scan_type": "-sT", "output": "x"}, "args:output:undeclared"),
    ("shell metacharacter in target", "triage", "shell", {"command": "dig", "target": f"{TARGET}; id"}, "forbidden_arg:;"),
    ("shell pipe in command", "triage", "shell", {"command": "dig | sh", "target": TARGET}, "forbidden_arg:|"),
    ("shell command substitution", "triage", "shell", {"command": "dig", "target": f"$(id).{TARGET}"}, "forbidden_arg:$("),
    ("shell command outside the enum", "triage", "shell", {"command": "rm -rf /", "target": TARGET}, "args:command:not_in_enum"),
    ("trufflehog path traversal", "triage", "trufflehog", {"repo_path": "/workspace/repos/../../etc"}, "target:unparseable"),
    ("trufflehog outside the repo root", "triage", "trufflehog", {"repo_path": "/etc/shadow"}, "args:repo_path:pattern_mismatch"),
    ("agent_browser javascript", "forensic", "agent_browser", {"url": APP, "javascript": "alert(1)"}, "forbidden_arg:javascript"),
    ("agent_browser plain http", "forensic", "agent_browser", {"url": "http://app.vendetta.lab/"}, "args:url:pattern_mismatch"),
    ("proxy replay", "forensic", "proxy", {"target": TARGET, "action": "list_requests", "replay": True}, "forbidden_arg:replay"),
    ("threat_model write", "forensic", "threat_model", {"run": "r1", "write": True}, "forbidden_arg:write"),
]


@pytest.mark.parametrize(("role", "tool", "args"), VALID_CALLS, ids=[f"{t}-{i}" for i, (_, t, _) in enumerate(VALID_CALLS)])
async def test_valid_call_is_dry_run_by_default(gateway: Gateway, role: str, tool: str, args: dict[str, Any]) -> None:
    response = await gateway.tool_call(role, tool, args)
    body = response.json()
    assert response.status == 200, body
    assert body["status"] == "dry_run" and body["tool"] == tool and body["live"] is False and body["request_id"]
    assert gateway.errow.calls == [] and gateway.errow.initializations == 0


@pytest.mark.parametrize(("label", "role", "tool", "args", "violation"), DENIED_CALLS, ids=[c[0] for c in DENIED_CALLS])
async def test_denied_call_is_403_with_the_violation(gateway: Gateway, label: str, role: str, tool: str, args: dict[str, Any], violation: str) -> None:
    response = await gateway.tool_call(role, tool, args)
    body = response.json()
    assert response.status == 403, (label, body)
    assert body["status"] == "policy_violation" and violation in body["violations"], (label, body)
    assert gateway.errow.calls == []


async def test_denied_calls_emit_chained_audit_events_and_metrics(gateway: Gateway) -> None:
    await gateway.tool_call("triage", "nmap", {"target": "127.0.0.1", "scan_type": "-sT"})
    await gateway.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})
    first, second = await gateway.events("cs3.ai.tool_call", 2)
    assert (first["decision"], second["decision"]) == ("denied", "dry_run")
    assert first["tool"] == "nmap" and first["tenant_id"] == "tenant-a" and first["incident_id"] == "inc-1" and first["role"] == "triage"
    assert "target:denied_cidr:127.0.0.0/8" in first["violations"] and first["live"] is False
    assert (first["seq"], second["seq"]) == (1, 2) and second["prev_hash"] == first["hash"] and first["chain_id"] == second["chain_id"]
    metrics = await gateway.metrics()
    assert metric_value(metrics, "llm_gateway_mcp_tool_calls_total", tool="nmap", decision="denied") == 1
    assert metric_value(metrics, "llm_gateway_mcp_tool_calls_total", tool="nmap", decision="dry_run") == 1


async def test_agent_browser_gets_the_default_screenshot_retention(gateway: Gateway) -> None:
    body = (await gateway.tool_call("forensic", "agent_browser", {"url": "https://app.vendetta.lab/x", "screenshot": True})).json()
    assert body["args"]["screenshot_retention_days"] == 7
    explicit = (await gateway.tool_call("forensic", "agent_browser", {"url": "https://app.vendetta.lab/x", "screenshot": True, "screenshot_retention_days": 30})).json()
    assert explicit["args"]["screenshot_retention_days"] == 30
    too_long = await gateway.tool_call("forensic", "agent_browser", {"url": "https://app.vendetta.lab/x", "screenshot": True, "screenshot_retention_days": 31})
    assert too_long.status == 403


async def test_denied_hostname_wins_over_allow_list_and_dns_rebinding_is_caught(gateway: Gateway) -> None:
    rebind = await gateway.tool_call("triage", "nmap", {"target": "rebind.vendetta.lab", "scan_type": "-sT"})
    assert rebind.status == 403 and "target:resolves_to_denied:169.254.169.254" in rebind.json()["violations"]
    mixed = await gateway.tool_call("triage", "nmap", {"target": "mixed.vendetta.lab", "scan_type": "-sT"})
    assert mixed.status == 403 and "target:resolves_to_denied:127.0.0.1" in mixed.json()["violations"]
    fine = await gateway.tool_call("triage", "nmap", {"target": "app.vendetta.lab", "scan_type": "-sT"})
    assert fine.status == 200


async def test_unresolvable_allow_listed_host_is_judged_by_name_alone(make_gateway: Any) -> None:
    async def failing(host: str) -> list[str]:
        raise OSError("name resolution failed")

    gw = await make_gateway(resolver=failing)
    assert (await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})).json()["status"] == "dry_run"
    denied = await gw.tool_call("triage", "nmap", {"target": "metadata.google.internal", "scan_type": "-sT"})
    assert denied.status == 403


@pytest.mark.parametrize(
    "envelope",
    [
        {"incident_id": "inc-1", "role": "triage", "tool": "nmap", "args": {"target": TARGET, "scan_type": "-sT"}},
        {"tenant_id": "tenant-a", "role": "triage", "tool": "nmap", "args": "not-an-object"},
        {"tenant_id": "tenant a!", "role": "triage", "tool": "nmap", "args": {"target": TARGET, "scan_type": "-sT"}},
        {"tenant_id": "tenant-a", "role": "triage", "tool": "nmap", "args": {"target": TARGET, "scan_type": "-sT"}, "execute": True},
        {"tenant_id": "tenant-a", "role": "triage", "tool": ["nmap"], "args": {}},
    ],
    ids=["no-tenant", "args-not-object", "bad-tenant", "unknown-envelope-field", "tool-not-a-string"],
)
async def test_invalid_envelope_is_denied(gateway: Gateway, envelope: dict[str, Any]) -> None:
    response = await gateway.post("/mcp/tool_call", envelope)
    assert response.status == 403 and response.json()["status"] == "policy_violation"
    assert any(v.startswith("envelope:") for v in response.json()["violations"])


async def test_non_object_body_is_400(gateway: Gateway) -> None:
    assert (await gateway.post("/mcp/tool_call", [1, 2])).status == 400
    assert (await gateway.post("/mcp/tool_call", data=b"{not json", headers={"Content-Type": "application/json"})).status == 400


async def test_tool_call_requires_authentication(gateway: Gateway) -> None:
    response = await gateway.post("/mcp/tool_call", {"tenant_id": "t", "role": "triage", "tool": "nmap", "args": {}}, auth=False)
    assert response.status == 401


async def test_tool_rate_limit_returns_429_with_retry_after(gateway: Gateway) -> None:
    query = {"query": "ioc lookup", "max_results": 3}
    for index in range(5):
        assert (await gateway.tool_call("forensic", "web_search", query, tenant_id=f"tenant-{index}")).status == 200
    limited = await gateway.tool_call("forensic", "web_search", query, tenant_id="tenant-5")
    body = limited.json()
    assert limited.status == 429 and body["status"] == "rate_limited" and body["limited_by"] == "tool"
    assert limited.headers["Retry-After"].isdigit() and int(limited.headers["Retry-After"]) >= 1
    events = await gateway.events("cs3.ai.tool_call", 6)
    assert [e["decision"] for e in events] == ["dry_run"] * 5 + ["rate_limited"]
    assert metric_value(await gateway.metrics(), "llm_gateway_mcp_tool_calls_total", tool="web_search", decision="rate_limited") == 1


async def test_per_target_rate_limit_is_per_tool_and_target(gateway: Gateway) -> None:
    call = {"target": TARGET, "scan_type": "-sT"}
    assert (await gateway.tool_call("triage", "nmap", call, tenant_id="t-1")).status == 200
    assert (await gateway.tool_call("triage", "nmap", call, tenant_id="t-2")).status == 200
    third = await gateway.tool_call("triage", "nmap", call, tenant_id="t-3")
    assert third.status == 429 and third.json()["limited_by"] == "tool_target"
    assert (await gateway.tool_call("triage", "nmap", {"target": "app.vendetta.lab", "scan_type": "-sT"}, tenant_id="t-3")).status == 200


async def test_per_tenant_rate_limit_applies_across_tools(gateway: Gateway) -> None:
    for _ in range(10):
        assert (await gateway.tool_call("forensic", "threat_model", {"run": "r1"})).status == 200
    limited = await gateway.tool_call("forensic", "threat_model", {"run": "r1"})
    assert limited.status == 429 and limited.json()["limited_by"] == "tenant"
    assert (await gateway.tool_call("forensic", "threat_model", {"run": "r1"}, tenant_id="tenant-b")).status == 200


async def test_denied_calls_do_not_consume_rate_budget(gateway: Gateway) -> None:
    for _ in range(12):
        assert (await gateway.tool_call("triage", "nmap", {"target": "127.0.0.1", "scan_type": "-sT"})).status == 403
    assert (await gateway.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})).status == 200


async def test_live_mode_executes_through_errow_mcp_over_mtls(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true"})
    response = await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"}, request_id="req-live-1")
    body = response.json()
    assert response.status == 200 and body["status"] == "executed" and body["tool"] == "nmap" and body["is_error"] is False and body["truncated"] is False
    assert "22/tcp open ssh" in body["output"] and "hunter2hunter2" not in body["output"] and "[REDACTED]" in body["output"]
    assert gw.errow.initializations == 1 and gw.errow.client_subjects and set(gw.errow.client_subjects) == {"llm-gateway"}
    (call,) = gw.errow.calls
    assert call["params"]["name"] == "nmap" and call["params"]["arguments"] == {"target": TARGET, "scan_type": "-sT"}
    assert call["params"]["_meta"]["tenant_id"] == "tenant-a" and call["params"]["_meta"]["request_id"] == "req-live-1"
    assert call["session"] == "session-1"
    events = await gw.events("cs3.ai.tool_call", 2)
    assert [e["decision"] for e in events] == ["allowed", "executed"] and all(e["live"] is True for e in events)
    assert "hunter2hunter2" not in str(events) and events[1]["result_summary"].startswith("ok chars=")
    second = await gw.tool_call("triage", "shell", {"command": "dig", "target": TARGET}, tenant_id="tenant-b")
    assert second.status == 200 and gw.errow.initializations == 1 and len(gw.errow.calls) == 2


async def test_live_mode_still_denies_without_calling_errow(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true"})
    response = await gw.tool_call("triage", "nmap", {"target": "169.254.169.254", "scan_type": "-sT"})
    assert response.status == 403 and gw.errow.calls == [] and gw.errow.initializations == 0


@pytest.mark.parametrize("flag", ["TRUE", "1", "yes", "false", ""])
async def test_only_the_literal_string_true_enables_live_mode(make_gateway: Any, flag: str) -> None:
    gw = await make_gateway({"MCP_LIVE": flag})
    response = await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})
    assert response.json()["status"] == "dry_run" and gw.errow.calls == []


async def test_live_output_is_truncated(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true", "MCP_OUTPUT_MAX_CHARS": "300"})
    gw.errow.reply_text = "A" * 5000
    body = (await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})).json()
    assert body["truncated"] is True and len(body["output"]) <= 300


async def test_errow_failure_is_502_and_audited_as_error(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true"})
    gw.errow.http_status = 500
    response = await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})
    assert response.status == 502 and response.json()["status"] == "error" and response.json()["error"] == "http_500"
    events = await gw.events("cs3.ai.tool_call", 2)
    assert [e["decision"] for e in events] == ["allowed", "error"] and events[1]["violations"] == ["errow_mcp:http_500"]
    gw.errow.http_status = 200
    recovered = await gw.tool_call("triage", "shell", {"command": "dig", "target": TARGET}, tenant_id="tenant-b")
    assert recovered.status == 200 and recovered.json()["status"] == "executed"


async def test_unreachable_errow_is_502(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true", "ERROW_MCP_URL": "https://localhost:1/mcp"})
    response = await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})
    assert response.status == 502 and response.json()["error"] == "unreachable"


async def test_live_concurrency_is_capped_by_the_policy(make_gateway: Any) -> None:
    gw = await make_gateway({"MCP_LIVE": "true"})
    gw.errow.delay_s = 0.6
    responses = await asyncio.gather(*(gw.tool_call("forensic", "threat_model", {"run": f"r{i}"}, tenant_id=f"tenant-{i}") for i in range(6)))
    statuses = sorted(r.status for r in responses)
    assert statuses == [200] * 4 + [429] * 2
    limited = next(r for r in responses if r.status == 429)
    assert limited.json()["limited_by"] == "concurrency" and limited.headers["Retry-After"] == "1"


async def test_targets_file_can_only_add_allow_list_entries(make_gateway: Any, tmp_path: Path) -> None:
    extension = tmp_path / "targets.yaml"
    extension.write_text("hostnames: [extra.example.org]\ncidrs: [127.0.0.0/8, 10.99.0.0/16]\ndomains: [corp.example.net]\nrepo_paths: [/workspace/extra/*]\n", encoding="utf-8")
    gw = await make_gateway({"MCP_TARGETS_FILE": str(extension)})
    added = await gw.tool_call("triage", "nmap", {"target": "extra.example.org", "scan_type": "-sT"})
    assert added.status == 200
    assert (await gw.tool_call("triage", "nmap", {"target": "10.99.4.7", "scan_type": "-sT"})).status == 200
    assert (await gw.tool_call("triage", "shell", {"command": "dig", "target": "host.corp.example.net"})).status == 200
    assert (await gw.tool_call("triage", "nmap", {"target": TARGET, "scan_type": "-sT"})).status == 200
    loopback = await gw.tool_call("triage", "nmap", {"target": "127.0.0.1", "scan_type": "-sT"})
    assert loopback.status == 403 and "target:denied_cidr:127.0.0.0/8" in loopback.json()["violations"]
    assert (await gw.tool_call("triage", "nmap", {"target": "8.8.8.8", "scan_type": "-sT"})).status == 403


@pytest.mark.parametrize(
    "content",
    ["denied:\n  hostnames: []\n", "limits:\n  per_tenant_per_minute: 9999\n", "tools: {}\n", "hostnames: not-a-list\n"],
    ids=["denied-section", "limits-section", "tools-section", "wrong-type"],
)
def test_targets_file_cannot_relax_the_policy(tmp_path: Path, content: str) -> None:
    extension = tmp_path / "targets.yaml"
    extension.write_text(content, encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.load(ROOT / "mcp_policy.yaml", extension)


async def test_policy_file_is_loaded_exactly_as_written() -> None:
    policy = Policy.load(ROOT / "mcp_policy.yaml")
    assert policy.live_env == "MCP_LIVE"
    assert (policy.limits.per_tenant_per_minute, policy.limits.cluster_per_minute, policy.limits.per_target_per_minute, policy.limits.max_concurrent) == (10, 100, 6, 4)
    assert sorted(policy.tools) == sorted(["bbot", "nmap", "nuclei", "gobuster", "subfinder", "wafw00f", "trufflehog", "shell",
                                           "agent_browser", "proxy", "web_search", "threat_model", "coverage"])
    assert policy.tools["web_search"].rate_per_minute == 5 and policy.tools["nmap"].rate_per_target_per_minute == 2
    assert policy.tools["nuclei"].forbidden_tag_values == ("dos", "fuzz", "intrusive", "rce-exploit")
    assert policy.tools["agent_browser"].screenshot_retention_days_default == 7
    assert {9200, 9101, 11434, 55000} <= set(policy.denied.ports)
    assert await policy.evaluate("triage", "nmap", {"target": TARGET, "scan_type": "-sT"}, lab_resolver) is not None


def test_policy_loader_rejects_a_permissive_default(tmp_path: Path) -> None:
    broken = tmp_path / "policy.yaml"
    broken.write_text((ROOT / "mcp_policy.yaml").read_text(encoding="utf-8").replace("default_action: deny", "default_action: allow"), encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.load(broken)
