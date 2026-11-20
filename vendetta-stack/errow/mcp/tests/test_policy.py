"""Policy parity with llm-gateway/mcp_policy.yaml semantics (same cases the gateway tests cover)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from conftest import POLICY_FILE, Clock, fake_resolver
from policy import Policy, PolicyError, RateLimited

NMAP = {"target": "scan-target.vendetta.lab", "scan_type": "-sT"}


def has(decision, prefix: str) -> bool:
    return any(v.startswith(prefix) for v in decision.violations)


def test_allows_nmap_sT_against_lab_target(policy: Policy) -> None:
    d = policy.evaluate("nmap", NMAP, "triage")
    assert d.allowed and d.violations == []
    assert d.target_key == "scan-target.vendetta.lab"
    assert d.resolved["scan-target.vendetta.lab"] == ["10.77.0.5"]


@pytest.mark.parametrize(
    "target, prefix",
    [
        ("127.0.0.1", "target:denied_cidr"),
        ("169.254.169.254", "target:denied_cidr"),
        ("metadata.google.internal", "target:denied_host"),
        ("localhost", "target:denied_host"),
        ("scan-target.vendetta.lab:9200", "target:denied_port:9200"),
        ("scan-target.vendetta.lab:11434", "target:denied_port:11434"),
        ("rebind.vendetta.lab", "target:denied_cidr"),
        ("meta.vendetta.lab", "target:denied_cidr"),
        ("mixed.vendetta.lab", "target:denied_cidr"),
        ("2130706433", "target:malformed"),
        ("8.8.8.8", "target:not_allowed"),
    ],
)
def test_denied_targets(policy: Policy, target: str, prefix: str) -> None:
    d = policy.evaluate("nmap", {**NMAP, "target": target}, "triage")
    assert not d.allowed
    assert has(d, prefix), d.violations


def test_denied_wins_over_allow_list(tmp_path: Path, clock: Clock) -> None:
    extra = tmp_path / "targets.yaml"
    extra.write_text("hostnames: [localhost, metadata.google.internal]\ncidrs: [127.0.0.0/8]\n")
    p = Policy.load(POLICY_FILE, resolver=fake_resolver, clock=clock, targets_file=str(extra))
    for t in ("localhost", "metadata.google.internal", "127.0.0.1"):
        assert not p.evaluate("nmap", {**NMAP, "target": t}, "triage").allowed


def test_targets_file_is_additive(tmp_path: Path, clock: Clock) -> None:
    extra = tmp_path / "targets.yaml"
    extra.write_text("hostnames: [lab2.example.test]\ncidrs: [10.99.0.0/24]\nrepo_paths: [/workspace/repos2/*]\n")
    resolver = lambda h: {"lab2.example.test": ["10.99.0.4"]}.get(h) or fake_resolver(h)  # noqa: E731
    p = Policy.load(POLICY_FILE, resolver=resolver, clock=clock, targets_file=str(extra))
    assert p.evaluate("nmap", {**NMAP, "target": "lab2.example.test"}, "triage").allowed
    assert p.evaluate("nmap", NMAP, "triage").allowed
    assert p.evaluate("nmap", {**NMAP, "target": "10.99.0.4"}, "triage").allowed
    assert not p.evaluate("nmap", {**NMAP, "target": "10.98.0.4"}, "triage").allowed


def test_broken_targets_file_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "targets.yaml"
    bad.write_text("hostnames: not-a-list\n")
    with pytest.raises(PolicyError):
        Policy.load(POLICY_FILE, targets_file=str(bad))
    extra = tmp_path / "ok.yaml"
    extra.write_text("hostnames: [lab2.example.test]\n")
    p = Policy.load(POLICY_FILE, resolver=lambda h: ["10.99.0.4"], targets_file=str(extra))
    extra.write_text("hostnames: [[[\n")
    import os

    os.utime(extra, (1, 99999999))
    assert p.allow_lists()["hostnames"] == ["scan-target.vendetta.lab", "lab2.example.test"]
    assert p.targets_error


def test_forbidden_args_and_undeclared(policy: Policy) -> None:
    d = policy.evaluate("nmap", {**NMAP, "--script": "vuln"}, "triage")
    assert not d.allowed and has(d, "forbidden_arg:--script") and has(d, "arg:--script:undeclared")
    d = policy.evaluate("nmap", {**NMAP, "scan_type": "-sS"}, "triage")
    assert not d.allowed and has(d, "arg:scan_type:enum")
    d = policy.evaluate("nmap", {**NMAP, "ports": "1-65535"}, "triage")
    assert not d.allowed
    d = policy.evaluate("bbot", {"target": "scan-target.vendetta.lab", "preset": "safe", "--allow-deadly": True}, "triage")
    assert not d.allowed and has(d, "forbidden_arg:--allow-deadly")


def test_nuclei_forbidden_tag_values(policy: Policy) -> None:
    args = {"target": "https://scan-target.vendetta.lab", "tags": ["cves"]}
    assert policy.evaluate("nuclei", args, "triage").allowed
    for bad in ("dos", "fuzz", "rce-exploit"):
        d = policy.evaluate("nuclei", {**args, "tags": ["cves", bad]}, "triage")
        assert not d.allowed and has(d, "forbidden_tag"), bad
    d = policy.evaluate("nuclei", {**args, "tags": ["cves,dos"]}, "triage")
    assert not d.allowed
    assert not policy.evaluate("nuclei", {**args, "rate_limit": 51}, "triage").allowed


def test_gobuster_threads_max(policy: Policy) -> None:
    args = {"target": "http://scan-target.vendetta.lab", "mode": "dir",
            "wordlist": "/usr/share/wordlists/dirb/common.txt", "threads": 10}
    assert policy.evaluate("gobuster", args, "triage").allowed
    d = policy.evaluate("gobuster", {**args, "threads": 11}, "triage")
    assert not d.allowed and has(d, "arg:threads:max")
    assert not policy.evaluate("gobuster", {**args, "threads": -1}, "triage").allowed
    assert not policy.evaluate("gobuster", {**args, "threads": True}, "triage").allowed
    assert not policy.evaluate("gobuster", {**args, "wordlist": "/etc/passwd"}, "triage").allowed


def test_unknown_tool_and_roles(policy: Policy) -> None:
    assert policy.evaluate("rm", {}, "triage").violations == ["tool:unknown"]
    d = policy.evaluate("nmap", NMAP, "forensic")
    assert d.violations == ["role:not_allowed:forensic"]
    assert policy.evaluate("nmap", NMAP, None).violations == ["role:missing"]
    assert has(policy.evaluate("nmap", NMAP, "root"), "role:invalid")
    assert not policy.evaluate("threat_model", {"run": "r1"}, "triage").allowed
    assert policy.evaluate("threat_model", {"run": "r1"}, "forensic").allowed
    assert policy.evaluate("nmap", ["x"], "triage").violations == ["args:not_an_object"]


@pytest.mark.parametrize("payload", ["scan-target.vendetta.lab; id", "a|b", "$(id)", "`id`", "a&&b", "a>b", "a<b", "a||b"])
def test_shell_metacharacters_denied(policy: Policy, payload: str) -> None:
    d = policy.evaluate("shell", {"command": "dig", "target": payload}, "triage")
    assert not d.allowed
    assert has(d, "forbidden_arg") or has(d, "arg:target:pattern")


def test_shell_command_enum_and_curl_url(policy: Policy) -> None:
    assert policy.evaluate("shell", {"command": "curl -sI", "target": "https://scan-target.vendetta.lab/"}, "triage").allowed
    assert not policy.evaluate("shell", {"command": "curl -X POST", "target": "scan-target.vendetta.lab"}, "triage").allowed
    assert not policy.evaluate("shell", {"command": "dig", "target": "https://scan-target.vendetta.lab/"}, "triage").allowed


def test_repo_path_rules(policy: Policy) -> None:
    ok = {"repo_path": "/workspace/repos/demo/app", "mode": "git"}
    assert policy.evaluate("trufflehog", ok, "triage").allowed
    for bad in ("/workspace/repos/../etc", "/etc/passwd", "/workspace/repos/a/./b", "/workspace/repos//x"):
        assert not policy.evaluate("trufflehog", {"repo_path": bad}, "triage").allowed, bad
    assert not policy.evaluate("trufflehog", {**ok, "no_verification": False}, "triage").allowed


def test_nmap_cidr_only_inside_allow_list(tmp_path: Path, clock: Clock) -> None:
    extra = tmp_path / "t.yaml"
    extra.write_text("cidrs: [10.99.0.0/24]\n")
    p = Policy.load(POLICY_FILE, resolver=fake_resolver, clock=clock, targets_file=str(extra))
    assert p.evaluate("nmap", {**NMAP, "scan_type": "-sn", "target": "10.99.0.0/28"}, "triage").allowed
    assert not p.evaluate("nmap", {**NMAP, "scan_type": "-sn", "target": "10.99.0.0/16"}, "triage").allowed
    assert not p.evaluate("nmap", {**NMAP, "scan_type": "-sn", "target": "10.0.0.0/8"}, "triage").allowed


def test_rate_limit_per_target_and_window(policy: Policy, clock: Clock) -> None:
    d = policy.evaluate("nmap", NMAP, "triage")
    for _ in range(2):
        policy.admit(d, "t1").release()
    with pytest.raises(RateLimited) as exc:
        policy.admit(d, "t1")
    assert exc.value.reason in ("rate:tool_target", "rate:target") and exc.value.retry_after >= 1
    clock.now += 61
    policy.admit(d, "t1").release()


def test_rate_limit_tenant_and_tool(policy: Policy, clock: Clock) -> None:
    d = policy.evaluate("threat_model", {"run": "r1"}, "forensic")
    for _ in range(10):
        policy.admit(d, "tenant-a").release()
    with pytest.raises(RateLimited) as exc:
        policy.admit(d, "tenant-a")
    assert exc.value.reason == "rate:tenant"
    policy.admit(d, "tenant-b").release()
    ws = policy.evaluate("web_search", {"query": "x"}, "forensic")
    for i in range(5):
        policy.admit(ws, f"t{i}").release()
    with pytest.raises(RateLimited) as exc:
        policy.admit(ws, "t9")
    assert exc.value.reason == "rate:tool"


def test_concurrency_cap_and_denied_calls_do_not_consume(policy: Policy) -> None:
    held = [policy.admit(policy.evaluate("threat_model", {"run": f"r{i}"}, "forensic"), f"t{i}") for i in range(4)]
    with pytest.raises(RateLimited) as exc:
        policy.admit(policy.evaluate("coverage", {"run": "r9"}, "forensic"), "t9")
    assert exc.value.reason == "rate:concurrency"
    held[0].release()
    held[0].release()
    policy.admit(policy.evaluate("coverage", {"run": "r9"}, "forensic"), "t9").release()
    for h in held[1:]:
        h.release()
    for _ in range(50):
        assert not policy.evaluate("nmap", {**NMAP, "target": "127.0.0.1"}, "triage").allowed
    policy.admit(policy.evaluate("nmap", NMAP, "triage"), "fresh").release()


def test_input_schema_generated_from_specs(policy: Policy) -> None:
    schema = policy.input_schema("nmap")
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert set(schema["required"]) == {"target", "scan_type"}
    assert schema["properties"]["scan_type"]["enum"] == ["-sn", "-sT", "-sV"]
    assert policy.input_schema("gobuster")["properties"]["threads"]["maximum"] == 10
    assert policy.input_schema("nuclei")["properties"]["tags"]["items"]["enum"][0] == "cves"
    assert set(policy.tools) == {"bbot", "nmap", "nuclei", "gobuster", "subfinder", "wafw00f", "trufflehog", "shell",
                                 "agent_browser", "proxy", "web_search", "threat_model", "coverage"}


def test_live_only_when_env_is_exactly_true(policy: Policy) -> None:
    assert policy.live_enabled({"MCP_LIVE": "true"})
    for v in ("TRUE", "1", "yes", "", "false"):
        assert not policy.live_enabled({"MCP_LIVE": v})
    assert not policy.live_enabled({})


def test_policy_rejects_weakened_documents() -> None:
    doc = yaml.safe_load(POLICY_FILE.read_text())
    weak = copy.deepcopy(doc)
    weak["default_action"] = "allow"
    with pytest.raises(PolicyError):
        Policy(weak)
    weak = copy.deepcopy(doc)
    del weak["denied"]
    with pytest.raises(PolicyError):
        Policy(weak)
