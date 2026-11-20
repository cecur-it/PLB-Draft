"""Executor: argv arrays, dry-run (no Docker), hardened container spec on a FAKE Docker client, readers, caps."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import POLICY_FILE, FakeContainer, FakeDocker, FakeNetwork, fake_resolver
from executor import ExecConfig, Executor, build_plan
from policy import Policy
from server import SELFTEST_CALLS

IMAGE = "errow-sandbox:test"
META = re.compile(r"[;&|`$<>]")


def make(policy: Policy, docker: FakeDocker | None = None, **cfg: Any) -> Executor:
    config = ExecConfig(image=IMAGE, docker_host="tcp://errow-dind:2376", **cfg)
    return Executor(policy, config, docker_factory=(lambda: docker) if docker else None)


def decide(policy: Policy, tool: str, **override: Any):
    role, args = SELFTEST_CALLS[tool]
    d = policy.evaluate(tool, {**args, **override}, role)
    assert d.allowed, d.violations
    return d


@pytest.mark.parametrize("tool", sorted(SELFTEST_CALLS))
def test_every_tool_plans_argv_arrays_and_dry_run_never_touches_docker(policy: Policy, tool: str) -> None:
    def boom() -> Any:
        raise AssertionError("docker must not be touched in dry-run")

    ex = Executor(policy, ExecConfig(image=IMAGE, docker_host="tcp://x:1"), docker_factory=boom)
    plan = ex.plan(decide(policy, tool))
    out = ex.dry_run(plan)
    assert isinstance(out["argv"], list) and all(isinstance(x, str) for x in out["argv"])
    assert out["steps"] and all(isinstance(s, list) for s in out["steps"])
    assert out["timeout_s"] == policy.tools[tool]["timeout_s"]
    json.dumps(out)
    if tool not in ("agent_browser", "proxy", "web_search", "threat_model", "coverage"):
        assert not any(META.search(tok) for tok in out["argv"]), out["argv"]
        assert "sh" not in out["argv"][:1] and "bash" not in out["argv"][:1]


def test_exact_argv_for_cli_tools(policy: Policy) -> None:
    ex = make(policy)
    assert ex.plan(decide(policy, "nmap")).steps == [["nmap", "-sT", "-p", "1-1024", "-T3", "scan-target.vendetta.lab", "-oX", "-"]]
    assert ex.plan(decide(policy, "bbot")).steps == [[
        "bbot", "-t", "scan-target.vendetta.lab", "-p", "safe", "-f", "passive", "-rf", "passive", "--silent", "--json",
        "-y", "--no-deps", "-n", "mcp", "-o", "/tmp/bbot"]]
    nuclei = ex.plan(decide(policy, "nuclei")).steps[0]
    assert nuclei[:5] == ["nuclei", "-u", "https://scan-target.vendetta.lab", "-tags", "cves,exposures"]
    assert nuclei[-5:] == ["-duc", "-ni", "-nc", "-silent", "-jsonl"] and "-rl" in nuclei and "10" in nuclei
    gob = ex.plan(decide(policy, "gobuster")).steps[0]
    assert gob[:3] == ["gobuster", "dir", "-u"] and gob[gob.index("-t") + 1] == "5"
    assert ex.plan(decide(policy, "subfinder")).steps[0][:3] == ["subfinder", "-d", "vendetta.lab"]
    assert ex.plan(decide(policy, "wafw00f")).steps[0][-1] == "https://scan-target.vendetta.lab"
    assert ex.plan(decide(policy, "shell")).steps == [["dig", "+time=3", "+tries=1", "scan-target.vendetta.lab"]]
    assert ex.plan(decide(policy, "shell", command="curl -sI")).steps[0][-2:] == ["--", "scan-target.vendetta.lab"]
    tf = ex.plan(decide(policy, "trufflehog", mode="git")).steps[0]
    assert tf == ["trufflehog", "git", "file:///workspace/repos/demo", "--json", "--no-verification", "--no-update"]


def test_untrusted_values_stay_single_argv_tokens(policy: Policy) -> None:
    plan = build_plan(decide(policy, "web_search", query="a b; rm -rf / $(id)"), ExecConfig())
    assert plan.steps[0][0:2] == ["python3", "-c"]
    assert "rm -rf" not in plan.steps[0][2]
    assert plan.env["WS_QUERY"].startswith("a b;")


def test_dry_run_sandbox_spec_is_hardened(policy: Policy) -> None:
    ex = make(policy)
    spec = ex.dry_run(ex.plan(decide(policy, "nmap")))["sandbox"]
    assert spec["read_only"] is True and spec["cap_drop"] == ["ALL"] and spec["privileged"] is False
    assert spec["network_mode"] == "offensive" and spec["volumes"] == {} and spec["auto_remove"] is True
    assert spec["entrypoint"] == ["nmap"] and spec["command"][0] == "-sT"


def test_live_container_spec_hardening(policy: Policy, docker: FakeDocker) -> None:
    docker.containers.next = {"output": [(b"<nmaprun>", None), (None, b"warn"), (b"</nmaprun>\n", None)]}
    ex = make(policy, docker, mem_limit="512m", cpus=0.5, pids_limit=64)
    res = ex.run(ex.plan(decide(policy, "nmap")), request_id="req-1")
    assert res.status == "executed" and res.exit_code == 0 and "<nmaprun>" in res.output and "warn" in res.stderr
    kw = docker.containers.created[0].kwargs
    assert kw["image"] == IMAGE
    assert kw["entrypoint"] == ["nmap"] and kw["command"][-3:] == ["scan-target.vendetta.lab", "-oX", "-"]
    assert kw["network_mode"] == "offensive" and kw["read_only"] is True and kw["privileged"] is False
    assert kw["cap_drop"] == ["ALL"] and kw["cap_add"] == ["NET_RAW", "NET_ADMIN", "NET_BIND_SERVICE"]
    assert kw["security_opt"] == ["no-new-privileges:true"]
    assert kw["pids_limit"] == 64 and kw["mem_limit"] == "512m" and kw["memswap_limit"] == "512m"
    assert kw["nano_cpus"] == 500_000_000
    assert kw["auto_remove"] is True and kw["init"] is True and kw["user"] == "pentester"
    assert kw["volumes"] == {} and "binds" not in kw and kw["tty"] is False and kw["stdin_open"] is False
    assert kw["tmpfs"]["/tmp"].startswith("rw,noexec,nosuid,nodev")
    assert kw["labels"]["vendetta.component"] == "errow-mcp-exec" and kw["labels"]["errow-mcp-request"] == "req-1"
    assert kw["extra_hosts"] == {"scan-target.vendetta.lab": "10.77.0.5"}
    assert "environment" in kw and "DOCKER_HOST" not in kw["environment"]
    calls = docker.containers.calls
    assert calls.index("attach") < calls.index("start") and calls.index("wait:removed") < calls.index("remove:True")
    assert calls[-1] == "remove:True" and docker.containers.removed == 1
    assert res.output_sha256 and res.output_bytes == len(b"<nmaprun></nmaprun>\n")


def test_only_nmap_and_ping_get_capabilities(policy: Policy, docker: FakeDocker) -> None:
    ex = make(policy, docker)
    for tool, caps in (("bbot", []), ("nuclei", []), ("subfinder", []), ("shell", [])):
        ex.run(ex.plan(decide(policy, tool)))
        assert docker.containers.created[-1].kwargs["cap_add"] == caps, tool
    ex.run(ex.plan(decide(policy, "shell", command="ping -c 3")))
    assert docker.containers.created[-1].kwargs["cap_add"] == ["NET_RAW"]
    assert all(c.kwargs["cap_drop"] == ["ALL"] for c in docker.containers.created)


def test_trufflehog_only_repo_mount_ro_no_network_raw_stripped(policy: Policy, docker: FakeDocker) -> None:
    line = json.dumps({"DetectorName": "AWS", "Raw": "AKIAXXXXXXXXXXXXXXXX", "RawV2": "x", "SourceMetadata": {"p": 1}})
    docker.containers.next = {"output": [(line.encode() + b"\nnot json\n", None)]}
    ex = make(policy, docker, repos_source="/srv/repos")
    res = ex.run(ex.plan(decide(policy, "trufflehog")))
    kw = docker.containers.created[0].kwargs
    assert kw["volumes"] == {"/srv/repos": {"bind": "/workspace/repos", "mode": "ro"}}
    assert kw["network_mode"] == "none" and kw["network_disabled"] is True
    assert "Raw" not in res.output and "AKIA" not in res.output and "AWS" in res.output
    ex2 = make(policy, FakeDocker())
    assert ex2.run(ex2.plan(decide(policy, "trufflehog"))).error == "repos_not_mounted"


def test_never_on_host_without_docker_host(policy: Policy) -> None:
    ex = Executor(policy, ExecConfig(image=IMAGE, docker_host=None))
    res = ex.run(ex.plan(decide(policy, "nmap")))
    assert res.status == "error" and res.error == "docker_host_unset"
    ex = Executor(policy, ExecConfig(image=None, docker_host="tcp://x:1"), docker_factory=lambda: FakeDocker())
    assert ex.run(ex.plan(decide(policy, "nmap"))).error == "no_image"


@pytest.mark.parametrize("net", ["host", "bridge", "default", "vendetta-edge", "vendetta-storage", "vendetta_inference"])
def test_forbidden_sandbox_networks(policy: Policy, net: str) -> None:
    from executor import ExecError

    with pytest.raises(ExecError):
        make(policy, network=net).plan(decide(policy, "nmap"))


def test_network_with_vendetta_services_refused(policy: Policy) -> None:
    dock = FakeDocker({"offensive": FakeNetwork({"abc": {"Name": "vendetta-stack-ollama-lb-1"}})})
    ex = make(policy, dock)
    res = ex.run(ex.plan(decide(policy, "nmap")))
    assert res.error == "network_not_isolated" and not dock.containers.created
    ex = make(policy, FakeDocker({}), create_network=False)
    assert ex.run(ex.plan(decide(policy, "nmap"))).error == "network_missing"


def test_missing_sandbox_network_is_created_once(policy: Policy) -> None:
    dock = FakeDocker({})
    ex = make(policy, dock)
    assert ex.run(ex.plan(decide(policy, "nmap"))).error is None
    assert ex.run(ex.plan(decide(policy, "nmap"))).error is None
    name, kw = dock.networks.created[0]
    assert name == "offensive" and len(dock.networks.created) == 1
    assert kw["driver"] == "bridge" and kw["labels"] == {"vendetta.component": "errow-mcp-sandbox"}


def test_timeout_kills_container(policy: Policy, docker: FakeDocker) -> None:
    import copy

    import yaml as _y

    doc = _y.safe_load(POLICY_FILE.read_text())
    doc = copy.deepcopy(doc)
    doc["tools"]["nmap"]["timeout_s"] = 1
    quick = Policy(doc, resolver=fake_resolver)
    docker.containers.next = {"block_until_killed": True}
    ex = make(quick, docker)
    started = time.monotonic()
    res = ex.run(ex.plan(quick.evaluate("nmap", {"target": "scan-target.vendetta.lab", "scan_type": "-sT"}, "triage")))
    assert res.status == "error" and res.error == "timeout" and time.monotonic() - started < 8
    assert "kill" in docker.containers.calls and docker.containers.removed == 1


def test_output_cap_kills_and_marks_truncated(policy: Policy, docker: FakeDocker) -> None:
    docker.containers.next = {"output": [(b"A" * 600, None) for _ in range(10)]}
    ex = make(policy, docker, output_max_bytes=1000)
    res = ex.run(ex.plan(decide(policy, "subfinder")))
    assert res.truncated and "kill" in docker.containers.calls and res.output_bytes >= 1000


def test_output_is_sanitized(policy: Policy, docker: FakeDocker) -> None:
    secret = b"hello\x07\x1b[31m token=abcd1234 Authorization: Bearer eyJhbGciOi.payload.sig " + b"B" * 9000
    docker.containers.next = {"output": [(secret, None)]}
    ex = make(policy, docker)
    res = ex.run(ex.plan(decide(policy, "subfinder")))
    assert "abcd1234" not in res.output and "eyJhbGciOi" not in res.output and "\x07" not in res.output
    assert "[REDACTED]" in res.output and res.output.endswith("...[truncated]") and res.truncated
    assert len(res.output.encode()) <= 8000 + len("...[truncated]")
    assert len(res.summary) <= 500


def test_nonzero_exit_and_docker_errors_do_not_crash(policy: Policy, docker: FakeDocker) -> None:
    docker.containers.next = {"exit_code": 2}
    ex = make(policy, docker)
    assert ex.run(ex.plan(decide(policy, "nmap"))).exit_code == 2

    class Broken(FakeDocker):
        def __init__(self) -> None:
            super().__init__()
            self.containers.create = lambda **kw: (_ for _ in ()).throw(RuntimeError("daemon down token=s3cr3t"))  # type: ignore

    ex = make(policy, Broken())
    res = ex.run(ex.plan(decide(policy, "nmap")))
    assert res.status == "error" and res.error == "executor_failure" and "s3cr3t" not in (res.message or "")
    assert ex.running == 0


def test_agent_browser_session_steps(policy: Policy, docker: FakeDocker) -> None:
    ex = make(policy, docker)
    plan = ex.plan(decide(policy, "agent_browser"))
    assert plan.kind == "container-session" and plan.shm_size == "256m"
    docker.containers.next = {}
    orig = docker.containers.create

    def create(**kw: Any) -> FakeContainer:
        c = orig(**kw)
        c.exec_results = [(0, (b"opened\n", None)), (0, (b"- heading 'Welcome' [ref=e1]\n", None)), (0, (b"shot\n", None)),
                          (0, (b"ab12  /tmp/shots/page.png\n", None)), (0, (b"closed\n", None))]
        return c

    docker.containers.create = create  # type: ignore[method-assign]
    res = ex.run(plan)
    c = docker.containers.created[0]
    assert c.kwargs["entrypoint"] == ["sleep"] and c.kwargs["read_only"] is True and c.kwargs["cap_drop"] == ["ALL"]
    assert [x["cmd"][3] if x["cmd"][0] == "agent-browser" else x["cmd"][0] for x in c.exec_calls] == [
        "open", "snapshot", "screenshot", "sha256sum", "close"]
    assert all(x["user"] == "pentester" for x in c.exec_calls)
    assert "Welcome" in res.output and res.status == "executed"
    assert docker.containers.removed == 1


def test_proxy_execs_in_running_run_sandbox_only(policy: Policy, docker: FakeDocker) -> None:
    ex = make(policy, docker)
    plan = ex.plan(decide(policy, "proxy"))
    assert ex.run(plan).error == "no_running_sandbox"
    mine = FakeContainer(docker.containers, {"labels": {"vendetta.component": "errow-mcp-exec", "errow-run-id": "r9"}})
    old = FakeContainer(docker.containers, {"labels": {"errow-run-id": "r1"}})
    new = FakeContainer(docker.containers, {"labels": {"errow-run-id": "r2"}})
    old.attrs["Created"], new.attrs["Created"] = "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"
    new.exec_results = [(0, (json.dumps({"data": {"requests": {"edges": []}}}).encode(), None))]
    docker.containers.listing = [mine, old, new]
    res = ex.run(plan)
    assert res.status == "executed" and new.exec_calls and not mine.exec_calls and not old.exec_calls
    call = new.exec_calls[0]
    assert call["cmd"][:2] == ["python3", "-c"] and call["environment"]["PROXY_HOST"] == "scan-target.vendetta.lab"
    assert call["environment"]["PROXY_ACTION"] == "list_requests"
    assert docker.containers.list_filters == {"label": ["errow-run-id"], "status": "running"}
    assert not docker.containers.created


def test_web_search_needs_key_and_keeps_it_out_of_argv(policy: Policy, docker: FakeDocker, tmp_path: Path) -> None:
    ex = make(policy, docker)
    assert ex.run(ex.plan(decide(policy, "web_search"))).status == "unconfigured"
    key = tmp_path / "exa.key"
    key.write_text("exa-secret-key\n")
    ex = make(policy, docker, search_key_file=str(key))
    plan = ex.plan(decide(policy, "web_search"))
    assert "exa-secret-key" not in json.dumps(ex.dry_run(plan))
    ex.run(plan)
    kw = docker.containers.created[-1].kwargs
    assert kw["environment"]["WS_KEY"] == "exa-secret-key" and "exa-secret-key" not in " ".join(kw["command"])


def write_run(root: Path) -> None:
    (root / "demo" / ".state").mkdir(parents=True)
    (root / "demo" / ".state" / "threat_models.json").write_text(json.dumps(
        {"agent-1": {"target": "https://scan-target.vendetta.lab", "content": "STRIDE token=abc12345", "written_by": "a"}}))
    (root / "demo" / "coverage.json").write_text(json.dumps(
        {"schema_version": 1, "run_id": "demo", "summary": {"covered": 3}, "entries": [1, 2], "gaps": [1]}))


def test_readers_are_read_only_and_path_safe(policy: Policy, tmp_path: Path) -> None:
    write_run(tmp_path)
    ex = make(policy, runs_dir=str(tmp_path))
    tm = ex.run(ex.plan(decide(policy, "threat_model")))
    assert tm.status == "executed" and "agent-1" in tm.output and "abc12345" not in tm.output
    full = ex.run(ex.plan(decide(policy, "threat_model", format="full")))
    assert "STRIDE" in full.output and "abc12345" not in full.output
    cov = json.loads(ex.run(ex.plan(decide(policy, "coverage"))).output)
    assert cov["entries"] == 2 and cov["gaps"] == 1
    assert ex.run(ex.plan(decide(policy, "coverage", run="missing"))).error == "not_found"
    outside = tmp_path.parent / "secret.json"
    outside.write_text("{}")
    d = policy.evaluate("coverage", {"run": ".."}, "forensic")
    if d.allowed:
        assert ex.run(ex.plan(d)).error == "bad_run"
    (tmp_path / "link").symlink_to(tmp_path.parent)
    assert ex.run(ex.plan(decide(policy, "coverage", run="link"))).status == "error"


def test_in_flight_counter_returns_to_zero(policy: Policy, docker: FakeDocker) -> None:
    ex = make(policy, docker)
    ex.run(ex.plan(decide(policy, "nmap")))
    assert ex.running == 0


def test_mcp_server_yaml_lists_every_policy_tool() -> None:
    doc = yaml.safe_load((POLICY_FILE.parent / "mcp-server.yaml").read_text())
    pol = yaml.safe_load(POLICY_FILE.read_text())
    assert sorted(t["name"] for t in doc["tools"]) == sorted(pol["tools"])
    assert doc["transport"] == "streamable-http" and doc["url"] == "https://errow-mcp:9103/mcp"
