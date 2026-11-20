"""JSON-RPC protocol, audit events, metrics, and the real mTLS listener (throwaway PKI)."""

from __future__ import annotations

import http.client
import json
import ssl
import threading
from pathlib import Path
from typing import Any

import pytest

from conftest import POLICY_FILE, Clock, FakeDocker, fake_resolver, make_leaf, write_ca, write_pair
from events import EventLog
from executor import ExecConfig, Executor
from policy import Policy
from server import (SUPPORTED_VERSIONS, Bridge, McpServer, ServerConfig, build_ssl_context, peer_names,
                    reason_label, run_healthcheck, run_selftest)

NMAP_ARGS = {"target": "scan-target.vendetta.lab", "scan_type": "-sT"}


def rpc(method: str, params: dict[str, Any] | None = None, rid: Any = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        msg["id"] = rid
    if params is not None:
        msg["params"] = params
    return msg


def call(tool: str, args: Any, role: str | None = "triage", **meta: Any) -> dict[str, Any]:
    m = {"role": role, "tenant_id": "tenant-1", "incident_id": "inc-9", "request_id": "req-7",
         "rationale": "triage the exposed host token=abc12345", **meta}
    if role is None:
        m.pop("role")
    return rpc("tools/call", {"name": tool, "arguments": args, "_meta": m})


@pytest.fixture
def bridge(policy: Policy, tmp_path: Path, clock: Clock) -> Bridge:
    ex = Executor(policy, ExecConfig(image="img", docker_host="tcp://x:1", runs_dir=str(tmp_path / "runs")))
    return Bridge(policy, ex, EventLog(tmp_path / "ev" / "mcp_events.ndjson"), env={"MCP_LIVE": "false"}, clock=clock)


def events(bridge: Bridge) -> list[dict[str, Any]]:
    p = bridge.events.path
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_initialize_and_negotiation(bridge: Bridge) -> None:
    r = bridge.handle(rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}}))
    res = r["result"]
    assert res["protocolVersion"] == "2025-03-26" and res["serverInfo"]["name"] == "errow-mcp"
    assert res["capabilities"] == {"tools": {"listChanged": False}}
    assert bridge.handle(rpc("initialize", {"protocolVersion": "1999-01-01"}))["result"]["protocolVersion"] == SUPPORTED_VERSIONS[0]
    assert bridge.handle(rpc("notifications/initialized", rid=None)) is None
    assert bridge.handle(rpc("ping"))["result"] == {}


def test_tools_list_schemas_and_role_filter(bridge: Bridge) -> None:
    tools = bridge.handle(rpc("tools/list"))["result"]["tools"]
    assert len(tools) == 13
    nmap = next(t for t in tools if t["name"] == "nmap")
    assert nmap["inputSchema"]["required"] == ["target", "scan_type"]
    assert nmap["inputSchema"]["properties"]["scan_type"]["enum"] == ["-sn", "-sT", "-sV"]
    assert nmap["inputSchema"]["additionalProperties"] is False
    names = lambda role: {t["name"] for t in bridge.handle(rpc("tools/list", {"_meta": {"role": role}}))["result"]["tools"]}  # noqa: E731
    assert names("forensic") == {"agent_browser", "proxy", "web_search", "threat_model", "coverage"}
    assert "nmap" in names("triage") and "coverage" not in names("triage")


def test_protocol_errors(bridge: Bridge) -> None:
    assert bridge.handle(rpc("nope"))["error"]["code"] == -32601
    assert bridge.handle({"jsonrpc": "1.0", "id": 1, "method": "ping"})["error"]["code"] == -32600
    assert bridge.handle([1])["error"]["code"] == -32600
    assert bridge.handle({"jsonrpc": "2.0", "id": {"a": 1}, "method": "ping"})["error"]["code"] == -32600
    assert bridge.handle(rpc("tools/call", {"arguments": {}}))["error"]["code"] == -32602
    assert bridge.handle({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": [1]})["error"]["code"] == -32602
    assert bridge.handle({"jsonrpc": "2.0", "id": 1, "result": {}}) is None


def test_dry_run_returns_argv_array_and_audits(bridge: Bridge) -> None:
    r = bridge.handle(call("nmap", NMAP_ARGS))["result"]
    s = r["structuredContent"]
    assert r["isError"] is False and s["status"] == "dry_run" and s["live"] is False
    assert s["plan"]["argv"] == ["nmap", "-sT", "scan-target.vendetta.lab", "-oX", "-"]
    assert s["plan"]["sandbox"]["read_only"] is True and s["plan"]["sandbox"]["cap_drop"] == ["ALL"]
    json.loads(r["content"][0]["text"])
    ev = events(bridge)[-1]
    assert ev["event_type"] == "mcp_exec" and ev["stream"] == "mcp_events" and ev["source"] == "errow"
    assert ev["decision"] == "dry_run" and ev["live"] is False and ev["tool"] == "nmap" and ev["role"] == "triage"
    assert ev["tenant_id"] == "tenant-1" and ev["incident_id"] == "inc-9" and ev["request_id"] == "req-7"
    assert ev["target"] == "scan-target.vendetta.lab" and ev["violations"] == [] and "abc12345" not in ev["rationale"]
    assert ev["args"] == NMAP_ARGS and ev["result_summary"].startswith("dry_run nmap") and len(ev["doc_id"]) == 64
    assert ev["@timestamp"].endswith("Z") and ev["run"] == "mcp"


@pytest.mark.parametrize(
    "tool, args, role, needle",
    [
        ("nmap", {**NMAP_ARGS, "target": "127.0.0.1"}, "triage", "target:denied_cidr"),
        ("nmap", {**NMAP_ARGS, "target": "169.254.169.254"}, "triage", "target:denied_cidr"),
        ("nmap", {**NMAP_ARGS, "target": "metadata.google.internal"}, "triage", "target:denied_host"),
        ("nmap", {**NMAP_ARGS, "target": "scan-target.vendetta.lab:9200"}, "triage", "target:denied_port:9200"),
        ("nmap", NMAP_ARGS, "forensic", "role:not_allowed:forensic"),
        ("nmap", NMAP_ARGS, None, "role:missing"),
        ("shell", {"command": "dig", "target": "a;id"}, "triage", "forbidden_arg:;"),
    ],
)
def test_denials_are_reported_audited_and_counted(bridge: Bridge, tool: str, args: Any, role: Any, needle: str) -> None:
    r = bridge.handle(call(tool, args, role))["result"]
    s = r["structuredContent"]
    assert r["isError"] is True and s["status"] == "policy_violation"
    assert any(v.startswith(needle) for v in s["violations"]), s["violations"]
    ev = events(bridge)[-1]
    assert ev["decision"] == "denied" and any(v.startswith(needle) for v in ev["violations"])
    assert "errow_mcp_policy_denied_total" in bridge.render_metrics()


def test_unknown_tool_is_jsonrpc_error(bridge: Bridge) -> None:
    r = bridge.handle(call("rm_rf", {}))
    assert r["error"]["code"] == -32602 and r["error"]["data"]["violations"] == ["tool:unknown"]
    assert events(bridge)[-1]["decision"] == "denied"
    assert 'tool="unknown"' in bridge.render_metrics()


def test_rate_limited_result(bridge: Bridge, clock: Clock) -> None:
    for _ in range(2):
        assert bridge.handle(call("nmap", NMAP_ARGS))["result"]["structuredContent"]["status"] == "dry_run"
    r = bridge.handle(call("nmap", NMAP_ARGS))["result"]
    assert r["structuredContent"]["status"] == "rate_limited" and r["isError"] and r["structuredContent"]["retry_after_s"] >= 1
    assert events(bridge)[-1]["decision"] == "rate_limited"
    clock.now += 61
    assert bridge.handle(call("nmap", NMAP_ARGS))["result"]["structuredContent"]["status"] == "dry_run"


def test_live_requires_exact_env_and_uses_executor(policy: Policy, tmp_path: Path, clock: Clock) -> None:
    dock = FakeDocker()
    dock.containers.next = {"output": [(b"Nmap done\n", None)]}
    ex = Executor(policy, ExecConfig(image="img", docker_host="tcp://x:1"), docker_factory=lambda: dock)
    b = Bridge(policy, ex, EventLog(tmp_path / "e.ndjson"), env={"MCP_LIVE": "TRUE"}, clock=clock)
    assert b.handle(call("nmap", NMAP_ARGS))["result"]["structuredContent"]["status"] == "dry_run"
    assert not dock.containers.created
    b.env["MCP_LIVE"] = "true"
    r = b.handle(call("nmap", {**NMAP_ARGS, "scan_type": "-sV"}))["result"]
    s = r["structuredContent"]
    assert s["status"] == "executed" and s["live"] is True and "Nmap done" in s["output"] and r["isError"] is False
    ev = json.loads((tmp_path / "e.ndjson").read_text().splitlines()[-1])
    assert ev["decision"] == "executed" and ev["live"] is True and ev["exit_code"] == 0 and len(ev["output_sha256"]) == 64
    assert ev["sandbox"]["network"] == "offensive" and ev["output_bytes"] == len(b"Nmap done\n")
    assert len(dock.containers.created) == 1


def test_executor_failure_is_an_error_result(policy: Policy, tmp_path: Path) -> None:
    ex = Executor(policy, ExecConfig(image="img", docker_host=None))
    b = Bridge(policy, ex, EventLog(tmp_path / "e.ndjson"), env={"MCP_LIVE": "true"})
    r = b.handle(call("nmap", NMAP_ARGS))["result"]
    assert r["isError"] and r["structuredContent"]["status"] == "error" and r["structuredContent"]["error"] == "docker_host_unset"
    assert json.loads((tmp_path / "e.ndjson").read_text().splitlines()[-1])["decision"] == "error"


def test_metrics_exposition(bridge: Bridge) -> None:
    bridge.handle(call("nmap", NMAP_ARGS))
    bridge.handle(call("nmap", {**NMAP_ARGS, "target": "127.0.0.1"}))
    text = bridge.render_metrics()
    assert 'errow_mcp_calls_total{tool="nmap",status="dry_run"} 1' in text
    assert 'errow_mcp_calls_total{tool="nmap",status="policy_violation"} 1' in text
    assert 'errow_mcp_policy_denied_total{tool="nmap",reason="target:denied_cidr"} 1' in text
    assert 'errow_mcp_call_duration_seconds_count{tool="nmap"} 2' in text
    assert "errow_mcp_sandbox_running 0" in text and "errow_mcp_live 0" in text


def test_reason_label_cardinality() -> None:
    assert reason_label("arg:--evil-1234:undeclared") == "arg:undeclared"
    assert reason_label("forbidden_arg:--script") == "forbidden_arg"
    assert reason_label("target:denied_cidr:10.0.0.0/8") == "target:denied_cidr"
    assert reason_label("tool:unknown") == "tool:unknown"


def test_event_log_rotation_append_only_and_fault_tolerance(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "mcp_events.ndjson", max_bytes=1500, keep=2)
    for i in range(30):
        log.emit({"tool": "nmap", "decision": "dry_run", "request_id": f"r{i}", "args": {"pad": "x" * 100}})
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["mcp_events.ndjson", "mcp_events.ndjson.1", "mcp_events.ndjson.2"]
    for p in tmp_path.iterdir():
        assert p.stat().st_size <= 1500 + 400
        assert all(json.loads(line)["event_type"] == "mcp_exec" for line in p.read_text().splitlines())
    errs: list[Exception] = []
    bad = EventLog(tmp_path / "file" / "x" / "e.ndjson", on_error=errs.append)
    (tmp_path / "file").write_text("not a dir")
    bad.emit({"tool": "x"})
    assert bad.write_errors == 1 and errs


def test_events_are_sanitized_and_doc_id_stable(tmp_path: Path) -> None:
    fixed = lambda: "2026-01-01T00:00:00.000Z"  # noqa: E731
    a = EventLog(tmp_path / "a.ndjson", now=fixed).emit({"tool": "x", "args": {"k": "password=hunter2\x00 " + "z" * 9000}})
    b = EventLog(tmp_path / "b.ndjson", now=fixed).emit({"tool": "x", "args": {"k": "password=hunter2\x00 " + "z" * 9000}})
    assert a["doc_id"] == b["doc_id"] and "hunter2" not in json.dumps(a) and a["args"]["k"].endswith("...[truncated]")


# ---------------------------------------------------------------------- mTLS listener
class Live:
    def __init__(self, bridge: Bridge, cfg: ServerConfig) -> None:
        self.server = McpServer(cfg, bridge, build_ssl_context(cfg))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def live(bridge: Bridge, pki: dict[str, Any]) -> Any:
    cfg = ServerConfig(bind="127.0.0.1", port=0, pki_dir=str(pki["dir"]), allowed_clients=("llm-gateway", "errow-mcp"),
                       read_timeout=3.0, policy_file=str(POLICY_FILE))
    srv = Live(bridge, cfg)
    yield srv, pki, cfg
    srv.close()


def client_ctx(pki: dict[str, Any], *, cn: str | None, ca_pair: Any = None, trust: Any = None) -> ssl.SSLContext:
    d: Path = pki["tmp"] / f"c-{cn or 'none'}-{id(ca_pair)}"
    d.mkdir(exist_ok=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(write_ca(d, trust or pki["ca"], "trust")))
    if cn:
        crt, key = write_pair(d, "client", make_leaf(ca_pair or pki["ca"], cn))
        ctx.load_cert_chain(str(crt), str(key))
    return ctx


def request(port: int, ctx: ssl.SSLContext, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None):
    conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=5)
    try:
        payload = json.dumps(body) if body is not None else None
        h = {"Content-Type": "application/json", **(headers or {})} if payload is not None else (headers or {})
        conn.request(method, path, body=payload, headers=h)
        resp = conn.getresponse()
        return resp.status, resp.read(), dict(resp.getheaders())
    finally:
        conn.close()


def test_mtls_valid_client_full_protocol(live: Any) -> None:
    srv, pki, _ = live
    ctx = client_ctx(pki, cn="llm-gateway")
    status, body, headers = request(srv.port, ctx, "GET", "/health")
    assert status == 200 and json.loads(body)["status"] == "ok" and headers["Cache-Control"] == "no-store"
    status, body, _ = request(srv.port, ctx, "POST", "/mcp", rpc("initialize", {"protocolVersion": "2025-06-18"}),
                              {"MCP-Protocol-Version": "2025-06-18"})
    assert status == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "errow-mcp"
    status, body, _ = request(srv.port, ctx, "POST", "/mcp", call("nmap", NMAP_ARGS))
    assert json.loads(body)["result"]["structuredContent"]["plan"]["argv"][0] == "nmap"
    status, body, _ = request(srv.port, ctx, "POST", "/mcp", rpc("notifications/initialized", rid=None))
    assert status == 202 and body == b""
    status, body, _ = request(srv.port, ctx, "POST", "/mcp", [rpc("ping", rid=1), rpc("ping", rid=2)])
    assert [r["id"] for r in json.loads(body)] == [1, 2]
    status, body, _ = request(srv.port, ctx, "GET", "/metrics")
    assert status == 200 and b"errow_mcp_calls_total" in body and b"errow_mcp_sandbox_running" in body


def test_http_edge_cases(live: Any) -> None:
    srv, pki, cfg = live
    ctx = client_ctx(pki, cn="llm-gateway")
    assert request(srv.port, ctx, "GET", "/mcp")[0] == 405
    assert request(srv.port, ctx, "DELETE", "/mcp")[0] == 405
    assert request(srv.port, ctx, "GET", "/nope")[0] == 404
    assert request(srv.port, ctx, "POST", "/mcp", rpc("ping"), {"MCP-Protocol-Version": "1999-01-01"})[0] == 400
    assert request(srv.port, ctx, "POST", "/mcp", rpc("ping"), {"Origin": "https://evil.example"})[0] == 403
    conn = http.client.HTTPSConnection("localhost", srv.port, context=ctx, timeout=5)
    conn.request("POST", "/mcp", body=b"{not json", headers={"Content-Type": "application/json"})
    assert json.loads(conn.getresponse().read())["error"]["code"] == -32700
    conn.request("POST", "/mcp", body=b"x", headers={"Content-Type": "text/plain"})
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 415
    big = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * (cfg.max_body + 10)}}
    assert request(srv.port, ctx, "POST", "/mcp", big)[0] == 413


def test_mtls_rejects_missing_wrong_ca_and_unlisted_client(live: Any) -> None:
    srv, pki, _ = live
    with pytest.raises((ssl.SSLError, ConnectionError, http.client.HTTPException, OSError)):
        request(srv.port, client_ctx(pki, cn=None), "GET", "/health")
    with pytest.raises((ssl.SSLError, ConnectionError, http.client.HTTPException, OSError)):
        request(srv.port, client_ctx(pki, cn="llm-gateway", ca_pair=pki["other"]), "GET", "/health")
    ctx = client_ctx(pki, cn="somebody-else")
    assert request(srv.port, ctx, "GET", "/health")[0] == 200
    assert request(srv.port, ctx, "POST", "/mcp", rpc("ping"))[0] == 403
    assert "errow_mcp_tls_failures_total" in srv.server.bridge.render_metrics()
    assert srv.server.bridge.metrics.tls_failures >= 1 and srv.server.bridge.metrics.rejected_clients >= 1


def test_server_tls_context_is_strict(live: Any) -> None:
    srv, _, _ = live
    assert srv.server.ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert srv.server.ctx.verify_mode == ssl.CERT_REQUIRED


def test_healthcheck_and_selftest_cli(live: Any, capsys: pytest.CaptureFixture[str]) -> None:
    srv, pki, cfg = live
    cfg.port = srv.port
    assert run_healthcheck(cfg) == 0
    cfg.port = 1
    assert run_healthcheck(cfg) == 1
    assert run_selftest(ServerConfig(policy_file=str(POLICY_FILE))) == 0
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["ok"] is True


def test_peer_names() -> None:
    cert = {"subject": ((("commonName", "llm-gateway"),),), "subjectAltName": (("DNS", "llm-gateway"), ("IP Address", "1.2.3.4"))}
    assert peer_names(cert) == {"llm-gateway"} and peer_names(None) == set()


def test_resolver_is_not_called_for_denied_names_and_uses_injected(policy: Policy) -> None:
    seen: list[str] = []
    p = Policy.load(POLICY_FILE, resolver=lambda h: seen.append(h) or fake_resolver(h))
    p.evaluate("nmap", {**NMAP_ARGS, "target": "metadata.google.internal"}, "triage")
    assert seen == []
