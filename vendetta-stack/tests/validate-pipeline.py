#!/usr/bin/env python3
"""End-to-end pipeline validator (stdlib only) — drives the smoke test and emits JUnit XML.

Traces: PROMPT §3 Phase 4 (validate-pipeline.py), gates G8 (schema round trip), G9 (offensive safety),
G11 (loop guard), G12 (LLM failover), G13 (audit chain).

It runs INSIDE the compose network (service `smoke-runner`, profile `test`) so no port has to be published.
Stages are invoked by ``tests/smoke-test.sh`` between mock-Ollama state changes:

  ingest        post fixtures to Fluent Bit, drop an Errow run dir for the shipper, call the gateway
  pipeline      wait for + assert documents in OpenSearch, sanitization, loop guard, audit chain
  guardrails    prompt-injection, telemetry-loop 400, JSON-schema conformance
  mcp           gateway /mcp/tool_call policy matrix + errow-mcp bridge JSON-RPC
  baseline      triage answered by the primary model, no fallback
  failover1     (nemotron down)  -> forensic model answered, fallback reason recorded
  failover2     (both down)      -> `Cecur Heuristics`, fallback true
  metrics       Prometheus targets/rules, Fluentd + gateway metric families
  record NAME   append one externally-computed result (``--status pass|fail --message ...``)
  report        write JUnit XML + print summary; exit 1 when anything failed

Exit codes: 0 all passed, 1 failures, 2 usage/environment error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

ENV = os.environ.get
OPENSEARCH_URL = ENV("OPENSEARCH_URL", "https://opensearch:9200")
OS_USER = ENV("OPENSEARCH_USER", "admin")
OS_PASSWORD_FILE = ENV("OPENSEARCH_PASSWORD_FILE", "/run/secrets/opensearch_admin_password")
CA_FILE = ENV("CA_FILE", "/pki/ca.crt")
FLUENT_BIT_HTTP = ENV("FLUENT_BIT_HTTP", "http://fluent-bit:9880")
GATEWAY_URL = ENV("GATEWAY_URL", "https://llm-gateway:9101")
GATEWAY_TOKEN_FILE = ENV("GATEWAY_TOKEN_FILE", "/run/secrets/llm_gateway_token")
ERROW_MCP_URL = ENV("ERROW_MCP_URL", "https://errow-mcp:9103/mcp")
CLIENT_CERT = ENV("CLIENT_CERT", "/pki/errow.crt")
CLIENT_KEY = ENV("CLIENT_KEY", "/pki/errow.key")
SINK_URL = ENV("SINK_URL", "http://sink:8080")
PROMETHEUS_URL = ENV("PROMETHEUS_URL", "http://prometheus:9090")
FLUENTD_METRICS = ENV("FLUENTD_METRICS", "http://fluentd-1:24231/metrics")
FIXTURES = Path(ENV("FIXTURES_DIR", "/tests/synthetic-logs"))
RUNS_DIR = Path(ENV("ERROW_RUNS_DIR", "/workspace/errow_runs"))
RESULTS_DIR = Path(ENV("RESULTS_DIR", "/results"))
WAIT_SECONDS = int(ENV("PIPELINE_WAIT_SECONDS", "150"))
RUN_NAME = ENV("SMOKE_RUN_NAME", "smoke-run")
LOOP_MARKER = "model runner crashed"
STATE = RESULTS_DIR / "results.json"


# --------------------------------------------------------------------------- results bookkeeping
def _load() -> list[dict[str, Any]]:
    if STATE.exists():
        return json.loads(STATE.read_text())
    return []


def _save(rows: list[dict[str, Any]]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(rows, indent=1))
    tmp.replace(STATE)


def record(stage: str, name: str, ok: bool, message: str = "", seconds: float = 0.0) -> bool:
    rows = [r for r in _load() if not (r["stage"] == stage and r["name"] == name)]
    rows.append({"stage": stage, "name": name, "ok": ok, "message": message, "seconds": round(seconds, 3)})
    _save(rows)
    print(f"{'PASS' if ok else 'FAIL'}  [{stage}] {name}" + (f" — {message}" if message and not ok else ""), flush=True)
    return ok


def check(stage: str) -> Callable[[Callable[[], None]], Callable[[], bool]]:
    """Run a function as one JUnit test case; AssertionError/any exception ⇒ failure."""

    def deco(fn: Callable[[], None]) -> Callable[[], bool]:
        def run() -> bool:
            started = time.time()
            try:
                fn()
            except AssertionError as exc:
                return record(stage, fn.__name__, False, str(exc) or "assertion failed", time.time() - started)
            except Exception as exc:  # noqa: BLE001 — a crashing check is a failed check
                return record(stage, fn.__name__, False, f"{type(exc).__name__}: {exc}", time.time() - started)
            return record(stage, fn.__name__, True, "", time.time() - started)

        run.__name__ = fn.__name__
        return run

    return deco


# --------------------------------------------------------------------------- HTTP helpers
def _read(path: str) -> str:
    return Path(path).read_text().strip()


def _ctx(client_cert: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_FILE)
    if client_cert:
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return ctx


def http(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None,
         *, tls_client: bool = False, timeout: float = 30.0, raw: bool = False) -> tuple[int, Any]:
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        if isinstance(body, (bytes, str)):
            data = body if isinstance(body, bytes) else body.encode()
        else:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    ctx = _ctx(tls_client) if url.startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload, code = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        payload, code = exc.read(), exc.code
    if raw:
        return code, payload.decode("utf-8", "replace")
    try:
        return code, json.loads(payload) if payload else None
    except ValueError:
        return code, payload.decode("utf-8", "replace")


def os_req(method: str, path: str, body: Any = None) -> tuple[int, Any]:
    auth = base64.b64encode(f"{OS_USER}:{_read(OS_PASSWORD_FILE)}".encode()).decode()
    return http(method, OPENSEARCH_URL + path, body, {"Authorization": f"Basic {auth}"})


def gw(method: str, path: str, body: Any = None, *, auth: bool = True, raw: bool = False) -> tuple[int, Any]:
    headers = {"Authorization": f"Bearer {_read(GATEWAY_TOKEN_FILE)}"} if auth else {}
    return http(method, GATEWAY_URL + path, body, headers, raw=raw, timeout=90)


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def os_search(index: str, query: dict[str, Any], size: int = 50) -> list[dict[str, Any]]:
    code, res = os_req("POST", f"/{index}/_search?ignore_unavailable=true&allow_no_indices=true",
                       {"query": query, "size": size})
    if code != 200:
        return []
    return [h["_source"] | {"_id": h["_id"], "_index": h["_index"]} for h in res["hits"]["hits"]]


def wait_for(desc: str, fn: Callable[[], Any], seconds: int = WAIT_SECONDS) -> Any:
    deadline, last = time.time() + seconds, None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            last = exc
        time.sleep(3)
    raise AssertionError(f"timed out after {seconds}s waiting for {desc} (last={last!r})")


def _refresh() -> None:
    os_req("POST", "/_refresh")


# --------------------------------------------------------------------------- stage: ingest
def stage_ingest() -> bool:
    ok = True

    @check("ingest")
    def post_vendetta_alert() -> None:
        alert = fixture("vendetta-alert.json")
        code, _ = http("POST", f"{FLUENT_BIT_HTTP}/vendetta.alerts", alert)
        assert code in (200, 201, 204), f"Fluent Bit http input returned {code}"

    @check("ingest")
    def post_vendetta_fim() -> None:
        code, _ = http("POST", f"{FLUENT_BIT_HTTP}/vendetta.fim", fixture("vendetta-fim.json"))
        assert code in (200, 201, 204), f"returned {code}"

    @check("ingest")
    def post_sanitization_probe() -> None:
        # NUL + control chars, a >8000 char tail, a Bearer token and key=value secrets
        message = ("sshd failed login\x00\x07 Authorization: Bearer abcDEF123456.secretvalue password=hunter2 "
                   + "A" * 9000)
        probe = fixture("vendetta-alert.json") | {"id": "smoke-sanitize-1", "full_log": message}
        code, _ = http("POST", f"{FLUENT_BIT_HTTP}/vendetta.alerts", probe)
        assert code in (200, 201, 204), f"returned {code}"

    @check("ingest")
    def post_ollama_journal() -> None:
        rec = {"SYSTEMD_UNIT": "ollama.service", "PRIORITY": "3",
               "MESSAGE": f"level=ERROR source=runner.go msg=\"{LOOP_MARKER}\" gpu=0 (inference server fault)"}
        code, _ = http("POST", f"{FLUENT_BIT_HTTP}/host.journal", rec)
        assert code in (200, 201, 204), f"returned {code}"

    @check("ingest")
    def drop_errow_run() -> None:
        run = RUNS_DIR / RUN_NAME
        (run / ".state").mkdir(parents=True, exist_ok=True)
        pairs = [("errow-finding.sarif.json", "findings.sarif"), ("errow-run.json", "run.json"),
                 ("errow-threat-model.json", ".state/threat_models.json")]
        for src, dst in pairs:
            tmp = run / (dst + ".tmp")
            tmp.write_bytes((FIXTURES / src).read_bytes())
            tmp.replace(run / dst)  # atomic rewrite, same as Errow itself

    for fn in (post_vendetta_alert, post_vendetta_fim, post_sanitization_probe, post_ollama_journal, drop_errow_run):
        ok &= fn()
    return ok


# --------------------------------------------------------------------------- stage: pipeline
def stage_pipeline() -> bool:
    ok = True

    @check("pipeline")
    def vendetta_alert_indexed() -> None:
        alert = fixture("vendetta-alert.json")
        docs = wait_for("vendetta-alerts doc", lambda: (_refresh(), os_search("vendetta-alerts*", {"ids": {"values": [alert["id"]]}}))[1])
        assert docs[0].get("severity") in {"critical", "high", "medium", "low", "info"}, f"bad severity {docs[0].get('severity')}"

    @check("pipeline")
    def vendetta_fim_indexed() -> None:
        fim = fixture("vendetta-fim.json")
        docs = wait_for("FIM alert", lambda: (_refresh(), os_search("vendetta-alerts*", {"ids": {"values": [fim["id"]]}}))[1])
        assert docs, "no FIM doc"

    @check("pipeline")
    def edge_sanitization_applied() -> None:
        docs = wait_for("sanitization probe", lambda: (_refresh(), os_search("vendetta-alerts*", {"ids": {"values": ["smoke-sanitize-1"]}}))[1])
        text = docs[0].get("full_log", "")
        assert "\x00" not in text and "\x07" not in text, "control characters survived the edge"
        assert len(text) <= 8000 + len("...[truncated]") + 8, f"message not truncated ({len(text)} chars)"
        assert "abcDEF123456" not in text and "hunter2" not in text, "credentials not redacted"
        assert "[REDACTED]" in text, "no redaction marker"

    @check("pipeline")
    def errow_findings_indexed() -> None:
        def findings() -> list[dict[str, Any]] | None:
            _refresh()
            found = os_search("errow-findings-*", {"term": {"run": RUN_NAME}})
            return found if len(found) >= 2 else None

        docs = wait_for(">=2 errow-findings docs", findings)
        blob = json.dumps(docs)
        assert "poc_script_code" not in blob, "exploit payload field leaked into the SIEM"
        assert any(d.get("ruleId") for d in docs), "SARIF ruleId missing"

    @check("pipeline")
    def errow_sarif_and_alert_copy() -> None:
        wait_for("errow-sarif docs", lambda: (_refresh(), os_search("errow-sarif-*", {"match_all": {}}, 5))[1])
        alerts = wait_for("SARIF→alert copy", lambda: (_refresh(), os_search("vendetta-alerts*", {"term": {"source.system": "errow"}}))[1])
        a = alerts[0]
        assert a.get("severity") in {"critical", "high", "medium", "low", "info"}, f"severity {a.get('severity')}"
        assert a.get("errow", {}).get("sarif_rule_id"), "errow.sarif_rule_id missing"
        assert a.get("rule", {}).get("id"), "rule.id missing"

    @check("pipeline")
    def errow_run_and_threat_model_indexed() -> None:
        wait_for("errow-runs doc", lambda: (_refresh(), os_search("errow-runs-*", {"match_all": {}}, 1))[1])
        wait_for("errow-threat-models doc", lambda: (_refresh(), os_search("errow-threat-models-*", {"match_all": {}}, 1))[1])

    @check("pipeline")
    def ai_inference_and_audit_indexed() -> None:
        code, res = gw("POST", "/triage", fixture("vendetta-alert.json"))
        assert code == 200, f"/triage returned {code}: {res}"
        assert res["results"][0]["analysis"]["severityAssessment"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        wait_for("cs3-ai-inference doc", lambda: (_refresh(), os_search("cs3-ai-inference-*", {"match_all": {}}, 1))[1])
        wait_for("cs3-ai-audit doc", lambda: (_refresh(), os_search("cs3-ai-audit-*", {"match_all": {}}, 1))[1])

    @check("pipeline")
    def enrichment_upserted_into_alert() -> None:
        alert = fixture("vendetta-alert.json")
        docs = wait_for("ai.engine on alert", lambda: (_refresh(), [d for d in os_search("vendetta-alerts*", {"ids": {"values": [alert["id"]]}}) if d.get("ai", {}).get("engine")])[1])
        assert docs[0]["ai"]["engine"], "ai.engine empty"

    @check("pipeline")
    def audit_chain_verifies() -> None:
        docs = os_search("cs3-ai-audit-*", {"match_all": {}}, 1000)
        assert docs, "no audit documents"
        chains: dict[str, list[dict[str, Any]]] = {}
        for d in docs:
            chains.setdefault(d["chain_id"], []).append(d)
        for chain_id, items in chains.items():
            items.sort(key=lambda d: d["seq"])
            prev = "0" * 64
            for d in items:
                body = {k: v for k, v in d.items() if k not in ("hash", "_id", "_index")}
                assert d["prev_hash"] == prev, f"chain {chain_id} seq {d['seq']}: prev_hash mismatch"
                canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                assert hashlib.sha256((prev + canon).encode()).hexdigest() == d["hash"], f"chain {chain_id} seq {d['seq']}: hash mismatch"
                prev = d["hash"]

    @check("pipeline")
    def ollama_journal_never_in_opensearch() -> None:
        _refresh()
        code, res = os_req("POST", "/*/_search?ignore_unavailable=true",
                           {"size": 1, "query": {"query_string": {"query": f'"{LOOP_MARKER}"'}}})
        assert code == 200, f"search returned {code}"
        assert res["hits"]["total"]["value"] == 0, "cs3.ai.ollama journal record reached OpenSearch (telemetry loop!)"

    @check("pipeline")
    def console_leg_has_alerts_but_not_ollama() -> None:
        code, body = http("GET", f"{SINK_URL}/_dump/api/cecur/logs/ingest", raw=True)
        assert code == 200, "Console leg received nothing (is CS3_CONSOLE_ENABLED=true in the smoke env?)"
        assert LOOP_MARKER not in body, "Ollama journald record reached the Console ingest leg (infinite triage loop risk)"
        assert "vendetta" in body.lower() or "sshd" in body.lower(), "Console leg did not carry Vendetta alerts"

    @check("pipeline")
    def siem_leg_has_ollama_journal() -> None:
        def got() -> bool:
            code, body = http("GET", f"{SINK_URL}/_dump/siem", raw=True)
            return code == 200 and LOOP_MARKER in body
        wait_for("SIEM leg to carry the ollama record", got, 60)

    for fn in (vendetta_alert_indexed, vendetta_fim_indexed, edge_sanitization_applied, errow_findings_indexed,
               errow_sarif_and_alert_copy, errow_run_and_threat_model_indexed, ai_inference_and_audit_indexed,
               enrichment_upserted_into_alert, audit_chain_verifies, ollama_journal_never_in_opensearch,
               console_leg_has_alerts_but_not_ollama, siem_leg_has_ollama_journal):
        ok &= fn()
    return ok


# --------------------------------------------------------------------------- stage: guardrails / schema
def run_live_tests(stage: str, module: str, classes: tuple[str, ...] | None = None) -> bool:
    """Run `tests/llm/<module>.py` (unittest) against the live gateway; one JUnit case per test method."""
    llm_dir = str(FIXTURES.parent / "llm")
    if llm_dir not in sys.path:
        sys.path.insert(0, llm_dir)
    loader = unittest.TestLoader()
    mod = __import__(module)
    suite = unittest.TestSuite()
    if classes:
        for cls in classes:
            suite.addTests(loader.loadTestsFromTestCase(getattr(mod, cls)))
    else:
        suite.addTests(loader.loadTestsFromModule(mod))

    class Recorder(unittest.TestResult):
        def __init__(self) -> None:
            super().__init__()
            self.ok = True
            self.started = time.time()

        def _done(self, test: unittest.TestCase, ok: bool, message: str = "") -> None:
            self.ok &= ok
            record(stage, f"{type(test).__name__}.{test._testMethodName}", ok, message, time.time() - self.started)
            self.started = time.time()

        def addSuccess(self, test: unittest.TestCase) -> None:
            self._done(test, True)

        def addFailure(self, test: unittest.TestCase, err: Any) -> None:
            self._done(test, False, str(err[1]))

        def addError(self, test: unittest.TestCase, err: Any) -> None:
            self._done(test, False, f"{err[0].__name__}: {err[1]}")

    result = Recorder()
    suite.run(result)
    return result.ok and result.testsRun > 0


def stage_guardrails() -> bool:
    return run_live_tests("guardrails", "test_prompt_injection") & run_live_tests("schema", "test_json_schema")


# --------------------------------------------------------------------------- stage: MCP
def _tool(tool: str, args: dict[str, Any], role: str = "triage") -> tuple[int, Any]:
    return gw("POST", "/mcp/tool_call", {"tenant_id": "smoke", "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
                                         "role": role, "tool": tool, "args": args, "rationale": "smoke test verification"})


def stage_mcp() -> bool:
    ok = True
    lab = "scan-target.vendetta.lab"

    @check("mcp")
    def allowed_nmap_is_dry_run_by_default() -> None:
        code, res = _tool("nmap", {"target": lab, "scan_type": "-sT", "ports": "1-1024"})
        assert code == 200, f"returned {code}: {res}"
        assert res["status"] in ("dry_run", "executed"), res
        if os.environ.get("MCP_LIVE", "false") != "true":
            assert res["status"] == "dry_run", "MCP executed a scan while MCP_LIVE is not true"

    @check("mcp")
    def deny_loopback_and_metadata() -> None:
        for target in ("127.0.0.1", "169.254.169.254", "metadata.google.internal"):
            code, res = _tool("nmap", {"target": target, "scan_type": "-sT"})
            assert code == 403, f"{target}: expected 403, got {code} {res}"

    @check("mcp")
    def deny_forbidden_args_and_tags() -> None:
        code, _ = _tool("nmap", {"target": lab, "scan_type": "-sT", "--script": "vuln"})
        assert code == 403, f"nmap --script allowed ({code})"
        code, _ = _tool("nuclei", {"target": f"https://{lab}", "tags": ["dos"]})
        assert code == 403, f"nuclei dos tag allowed ({code})"
        code, _ = _tool("gobuster", {"target": f"https://{lab}", "mode": "dir", "threads": 11,
                                     "wordlist": "/usr/share/wordlists/dirb/common.txt"})
        assert code == 403, f"gobuster threads=11 allowed ({code})"

    @check("mcp")
    def deny_unknown_tool_wrong_role_and_foreign_target() -> None:
        assert _tool("metasploit", {"target": lab})[0] == 403, "unknown tool allowed"
        assert _tool("nmap", {"target": lab, "scan_type": "-sT"}, role="forensic")[0] == 403, "wrong role allowed"
        assert _tool("nmap", {"target": "8.8.8.8", "scan_type": "-sT"})[0] == 403, "target outside allow-list allowed"

    @check("mcp")
    def tool_calls_are_audited() -> None:
        docs = wait_for("cs3.ai.tool_call audit", lambda: (_refresh(), os_search("errow-mcp-*", {"term": {"event_type": "tool_call"}}))[1])
        decisions = {d.get("decision") for d in docs}
        assert decisions & {"dry_run", "allowed"} and "denied" in decisions, f"decisions seen: {decisions}"

    @check("mcp")
    def bridge_lists_tools_over_mtls() -> None:
        hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        code, res = http("POST", ERROW_MCP_URL, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}}}, hdr, tls_client=True)
        assert code == 200, f"initialize returned {code}: {res}"
        code, res = http("POST", ERROW_MCP_URL, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, hdr, tls_client=True)
        assert code == 200, f"tools/list returned {code}"
        names = {t["name"] for t in res["result"]["tools"]}
        expected = {"bbot", "nmap", "nuclei", "gobuster", "subfinder", "wafw00f", "trufflehog", "shell", "agent_browser",
                    "proxy", "web_search", "threat_model", "coverage"}
        assert expected <= names, f"missing tools: {sorted(expected - names)}"

    @check("mcp")
    def bridge_rejects_clients_without_certificate() -> None:
        try:
            req = urllib.request.Request(ERROW_MCP_URL, data=b"{}", method="POST", headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10, context=_ctx(False))
        except (ssl.SSLError, urllib.error.URLError, ConnectionError, OSError):
            return
        raise AssertionError("errow-mcp accepted a connection without a client certificate")

    for fn in (allowed_nmap_is_dry_run_by_default, deny_loopback_and_metadata, deny_forbidden_args_and_tags,
               deny_unknown_tool_wrong_role_and_foreign_target, tool_calls_are_audited,
               bridge_lists_tools_over_mtls, bridge_rejects_clients_without_certificate):
        ok &= fn()
    return ok


# --------------------------------------------------------------------------- stages: failover
def stage_baseline() -> bool:
    return run_live_tests("failover", "test_failover", ("Tier1PrimaryAnswers",))


def stage_failover1() -> bool:
    return run_live_tests("failover", "test_failover", ("Tier2ForensicTakesOver",))


def stage_failover2() -> bool:
    return run_live_tests("failover", "test_failover", ("Tier3HeuristicsNeverStall",))


# --------------------------------------------------------------------------- stage: metrics
def stage_metrics() -> bool:
    ok = True

    @check("metrics")
    def prometheus_targets_up() -> None:
        def ready() -> Any:
            code, res = http("GET", f"{PROMETHEUS_URL}/api/v1/targets")
            if code != 200:
                return None
            jobs = {t["labels"].get("job"): t["health"] for t in res["data"]["activeTargets"]}
            return jobs if jobs and all(v == "up" for v in jobs.values()) else None
        wait_for("all Prometheus targets up", ready, 90)

    @check("metrics")
    def alert_rules_loaded() -> None:
        code, res = http("GET", f"{PROMETHEUS_URL}/api/v1/rules")
        assert code == 200 and sum(len(g["rules"]) for g in res["data"]["groups"]) >= 10, "alert rules missing"

    @check("metrics")
    def gateway_metric_families_exposed() -> None:
        code, text = gw("GET", "/metrics", auth=False, raw=True)
        assert code == 200, f"/metrics returned {code}"
        for name in ("llm_gateway_requests_total", "llm_gateway_failover_total", "llm_gateway_gpu_seconds_total",
                     "llm_gateway_tokens_total", "llm_gateway_audit_chain_ok", "llm_gateway_prompt_injection_blocked_total",
                     "llm_gateway_queue_depth", "llm_gateway_mcp_tool_calls_total"):
            assert name in text, f"{name} missing from /metrics"
        assert "llm_gateway_audit_chain_ok 1" in text, "audit chain gauge is not 1"

    @check("metrics")
    def fluentd_emits_records() -> None:
        code, text = http("GET", FLUENTD_METRICS, raw=True)
        assert code == 200 and "fluentd_output_status_emit_records" in text, "Fluentd prometheus metrics missing"

    for fn in (prometheus_targets_up, alert_rules_loaded, gateway_metric_families_exposed, fluentd_emits_records):
        ok &= fn()
    return ok


# --------------------------------------------------------------------------- reporting
def report(out: Path) -> int:
    rows = _load()
    if not rows:
        print("no results recorded", file=sys.stderr)
        return 2
    suite = ET.Element("testsuite", name="vendetta-stack-smoke", tests=str(len(rows)),
                       failures=str(sum(not r["ok"] for r in rows)),
                       time=str(round(sum(r["seconds"] for r in rows), 3)))
    for r in rows:
        case = ET.SubElement(suite, "testcase", classname=r["stage"], name=r["name"], time=str(r["seconds"]))
        if not r["ok"]:
            ET.SubElement(case, "failure", message=r["message"][:500]).text = r["message"]
    out.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(out, encoding="utf-8", xml_declaration=True)
    failed = [r for r in rows if not r["ok"]]
    print(f"\n{len(rows) - len(failed)}/{len(rows)} checks passed; JUnit: {out}")
    for r in failed:
        print(f"  FAILED [{r['stage']}] {r['name']}: {r['message']}")
    return 1 if failed else 0


STAGES: dict[str, Callable[[], bool]] = {
    "ingest": stage_ingest, "pipeline": stage_pipeline, "guardrails": stage_guardrails, "mcp": stage_mcp,
    "baseline": stage_baseline, "failover1": stage_failover1, "failover2": stage_failover2, "metrics": stage_metrics,
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("stage", choices=[*STAGES, "record", "report", "reset"])
    p.add_argument("name", nargs="?", help="check name for `record`")
    p.add_argument("--status", choices=["pass", "fail"], default="pass")
    p.add_argument("--message", default="")
    p.add_argument("--group", default="smoke", help="classname for `record`")
    p.add_argument("--junit", type=Path, default=RESULTS_DIR / "junit.xml")
    args = p.parse_args(argv)
    if args.stage == "reset":
        STATE.unlink(missing_ok=True)
        return 0
    if args.stage == "report":
        return report(args.junit)
    if args.stage == "record":
        if not args.name:
            print("record needs a NAME", file=sys.stderr)
            return 2
        record(args.group, args.name, args.status == "pass", args.message)
        return 0
    try:
        return 0 if STAGES[args.stage]() else 1
    except FileNotFoundError as exc:
        print(f"environment error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
