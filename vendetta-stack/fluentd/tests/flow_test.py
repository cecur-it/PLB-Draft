#!/usr/bin/env python3
"""Traces: PROMPT §3 Data flow, §4.3 telemetry-loop prevention, §6 Closed loop; CONTRACT §3, §4.2, §5, §6. Behavioural test of a RUNNING Fluentd
aggregator (started by test_routing.sh against tests/stubs.py): sends real Forward-protocol events over mTLS, waits for the buffers to
flush, then asserts on what each stub received. Exit 1 when any assertion fails.

Usage: flow_test.py --outdir DIR --pki DIR --fwd HOST:PORT --metrics-url URL --data DIR [--wait SEC] [--metrics-out FILE]
"""
import argparse
import copy
import datetime
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "fluent-bit", "tests"))
from forward_send import pack  # noqa: E402

FIXTURES = os.path.join(HERE, "..", "..", "tests", "synthetic-logs")
TOKENS = {"gateway": "Bearer fixture-llm_gateway_token", "feedback": "Bearer fixture-feedback_webhook_token",
          "cloud": "Bearer fixture-errow_api_token", "esoc": "Bearer fixture-esoc_token", "siem": "Bearer fixture-siem_token"}
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  -> {detail}"), flush=True)


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Sender:
    def __init__(self, pki, host, port):
        self.pki, self.host, self.port = pki, host, port

    def send(self, tag, record):
        ctx = ssl.create_default_context(cafile=os.path.join(self.pki, "ca.crt"))
        ctx.load_cert_chain(os.path.join(self.pki, "fluent-bit.crt"), os.path.join(self.pki, "fluent-bit.key"))
        with socket.create_connection((self.host, self.port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="fluentd-1") as tls:
                tls.sendall(pack([tag, int(time.time()), record]))
                time.sleep(0.3)


class Stubs:
    def __init__(self, outdir):
        self.outdir = outdir

    def requests(self, name):
        path = os.path.join(self.outdir, name + ".ndjson")
        with open(path, encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]

    def bodies(self, name):
        return [r["body"] for r in self.requests(name)]

    def text(self, name):
        return "\n".join(self.bodies(name))

    def items(self):
        out = []
        for req in self.requests("opensearch"):
            out.extend(req.get("items", []))
        return out

    def lines(self, name):
        rows = []
        for body in self.bodies(name):
            for ln in body.split("\n"):
                if ln.strip():
                    try:
                        rows.append(json.loads(ln))
                    except ValueError:
                        pass
        return rows


def wait_for(fn, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if fn():
                return True
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(1)
    return False


def build_events():
    ts = now()
    alert = fixture("vendetta-alert.json")
    extras = {"@timestamp": ts, "stream": "alerts", "severity": "high", "source": "vendetta", "agentName": "agent-001", "message": "m", "fields": {}}
    high = {**alert, **extras}
    low = copy.deepcopy(high)
    low["id"], low["rule"]["level"], low["severity"] = "low-alert-0001", 3, "info"
    fim = {**fixture("vendetta-fim.json"), **extras, "stream": "fim", "id": "fim-alert-0001"}
    chain = {"chain_id": "chain-a", "seq": 1, "prev_hash": "0" * 64, "hash": "a1" * 32}
    inference = {"@timestamp": ts, "event_type": "inference", "request_id": "req-0001", "tenant_id": "t1", "incident_id": "inc-1", "alert_id": high["id"],
                 "model": "nemotron-3-nano:30b", "role": "triage", "engine_used": "nemotron-3-nano:30b", "fallback": False, "fallback_reason": None,
                 "latency_ms": 2100, "gpu_seconds": 6.42, "tokens_in": 812, "tokens_out": 240, "verdict": "completed", "guardrail": {"injection": False},
                 "input_sha256": "ab" * 32, "input_chars": 1200, "analysis": fixture("ai-incident-analysis.json"), **chain}
    orphan = {**copy.deepcopy(inference), "request_id": "req-orphan-0002", "alert_id": "", "seq": 2, "prev_hash": chain["hash"], "hash": "b2" * 32}
    orphan["analysis"]["severityAssessment"] = "MEDIUM"
    tool_call = {"@timestamp": ts, "event_type": "tool_call", "request_id": "req-0003", "tenant_id": "t1", "incident_id": "inc-1", "role": "forensic",
                 "tool": "nmap", "args": {"target": "scan-target.vendetta.lab"}, "target": "scan-target.vendetta.lab", "decision": "allow", "violations": [],
                 "rationale": "confirm exposed ports", "gpu_seconds": 0.1, "live": False, "result_summary": "ok", "chain_id": "chain-a", "seq": 3,
                 "prev_hash": orphan["hash"], "hash": "c3" * 32}
    enrichment = {"id": high["id"], "severity": "critical", "ai": {"engine": "nemotron-3-nano:30b", "confidence": 91.0}, "root_cause": "exposed sshd"}
    base = fixture("errow-finding.sarif.json")["runs"][0]["results"][0]
    findings = {}
    for key, sev, agent in (("F1", "critical", "001"), ("F2", "critical", "000"), ("F3", "critical", "002"), ("F4", "medium", "001")):
        rec = copy.deepcopy(base)
        rec.update({"@timestamp": ts, "stream": "findings", "run": f"run-{key}", "ruleId": f"CWE-{key}"})
        rec["partialFingerprints"] = {"primaryLocationLineHash": f"{key}".ljust(64, "0")}
        rec["properties"]["errow"].update({"severity": sev, "vendetta_agent_id": agent})
        findings[key] = rec
    cfg_finding = {"@timestamp": ts, "schema_version": "1.0", "record_type": "finding", "doc_id": "d" * 64,
                   "source": {"system": "cfgaudit", "stream": "cfgaudit.findings"}, "run": {"id": "cfg-run-1"},
                   "asset": {"id": "a" * 64, "name": "CFG_FINDING_MARK", "vendor": "ios"},
                   "config": {"name": "edge.cfg", "sha256": "b" * 64},
                   "control": {"id": "IOS-005", "title": "SNMP write community", "frameworks": []},
                   "finding": {"id": "d" * 64, "key": "c" * 64}, "status": "fail", "severity": "high",
                   "evidence": {"sha256": "e" * 64, "items": ["snmp-server community [REDACTED]"]}, "remediation": "Use SNMPv3."}
    cfg_run = {"@timestamp": ts, "schema_version": "1.0", "record_type": "run", "doc_id": "cfg-run-1",
               "source": {"system": "cfgaudit", "stream": "cfgaudit.runs"}, "tool": {"name": "cfgaudit", "version": "0.1.0"},
               "run": {"id": "cfg-run-1", "started_at": ts, "completed_at": ts, "status": "completed", "min_severity": "info", "shadow_mode": "off"},
               "status": "completed", "summary": {"files_total": 1, "files_audited": 1, "files_skipped": 0, "assets_audited": 1,
                                                  "findings_total": 1, "severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
               "assets": [], "warnings": ["CFG_RUN_MARK"]}
    return {"ts": ts, "high": high, "low": low, "fim": fim, "inference": inference, "orphan": orphan, "tool_call": tool_call,
            "enrichment": enrichment, "findings": findings, "cfg_finding": cfg_finding, "cfg_run": cfg_run}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--pki", required=True)
    ap.add_argument("--fwd", required=True)
    ap.add_argument("--metrics-url", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--wait", type=int, default=90)
    ap.add_argument("--metrics-out")
    a = ap.parse_args()

    host, port = a.fwd.rsplit(":", 1)
    ev, sender, stubs = build_events(), Sender(a.pki, host, int(port)), Stubs(a.outdir)
    sender.send("cs3.ai.ollama", {"@timestamp": ev["ts"], "MESSAGE": "CUDA error: out of memory OLLAMA_MARK", "SYSTEMD_UNIT": "ollama.service", "PRIORITY": "3"})
    sender.send("vendetta.alerts", ev["high"])
    sender.send("vendetta.alerts", ev["low"])
    sender.send("vendetta.fim", ev["fim"])
    sender.send("cs3.ai.inference", ev["inference"])
    sender.send("cs3.ai.inference", ev["inference"])
    sender.send("cs3.ai.inference", ev["orphan"])
    sender.send("cs3.ai.enrichment", ev["enrichment"])
    sender.send("cs3.ai.tool_call", ev["tool_call"])
    for rec in ev["findings"].values():
        sender.send("errow.findings", rec)
    sender.send("errow.telemetry", {"@timestamp": ev["ts"], "event": "cli_start", "marker": "TELEMETRY_MARK"})
    sender.send("errow.tui_events", {"@timestamp": ev["ts"], "event": "key", "marker": "TUI_MARK"})
    sender.send("errow.runs", {"@timestamp": ev["ts"], "run": "run-R1", "marker": "RUN_MARK"})
    sender.send("cfgaudit.findings", ev["cfg_finding"])
    sender.send("cfgaudit.findings", ev["cfg_finding"])
    sender.send("cfgaudit.runs", ev["cfg_run"])
    sender.send("zzz.unknown.tag", {"@timestamp": ev["ts"], "marker": "UNROUTED_MARK"})
    for tag, rec in (("cs3.sp.ai_inference", {"inferences": 7, "gpu_seconds": 12.5, "tokens_in": 100, "tokens_out": 50, "avg_latency_ms": 900.0, "edge_node": "edge-1"}),
                     ("cs3.sp.ai_ollama", {"lines": 3, "edge_node": "edge-1"}),
                     ("cs3.sp.vendetta_by_level", {"rule_level": 10, "alerts": 4, "edge_node": "edge-1"}),
                     ("cs3.sp.vendetta_alert_rate", {"alerts": 9, "max_rule_level": 12, "edge_node": "edge-1"}),
                     ("cs3.sp.errow_findings", {"level": "error", "findings": 2, "edge_node": "edge-1"})):
        sender.send(tag, rec)

    def all_arrived():
        docs = [json.dumps(i["doc"]) for i in stubs.items()]
        return (len(stubs.items()) >= 17 and stubs.requests("gateway") and stubs.requests("cloud") and stubs.requests("esoc")
                and stubs.requests("siem") and any("CFG_FINDING_MARK" in doc for doc in docs)
                and any("CFG_RUN_MARK" in doc for doc in docs)
                and any(r["path"].endswith("/approved-action") for r in stubs.requests("feedback")))

    print(f"== waiting up to {a.wait}s for buffers to flush", flush=True)
    arrived = wait_for(all_arrived, a.wait)
    check("every sink received traffic within the wait window", arrived)
    time.sleep(12)

    items = stubs.items()
    idx = lambda prefix: [i for i in items if str(i["meta"].get("_index", "")).startswith(prefix)]  # noqa: E731
    high_id = ev["high"]["id"]

    print("== A. telemetry-loop invariant: cs3.ai.ollama -> ESOC + SIEM only")
    esoc_text, siem_text = stubs.text("esoc"), stubs.text("siem")
    check("ESOC OTLP leg got the ollama line", "OLLAMA_MARK" in esoc_text)
    check("SIEM NDJSON leg got the ollama line", "OLLAMA_MARK" in siem_text)
    sink_hits = [n for n in ("opensearch", "gateway", "feedback", "cloud", "manager") if "OLLAMA_MARK" in stubs.text(n)]
    check("no other sink (OpenSearch, gateway/triage, feedback, cloud, manager) saw it", not sink_hits, sink_hits)
    siem_ollama = [r for r in stubs.lines("siem") if "OLLAMA_MARK" in json.dumps(r)]
    check("SIEM record is stamped leg=esoc+siem", bool(siem_ollama) and siem_ollama[0].get("leg") == "esoc+siem", siem_ollama[:1])
    esoc_reqs = stubs.requests("esoc")
    check("ESOC request used mTLS (client CN fluentd-1) and the bearer token",
          bool(esoc_reqs) and esoc_reqs[0]["peer_cn"] == "fluentd-1" and esoc_reqs[0]["headers"].get("Authorization") == TOKENS["esoc"], esoc_reqs[:1])
    otlp = json.loads(esoc_reqs[0]["body"]) if esoc_reqs else {}
    recs = [lr for rl in otlp.get("resourceLogs", []) for sl in rl.get("scopeLogs", []) for lr in sl.get("logRecords", [])]
    check("ESOC body is an OTLP/HTTP-JSON ExportLogsServiceRequest with severityNumber", bool(recs) and "severityNumber" in recs[0], otlp)
    siem_reqs = stubs.requests("siem")
    check("SIEM request carries the bearer token and X-Origin-Sensor", bool(siem_reqs) and siem_reqs[0]["headers"].get("Authorization") == TOKENS["siem"]
          and siem_reqs[0]["headers"].get("X-Origin-Sensor") == "CS3-Aggregator", siem_reqs[:1] and siem_reqs[0]["headers"])
    for tag in ("cs3-ai", "vendetta-alerts"):
        check(f"no `{tag}` OpenSearch document carries the ollama line", not [i for i in idx(tag) if "OLLAMA_MARK" in json.dumps(i["doc"])])

    print("== B. Vendetta alerts -> vendetta-alerts upsert + gateway /triage")
    up = [i for i in idx("vendetta-alerts") if i["meta"].get("_id") == high_id]
    check("alert upserted into vendetta-alerts with _id = alert id", any(i["action"] == "update" and i["doc"].get("doc_as_upsert") for i in up), up)
    doc = next((i["doc"]["doc"] for i in up if "rule" in i["doc"].get("doc", {})), {})
    check("document is the CONTRACT §4.1 alert (source.system, severity, mitre)", doc.get("source") == {"system": "vendetta", "stream": "alerts"}
          and doc.get("severity") == "high" and isinstance(doc.get("mitre"), dict) and "message" not in doc and "stream" not in doc, doc)
    check("level-3 alert also stored (OpenSearch keeps everything)", any(i["meta"].get("_id") == "low-alert-0001" for i in idx("vendetta-alerts")))
    gw = stubs.requests("gateway")
    gw_ids = stubs.text("gateway")
    check("triage POST on /triage with bearer + client cert fluentd-1", bool(gw) and all(r["path"] == "/triage" and r["headers"].get("Authorization") == TOKENS["gateway"]
          and r["peer_cn"] == "fluentd-1" for r in gw), gw[:1])
    check("triage got the high alert and the medium fim alert", high_id in gw_ids and "fim-alert-0001" in gw_ids)
    check("triage did NOT get the info-severity alert", "low-alert-0001" not in gw_ids)
    check("triage got no AI, Errow or Ollama data", not any(m in gw_ids for m in ("req-0001", "req-orphan-0002", "req-0003", "run-F1", "OLLAMA_MARK", "TUI_MARK", "TELEMETRY_MARK")))

    print("== C. cs3.ai.inference -> inference + audit (chain untouched, replay idempotent) + alert upsert")
    inf = ev["inference"]
    audit = [i for i in idx("cs3-ai-audit-") if i["meta"].get("_id") == inf["hash"]]
    check("audit entry written with action create and _id = hash", bool(audit) and all(i["action"] == "create" for i in audit), audit)
    check("audit document is byte-identical to the gateway event (chain fields untouched, null preserved)", bool(audit) and audit[0]["doc"] == inf, audit[:1] and audit[0]["doc"])
    statuses = [next(iter(r.values())).get("status") for req in stubs.requests("opensearch") for r in req.get("results", [])
                if next(iter(r.values())).get("_id") == inf["hash"] and str(next(iter(r.values())).get("_index", "")).startswith("cs3-ai-audit-")]
    check("replayed audit event: first create accepted (201), duplicate rejected (409), nothing else", sorted(set(statuses)) == [201, 409], statuses)
    created = [i for i in idx("cs3-ai-audit-") if i["meta"].get("_id") == ev["orphan"]["hash"]]
    check("second chain entry stored with prev_hash = first hash", bool(created) and created[0]["doc"]["prev_hash"] == inf["hash"])
    check("inference mirrored into cs3-ai-inference-*", any(i["meta"].get("_id") == inf["hash"] for i in idx("cs3-ai-inference-")))
    known = [i for i in idx("vendetta-alerts") if i["meta"].get("_id") == high_id and "ai" in i["doc"].get("doc", {})]
    check("known alert gets a PARTIAL AI update (severity/mitre/root_cause/ai; no source/rule/@timestamp)",
          bool(known) and not ({"source", "rule", "@timestamp"} & set(known[0]["doc"]["doc"])) and known[0]["doc"]["doc"]["ai"].get("engine"), known[:1])
    check("known-alert update maps §4.2 fields", bool(known) and known[0]["doc"]["doc"].get("root_cause") == ev["inference"]["analysis"]["probableRootCause"]
          and known[0]["doc"]["doc"].get("severity") == "high", known[:1])
    orphan = [i for i in idx("vendetta-alerts") if i["meta"].get("_id") == "req-orphan-0002"]
    check("orphan inference becomes a full alert (source cs3-ai, rule.level 8, severity medium)", bool(orphan) and orphan[0]["doc"]["doc"].get("source", {}).get("system") == "cs3-ai"
          and orphan[0]["doc"]["doc"]["rule"]["level"] == 8 and orphan[0]["doc"]["doc"]["severity"] == "medium", orphan[:1])
    enr = [i for i in idx("vendetta-alerts") if i["meta"].get("_id") == high_id and i["doc"].get("doc", {}).get("root_cause") == "exposed sshd"]
    check("cs3.ai.enrichment upserted by id", bool(enr))

    print("== D. cs3.ai.tool_call -> errow-mcp-* + cs3-ai-audit-*")
    tc = ev["tool_call"]
    check("tool_call in errow-mcp-*", any(i["doc"].get("hash") == tc["hash"] for i in idx("errow-mcp-")))
    check("tool_call in cs3-ai-audit-* with _id = hash", any(i["meta"].get("_id") == tc["hash"] and i["action"] == "create" for i in idx("cs3-ai-audit-")))

    print("== E. Errow findings fan-out and the closed loop")
    f1 = ev["findings"]["F1"]
    fnd = [i for i in idx("errow-findings-") if i["doc"].get("run") == "run-F1"]
    check("errow-findings-* with ingest pipeline errow-finding-enrichment, SARIF fields intact",
          bool(fnd) and fnd[0]["meta"].get("pipeline") == "errow-finding-enrichment" and fnd[0]["doc"].get("ruleId") == f1["ruleId"] and "locations" in fnd[0]["doc"], fnd[:1])
    check("errow-sarif-* copy stored", any(i["doc"].get("run") == "run-F1" for i in idx("errow-sarif-")))
    al = [i for i in idx("vendetta-alerts") if i["meta"].get("pipeline") == "sarif-to-vendetta-alert"]
    check("vendetta-alerts copy uses ingest pipeline sarif-to-vendetta-alert (all 4 findings)", len({i["doc"]["doc"].get("run") for i in al if "doc" in i["doc"]}) == 4, al[:1])
    fb_runs = {r.get("run") for r in stubs.lines("feedback")}
    check("feedback webhook got severity >= high only (F1,F2,F3; not the medium F4)", fb_runs == {"run-F1", "run-F2", "run-F3"}, fb_runs)
    fb = stubs.requests("feedback")
    check("feedback POST carries the bearer token", bool(fb) and all(r["headers"].get("Authorization") == TOKENS["feedback"] for r in fb))
    cloud_runs = {r.get("run") for r in stubs.lines("cloud")}
    check("Errow cloud leg got high+critical only", cloud_runs == {"run-F1", "run-F2", "run-F3"}, cloud_runs)
    cl = stubs.requests("cloud")
    check("cloud POST on /api/v1/retests with the Errow API token", bool(cl) and all(r["path"] == "/api/v1/retests" and r["headers"].get("Authorization") == TOKENS["cloud"] for r in cl), cl[:1])
    mgr = stubs.requests("manager")
    auth = [r for r in mgr if r["path"] == "/security/user/authenticate"]
    check("entrypoint probe-minted a JWT against /security/user/authenticate", bool(auth))
    check("execd leg sends the manager no active-response itself (the gate does that)", not [r for r in mgr if r["method"] == "PUT"])
    gate = [r for r in stubs.requests("feedback") if r["path"] == "/approved-action"]
    check("execd leg posts to the approval gate only for agent 001: 000 is always refused, 002 is not allow-listed, "
          "the medium finding is below the severity gate", len(gate) == 1, [(r["path"], r["body"]) for r in gate])
    body = json.loads(gate[0]["body"]) if gate else {}
    check("gate body carries the primaryLineHash fingerprint, the agent, the command and the run",
          body.get("fingerprint") == f1["partialFingerprints"]["primaryLocationLineHash"] and body.get("agent_id") == "001"
          and body.get("command") == "!host-isolate.sh" and body.get("run") == "run-F1", body)
    check("gate body is not the manager active-response envelope (the gate now builds that)", bool(body) and "alert" not in body, body)

    print("== F. Cfgaudit findings/runs -> dedicated storage only (deterministic replay)")
    cfg_id = ev["cfg_finding"]["doc_id"]
    cfg_findings = [i for i in idx("cfgaudit-findings-") if i["meta"].get("_id") == cfg_id]
    check("finding replay uses deterministic _id and only cfgaudit-findings-*", len(cfg_findings) == 2
          and all(i["action"] == "index" and i["doc"].get("asset", {}).get("name") == "CFG_FINDING_MARK" for i in cfg_findings), cfg_findings)
    check("run summary lands only in cfgaudit-runs-* with run id as _id",
          any(i["meta"].get("_id") == "cfg-run-1" and "CFG_RUN_MARK" in i["doc"].get("warnings", []) for i in idx("cfgaudit-runs-")))
    wrong_indices = [i["meta"].get("_index") for i in items
                     if any(m in json.dumps(i["doc"]) for m in ("CFG_FINDING_MARK", "CFG_RUN_MARK"))
                     and not str(i["meta"].get("_index", "")).startswith(("cfgaudit-findings-", "cfgaudit-runs-"))]
    check("no Cfgaudit record reaches Errow, Vendetta or AI indices", not wrong_indices, wrong_indices)
    cfg_sinks = [name for name in ("gateway", "feedback", "cloud", "manager", "esoc", "siem")
                 if any(m in stubs.text(name) for m in ("CFG_FINDING_MARK", "CFG_RUN_MARK"))]
    check("Cfgaudit is storage-only: no triage, feedback, cloud, manager, ESOC or SIEM fan-out", not cfg_sinks, cfg_sinks)
    check("Cfgaudit writes use no Errow/SARIF ingest pipeline",
          all(not i["meta"].get("pipeline") for i in cfg_findings), cfg_findings)

    print("== G. other Errow streams, unrouted tags, stream-processor metrics")
    check("errow.telemetry -> errow-telemetry-* only", any(i["doc"].get("marker") == "TELEMETRY_MARK" for i in idx("errow-telemetry-"))
          and not [n for n in ("gateway", "feedback", "cloud", "esoc", "siem") if "TELEMETRY_MARK" in stubs.text(n)])
    check("errow.tui_events -> errow-tui-* and never triaged", any(i["doc"].get("marker") == "TUI_MARK" for i in idx("errow-tui-")) and "TUI_MARK" not in gw_ids)
    check("errow.runs -> errow-runs-*", any(i["doc"].get("marker") == "RUN_MARK" for i in idx("errow-runs-")))
    check("unknown tag appears in no sink", not [n for n in ("opensearch", "gateway", "feedback", "cloud", "esoc", "siem", "manager") if "UNROUTED_MARK" in stubs.text(n)])
    def dead_files():
        found = []
        for root, _, files in os.walk(os.path.join(a.data, "dead-letter")):
            found += [os.path.join(root, f) for f in files]
        return found

    def unrouted_files():
        return [p for p in dead_files() if "UNROUTED_MARK" in open(p, encoding="utf-8", errors="replace").read()]

    wait_for(lambda: bool(unrouted_files()), 100)  # time-sliced file buffer: timekey 60 s + timekey_wait 10 s
    dead, unrouted = dead_files(), unrouted_files()
    check("unknown tag was parked in dead-letter/unrouted", bool(unrouted), dead)
    check("nothing else was dead-lettered (409 replays are not failures)", all("unrouted" in p for p in dead), dead)

    with urllib.request.urlopen(a.metrics_url, timeout=10) as resp:
        metrics = resp.read().decode()
    if a.metrics_out:
        with open(a.metrics_out, "w", encoding="utf-8") as fh:
            fh.write(metrics)
    for needle in ('fluentd_output_status_emit_records{', 'fluentd_output_status_buffer_queue_length{', 'fluentd_output_status_retry_count{',
                   'cs3_pipeline_vendetta_alerts_total{', 'cs3_sp_ai_inferences_60s{', 'cs3_sp_ai_ollama_lines_60s{', 'cs3_sp_vendetta_alerts_by_level_60s{',
                   'plugin_id="opensearch"', 'plugin_id="http-llm-triage"', 'plugin_id="siem-ndjson"'):
        check(f"/metrics exposes {needle}", needle in metrics)
    check("stream-processor gauge carries edge_node", 'cs3_sp_ai_inferences_60s{edge_node="edge-1"' in metrics or 'edge_node="edge-1"' in metrics)

    failed = RESULTS.count(False)
    print(f"RESULT: {RESULTS.count(True)} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
