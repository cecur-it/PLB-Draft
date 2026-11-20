#!/usr/bin/env python3
"""Stdlib fake Vendetta manager API + OpenSearch + LLM gateway for tests/test_feedback_loop.sh.

Traces: CONTRACT §4.4 (/triage, /forensic, /mcp/tool_call), §6 (feedback loop), Vendetta manager API :55000, OpenSearch
_search/_update/_update_by_query. POST /__mode {"mode": ok|500|400|401|slow|invalid|heuristic} switches the /forensic behaviour.
Prints "PORT=<n>" on the first stdout line. Every request is recorded; GET /__state returns them, POST /__reset clears them.
Credentials are test-only values supplied through the environment (FAKE_API_PASSWORD, FAKE_GATEWAY_TOKEN, FAKE_OS_AUTH).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

STATE_LOCK = threading.Lock()
STATE: dict = {"requests": [], "updated": {}, "mode": "ok"}
JWT = "fake-jwt-token-for-tests"


def load_alerts(path: str) -> list[dict]:
    alerts = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            alerts.append(json.loads(line))
    return alerts


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    alerts: list[dict] = []

    def log_message(self, fmt, *args):
        pass

    def _reply(self, code: int, payload, raw: bool = False) -> None:
        body = payload.encode() if raw else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain" if raw else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length).decode() if length else ""

    def _record(self, body: str) -> dict:
        entry = {"method": self.command, "path": self.path, "body": body, "auth": self.headers.get("Authorization", "")}
        with STATE_LOCK:
            STATE["requests"].append(entry)
        return entry

    def _basic_ok(self, secret: str) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        return base64.b64decode(header[6:]).decode() == secret

    def _forensic(self, body: str) -> None:
        if self.headers.get("Authorization") != f"Bearer {os.environ['FAKE_GATEWAY_TOKEN']}":
            self._reply(401, {"error": "unauthorized"})
            return
        with STATE_LOCK:
            mode = STATE["mode"]
            seq = sum(1 for r in STATE["requests"] if r["path"] == "/forensic")
        if mode == "500":
            self._reply(500, {"error": "inference_failed"})
            return
        if mode == "400":
            self._reply(400, {"error": "telemetry_loop_rejected"})
            return
        if mode == "401":
            self._reply(401, {"error": "unauthorized"})
            return
        if mode == "slow":
            time.sleep(3)
        if mode == "invalid":
            self._reply(200, {"results": []})
            return
        record = json.loads(body or "{}")
        ident = str(record.get("incident_id") or record.get("id") or "unknown")
        analysis = {
            "triageSummary": "fake forensic analysis", "severityAssessment": "HIGH", "mitreTactic": "Initial Access",
            "mitreTechnique": "T1190 - Exploit Public-Facing Application", "probableRootCause": "fake root cause",
            "recommendedImmediateAction": "fake action", "confidenceScore": 82, "engineUsed": "gemma4:26b", "toolCalls": [],
        }
        meta = {"model": "gemma4:26b", "role": "forensic", "fallback": False}
        if mode == "heuristic":
            analysis["engineUsed"] = "Cecur Heuristics"
            meta = {"model": "heuristics", "role": "forensic", "fallback": True, "fallback_reason": "ollama_unavailable"}
        else:
            analysis["proposedDetectionRule"] = (
                '<group name="errow,web,">\n  <rule id="100210" level="10">\n    <if_group>web|accesslog</if_group>\n'
                '    <regex type="pcre2">(?i)(union\\s+select|or\\s+1=1)</regex>\n'
                f"    <description>Possible SQL injection ({ident})</description>\n  </rule>\n</group>"
            )
            analysis["proposedRemediation"] = "Use parameterised queries for the search endpoint and validate the q parameter."
        self._reply(200, {"results": [{"request_id": f"r-forensic-{seq}", "alert_id": ident, "analysis": analysis, "meta": meta}]})

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/__state":
            with STATE_LOCK:
                self._reply(200, STATE)
            return
        self._record("")
        if parts.path == "/agents":
            if self.headers.get("Authorization") != f"Bearer {JWT}":
                self._reply(401, {"error": 401})
                return
            name = parse_qs(parts.query).get("name", [""])[0]
            agents = {"scan-target.vendetta.lab": "001", "vendetta-manager": "000"}
            items = [{"id": agents[name], "name": name}] if name in agents else []
            self._reply(200, {"data": {"affected_items": items, "total_affected_items": len(items)}, "error": 0})
            return
        self._reply(404, {"error": "not found"})

    def do_PUT(self):  # noqa: N802
        body = self._read()
        self._record(body)
        parts = urlsplit(self.path)
        if parts.path == "/active-response":
            if self.headers.get("Authorization") != f"Bearer {JWT}":
                self._reply(401, {"error": 401})
                return
            self._reply(200, {"data": {"affected_items": parse_qs(parts.query).get("agents_list", [])}, "error": 0})
            return
        self._reply(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        body = self._read()
        parts = urlsplit(self.path)
        if parts.path == "/__reset":
            with STATE_LOCK:
                STATE["requests"].clear()
                STATE["updated"].clear()
                STATE["mode"] = "ok"
            self._reply(200, {"ok": True})
            return
        if parts.path == "/__mode":
            with STATE_LOCK:
                STATE["mode"] = json.loads(body or "{}").get("mode", "ok")
            self._reply(200, {"ok": True})
            return
        self._record(body)
        if parts.path == "/security/user/authenticate":
            if not self._basic_ok(os.environ["FAKE_API_AUTH"]):
                self._reply(401, {"error": 401})
                return
            self._reply(200, JWT, raw=True)
        elif parts.path == "/triage":
            if self.headers.get("Authorization") != f"Bearer {os.environ['FAKE_GATEWAY_TOKEN']}":
                self._reply(401, {"error": "unauthorized"})
                return
            alert = json.loads(body or "{}")
            rule_id = str((alert.get("rule") or {}).get("id", ""))
            host = (alert.get("agent") or {}).get("name", "scan-target.vendetta.lab")
            calls = [] if rule_id == "notools" else [{
                "tool": "nmap",
                "args": {"target": host, "scan_type": "-sT", "ports": "8080", "timing": "-T3"},
                "rationale": "Confirm the web service exposed by the alert is reachable.",
            }]
            self._reply(200, {"results": [{"request_id": "r-1", "alert_id": alert.get("id", ""), "analysis": {
                "triageSummary": "fake", "severityAssessment": "HIGH", "mitreTactic": "Initial Access",
                "mitreTechnique": "T1190", "probableRootCause": "fake", "recommendedImmediateAction": "fake",
                "confidenceScore": 80, "engineUsed": "fake", "toolCalls": calls}}]})
        elif parts.path == "/forensic":
            self._forensic(body)
        elif parts.path == "/mcp/tool_call":
            if self.headers.get("Authorization") != f"Bearer {os.environ['FAKE_GATEWAY_TOKEN']}":
                self._reply(401, {"error": "unauthorized"})
                return
            self._reply(200, {"status": "dry_run", "tool": json.loads(body).get("tool")})
        elif parts.path == "/vendetta-alerts-*/_search":
            if not self._basic_ok(os.environ["FAKE_OS_AUTH"]):
                self._reply(401, {"error": "unauthorized"})
                return
            with STATE_LOCK:
                updated = set(STATE["updated"])
            hits = []
            for alert in self.alerts:
                if alert["id"] in updated or (alert.get("source") or {}).get("system") == "errow":
                    continue
                hits.append({"_index": "vendetta-alerts-000001", "_id": alert["id"], "_source": alert})
            self._reply(200, {"hits": {"hits": hits}})
        elif parts.path.endswith("/_update_by_query"):
            if not self._basic_ok(os.environ["FAKE_OS_AUTH"]):
                self._reply(401, {"error": "unauthorized"})
                return
            self._reply(200, {"took": 3, "updated": 3, "noops": 1, "failures": []})
        elif "/_update/" in parts.path:
            if not self._basic_ok(os.environ["FAKE_OS_AUTH"]):
                self._reply(401, {"error": "unauthorized"})
                return
            doc_id = parts.path.rsplit("/", 1)[1]
            with STATE_LOCK:
                STATE["updated"][doc_id] = json.loads(body)
            self._reply(200, {"result": "updated"})
        elif parts.path == "/soar":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts", required=True, help="NDJSON file of normalized alerts served by _search")
    args = parser.parse_args()
    Handler.alerts = load_alerts(args.alerts)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(f"PORT={httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
