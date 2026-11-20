"""Unit tests for schema-validate.py (stdlib unittest; also collected by pytest).

Run: python3 -m unittest discover -s errow/feedback-loop/tests -p 'test_schema_validate.py'
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "schema-validate.py"
FIXTURES = HERE.parent.parent.parent / "tests" / "synthetic-logs"

spec = importlib.util.spec_from_file_location("schema_validate", SCRIPT)
sv = importlib.util.module_from_spec(spec)
sys.modules["schema_validate"] = sv
spec.loader.exec_module(sv)


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def run_cli(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True, text=True, check=False, timeout=60
    )


class SarifTests(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = load("errow-finding.sarif.json")

    def test_fixture_is_valid_and_shaped_like_errow_output(self) -> None:
        self.assertEqual(sv.validate_sarif(self.doc), [])
        run = self.doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "errow")
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels["CWE-89"], "error")
        self.assertEqual(levels["CWE-79"], "warning")
        sqli = run["results"][0]
        self.assertNotIn("cve", sqli["properties"]["errow"])

    def test_transform_maps_every_field_and_round_trips(self) -> None:
        alerts = sv.transform_sarif(self.doc, "scan-target-vendetta-lab-8080_3f9a")
        self.assertEqual(len(alerts), 3)
        sqli = alerts[0]
        self.assertEqual(sqli["severity"], "high")
        self.assertEqual(sqli["rule"]["level"], 11)
        self.assertEqual(sqli["errow"]["cwe"], "CWE-89")
        self.assertEqual(sqli["errow"]["owasp"], "A03:2021 Injection")
        self.assertEqual(sqli["mitre"]["id"], ["T1190"])
        self.assertEqual(sqli["errow"]["endpoint"], "/rest/products/search")
        self.assertEqual(sqli["agent"]["name"], "scan-target.vendetta.lab")
        self.assertNotIn("cve", sqli["errow"])
        expected_id = hashlib.sha256(
            ("scan-target-vendetta-lab-8080_3f9a" + "CWE-89" + sqli["errow"]["fingerprint"]).encode()
        ).hexdigest()
        self.assertEqual(sqli["id"], expected_id)
        self.assertEqual(sv.validate_alert(sqli), [])
        for (result, _rules), alert in zip(sv.fail_results(self.doc), alerts, strict=True):
            self.assertEqual(sv.roundtrip_errors(result, alert, "scan-target-vendetta-lab-8080_3f9a"), [])

    def test_severity_falls_back_to_level_map(self) -> None:
        result = {"level": "note", "properties": {"errow": {}}}
        self.assertEqual(sv.sarif_severity(result), "low")
        self.assertEqual(sv.sarif_severity({"level": "warning"}), "medium")
        self.assertEqual(sv.sarif_severity({"level": "error", "properties": {"errow": {"severity": "critical"}}}), "critical")

    def test_level_bands(self) -> None:
        bands = {0: "info", 3: "info", 4: "low", 6: "low", 7: "medium", 9: "medium", 10: "high", 12: "high", 13: "critical", 15: "critical"}
        for level, expected in bands.items():
            self.assertEqual(sv.severity_from_level(level), expected)
        for severity, level in sv.SEVERITY_TO_LEVEL.items():
            self.assertEqual(sv.severity_from_level(level), severity)

    def test_tampered_fingerprint_is_detected(self) -> None:
        doc = copy.deepcopy(self.doc)
        doc["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"] = "xyz"
        self.assertTrue(any("64 hex" in e for e in sv.validate_sarif(doc)))

    def test_roundtrip_detects_drift(self) -> None:
        result, _ = sv.fail_results(self.doc)[0]
        alert = sv.transform_sarif(self.doc, "r1")[0]
        alert["severity"] = "low"
        alert["errow"]["endpoint"] = "/other"
        alert["errow"]["cwe"] = "CWE-79"
        errors = sv.roundtrip_errors(result, alert, "r1")
        self.assertTrue(any("severity" in e for e in errors))
        self.assertTrue(any("endpoint" in e for e in errors))
        self.assertTrue(any("CWE" in e for e in errors))

    def test_exploit_script_bodies_are_rejected(self) -> None:
        doc = copy.deepcopy(self.doc)
        doc["runs"][0]["results"][0]["properties"]["errow"]["poc_script_code"] = "curl http://x"
        self.assertTrue(any("poc_script_code" in e for e in sv.validate_sarif(doc)))
        doc = copy.deepcopy(self.doc)
        doc["runs"][0]["results"][0]["properties"]["errow"]["poc"]["script"] = "curl http://x"
        self.assertTrue(any("poc" in e for e in sv.validate_sarif(doc)))

    def test_wrong_version_and_bad_rule_index(self) -> None:
        doc = copy.deepcopy(self.doc)
        doc["version"] = "2.0.0"
        doc["runs"][0]["results"][1]["ruleIndex"] = 0
        errors = sv.validate_sarif(doc)
        self.assertTrue(any("version" in e for e in errors))
        self.assertTrue(any("ruleIndex" in e for e in errors))

    def test_cve_rule_id_maps_to_cve_field(self) -> None:
        doc = copy.deepcopy(self.doc)
        result = doc["runs"][0]["results"][1]
        result["ruleId"] = "CVE-2024-12345"
        doc["runs"][0]["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] = "CVE-2024-12345"
        del result["properties"]["errow"]["cwe"]
        alert = sv.transform_sarif(doc, "r1")[1]
        self.assertEqual(alert["errow"]["cve"], "CVE-2024-12345")
        self.assertNotIn("cwe", alert["errow"])
        self.assertEqual(alert["mitre"]["id"], ["T1190"])


class AiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis = load("ai-incident-analysis.json")

    def test_fixture_valid(self) -> None:
        self.assertEqual(sv.validate_ai(self.analysis), [])

    def test_required_and_strict(self) -> None:
        for key in sv.AI_REQUIRED_STR + ("confidenceScore",):
            bad = {k: v for k, v in self.analysis.items() if k != key}
            self.assertTrue(sv.validate_ai(bad), key)
        bad = {**self.analysis, "surprise": 1}
        self.assertTrue(any("additionalProperties" in e for e in sv.validate_ai(bad)))

    def test_value_constraints(self) -> None:
        cases = [
            {"severityAssessment": "high"},
            {"severityAssessment": "SEVERE"},
            {"confidenceScore": 101},
            {"confidenceScore": -1},
            {"confidenceScore": True},
            {"gpuSeconds": -0.1},
            {"needsVerification": "yes"},
            {"toolCalls": [{"tool": "nmap", "args": "x", "rationale": "r"}]},
            {"toolCalls": [{"tool": "nmap", "args": {}, "rationale": "r", "extra": 1}]},
            {"toolCalls": "nmap"},
        ]
        for patch in cases:
            self.assertTrue(sv.validate_ai({**self.analysis, **patch}), patch)

    def test_mapping_into_alert(self) -> None:
        fields = sv.ai_to_alert_fields(self.analysis)
        self.assertEqual(fields["severity"], "high")
        self.assertEqual(fields["mitre"]["tactic"], ["Credential Access"])
        self.assertEqual(fields["mitre"]["technique"], ["T1110 Brute Force"])
        self.assertEqual(fields["mitre"]["id"], ["T1110"])
        self.assertEqual(fields["ai"]["cost"]["gpu_seconds"], 6.42)
        self.assertEqual(fields["ai"]["role"], "triage")
        self.assertFalse(fields["ai"]["fallback"])
        heuristic = {**self.analysis, "engineUsed": "Cecur Heuristics"}
        self.assertEqual(sv.ai_to_alert_fields(heuristic)["ai"]["role"], "heuristic")
        self.assertTrue(sv.ai_to_alert_fields(heuristic)["ai"]["fallback"])

    def test_merge_keeps_alert_valid(self) -> None:
        base = sv.normalize_vendetta_alert(load("vendetta-alert.json"))
        self.assertEqual(sv.validate_alert(base), [])
        merged = sv.merge_ai_into_alert(base, {**self.analysis, "severityAssessment": "CRITICAL"})
        self.assertEqual(merged["severity"], "critical")
        self.assertEqual(sv.validate_alert(merged, check_level_consistency=False), [])
        self.assertTrue(sv.validate_alert(merged))


class AlertTests(unittest.TestCase):
    def test_fim_fixture_normalizes_to_fim_stream(self) -> None:
        alert = sv.normalize_vendetta_alert(load("vendetta-fim.json"))
        self.assertEqual(alert["source"], {"system": "vendetta", "stream": "fim"})
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(sv.validate_alert(alert), [])

    def test_alert_rejects_bad_fields(self) -> None:
        alert = sv.normalize_vendetta_alert(load("vendetta-alert.json"))
        for patch in ({"severity": "urgent"}, {"@timestamp": "yesterday"}, {"rule": {**alert["rule"], "level": 16}}):
            self.assertTrue(sv.validate_alert({**alert, **patch}), patch)


class FixtureTests(unittest.TestCase):
    def test_all_fixtures_are_valid_json_without_secrets(self) -> None:
        pattern = re.compile(r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{20,}|YOUR_API_KEY|TODO|CHANGEME)")
        for path in sorted(FIXTURES.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            json.loads(text)
            self.assertIsNone(pattern.search(text), path.name)

    def test_mcp_tool_call_hash_chain(self) -> None:
        event = load("errow-mcp-tool-call.json")
        self.assertEqual(event["event_type"], "tool_call")
        self.assertEqual(event["prev_hash"], "0" * 64)
        body = {k: v for k, v in event.items() if k != "hash"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(hashlib.sha256((event["prev_hash"] + canonical).encode()).hexdigest(), event["hash"])
        self.assertEqual(event["target"], "scan-target.vendetta.lab")
        self.assertEqual(event["decision"], "dry_run")
        self.assertFalse(event["live"])

    def test_llm_request_has_no_prompt_bodies(self) -> None:
        event = load("errow-llm-request.json")
        self.assertFalse({"messages", "prompt", "response", "completion"} & set(event))
        self.assertEqual(event["api_host"], "llm-gateway:9101")
        self.assertFalse(event["streaming"])

    def test_threat_model_has_required_sections(self) -> None:
        for model in load("errow-threat-model.json").values():
            lowered = model["content"].lower()
            for section in ("overview", "trust boundaries and assumptions", "attack surface and attacker stories", "severity calibration"):
                self.assertIn(section, lowered)

    def test_run_record_points_at_the_lab_target(self) -> None:
        run = load("errow-run.json")
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["targets_info"][0]["details"]["target_url"], "http://scan-target.vendetta.lab:8080")


class CliTests(unittest.TestCase):
    def test_all_defaults_exit_zero(self) -> None:
        proc = run_cli("all")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("OK   sarif", proc.stdout)

    def test_json_summary(self) -> None:
        proc = run_cli("all", "--json")
        summary = json.loads(proc.stdout)
        self.assertTrue(summary["ok"])
        self.assertEqual(len(summary["checks"]), 3)

    def test_invalid_document_exits_one(self) -> None:
        proc = run_cli("ai", "-", "--no-merge", stdin=json.dumps({"triageSummary": "x"}))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("FAIL", proc.stderr)
        proc = run_cli("sarif", "-", stdin="{not json")
        self.assertEqual(proc.returncode, 1)

    def test_usage_errors_exit_two(self) -> None:
        self.assertEqual(run_cli().returncode, 2)
        self.assertEqual(run_cli("bogus").returncode, 2)
        self.assertEqual(run_cli("sarif", str(FIXTURES / "does-not-exist.json")).returncode, 2)

    def test_emit_alerts_ndjson_is_ingestable(self) -> None:
        proc = run_cli("sarif", "--emit-alerts", "-", "-q")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertEqual({line["source"]["system"] for line in lines}, {"errow"})


if __name__ == "__main__":
    unittest.main()
