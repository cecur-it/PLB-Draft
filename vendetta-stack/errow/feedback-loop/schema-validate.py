#!/usr/bin/env python3
"""schema-validate.py - Errow <-> Vendetta schema round-trip validator (stdlib only).

Spec traceability (vendetta-stack CONTRACT.md):
  sec 4.1  normalized Vendetta alert      -> validate_alert(), normalize_vendetta_alert()
  sec 4.1  SARIF result -> alert mapping  -> sarif_result_to_alert()  (field-by-field table below)
  sec 4.1  severity bands / SARIF levels  -> severity_from_level(), sarif_severity()
  sec 4.2  AIIncidentAnalysis (strict)    -> validate_ai(), ai_to_alert_fields()
  sec 6    G8 round trip, exit codes 0/1/2
  sec 15   alert id == shipper doc_id = sha256(run + ruleId + primaryLocationLineHash)

SARIF result -> alert, field by field (source on the left, alert key on the right):
  properties.errow.timestamp (else now)         -> @timestamp (UTC, millisecond ISO-8601 'Z')
  sha256(run + ruleId + primaryLocationLineHash) -> id (identical to the shipper doc_id)
  constant                                      -> source {system: errow, stream: errow.findings}
  ruleId                                        -> rule.id, errow.sarif_rule_id
  severity (errow.severity | level map)         -> severity, rule.level (info 3, low 5, medium 8, high 11, critical 14)
  first line of message.text                    -> rule.description
  rule tags + constants                         -> rule.groups
  CWE (errow.cwe | ruleId)                      -> errow.cwe, mitre.* / rule.mitre (CWE map below), errow.owasp
  errow.cve | ruleId CVE-...                    -> errow.cve (omitted when absent)
  errow.cvss | security-severity                -> errow.cvss
  errow.confidence                              -> errow.confidence
  errow.target / errow.endpoint                 -> errow.target / errow.endpoint, agent.name (host), location
  errow.id                                      -> errow.finding_id
  partialFingerprints.primaryLocationLineHash   -> errow.fingerprint
  message.text                                  -> full_log (<= 8000 chars)
  errow.technical_analysis / remediation_steps  -> root_cause / recommended_action
  run name                                      -> errow.run

The CWE -> MITRE / OWASP tables are a deliberately small local reference; the OpenSearch ingest
pipeline remains authoritative in production and must agree on the fields compared here.

Exit codes: 0 valid, 1 invalid document(s), 2 usage / unreadable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_TO_LEVEL = {"info": 3, "low": 5, "medium": 8, "high": 11, "critical": 14}
SARIF_LEVELS = ("error", "warning", "note", "none")
SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
AI_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
AI_REQUIRED_STR = (
    "triageSummary",
    "severityAssessment",
    "mitreTactic",
    "mitreTechnique",
    "probableRootCause",
    "recommendedImmediateAction",
    "engineUsed",
)
AI_ALLOWED = set(AI_REQUIRED_STR) | {
    "confidenceScore",
    "needsVerification",
    "toolCalls",
    "gpuSeconds",
    "proposedDetectionRule",
    "proposedRemediation",
}
HEURISTIC_ENGINE = "Cecur Heuristics"
ALERT_SOURCES = ("vendetta", "errow", "cs3-ai")
FULL_LOG_MAX = 8000
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CWE_RE = re.compile(r"^CWE-\d+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# CWE -> (MITRE technique id, technique name, tactic)
CWE_MITRE = {
    "CWE-89": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "CWE-79": ("T1189", "Drive-by Compromise", "Initial Access"),
    "CWE-78": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-77": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-94": ("T1059", "Command and Scripting Interpreter", "Execution"),
    "CWE-22": ("T1083", "File and Directory Discovery", "Discovery"),
    "CWE-918": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "CWE-287": ("T1078", "Valid Accounts", "Initial Access"),
    "CWE-306": ("T1078", "Valid Accounts", "Initial Access"),
    "CWE-798": ("T1552", "Unsecured Credentials", "Credential Access"),
    "CWE-200": ("T1592", "Gather Victim Host Information", "Reconnaissance"),
    "CWE-209": ("T1592", "Gather Victim Host Information", "Reconnaissance"),
}
DEFAULT_MITRE = ("T1190", "Exploit Public-Facing Application", "Initial Access")
CWE_OWASP = {
    "CWE-89": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-77": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-200": "A01:2021 Broken Access Control",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-862": "A01:2021 Broken Access Control",
    "CWE-863": "A01:2021 Broken Access Control",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-311": "A02:2021 Cryptographic Failures",
    "CWE-1021": "A05:2021 Security Misconfiguration",
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-209": "A05:2021 Security Misconfiguration",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-306": "A07:2021 Identification and Authentication Failures",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
}


class InputError(Exception):
    """Unreadable file or unusable arguments (exit code 2)."""


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def severity_from_level(level: int) -> str:
    if level <= 3:
        return "info"
    if level <= 6:
        return "low"
    if level <= 9:
        return "medium"
    if level <= 12:
        return "high"
    return "critical"


def normalise_cwe(value: Any) -> str | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else None


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-2] + ":" + text[-2:]
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def iso_millis(value: datetime) -> str:
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def alert_id(run: str, rule_id: str, fingerprint: str) -> str:
    return hashlib.sha256((run + rule_id + fingerprint).encode()).hexdigest()


def sarif_severity(result: dict[str, Any]) -> str:
    errow = (result.get("properties") or {}).get("errow") or {}
    declared = str(errow.get("severity") or "").lower()
    if declared in SEVERITIES:
        return declared
    return SARIF_LEVEL_TO_SEVERITY.get(str(result.get("level") or "warning"), "medium")


# --------------------------------------------------------------------------- SARIF validation
def _find_key(node: Any, key: str, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(node, dict):
        for name, child in node.items():
            if name == key:
                hits.append(f"{path}.{name}")
            hits.extend(_find_key(child, key, f"{path}.{name}"))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            hits.extend(_find_key(child, key, f"{path}[{index}]"))
    return hits


def validate_sarif(doc: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["SARIF document must be a JSON object"]
    if doc.get("version") != "2.1.0":
        errors.append(f"version must be '2.1.0', got {doc.get('version')!r}")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        return [*errors, "runs must be a non-empty array"]
    for leak in _find_key(doc, "poc_script_code"):
        errors.append(f"{leak}: exploit script bodies must never appear in SARIF")
    for r_index, run in enumerate(runs):
        where = f"runs[{r_index}]"
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        if not isinstance(driver.get("name"), str) or not driver["name"]:
            errors.append(f"{where}.tool.driver.name missing")
        rules = driver.get("rules") or []
        ids = [rule.get("id") for rule in rules if isinstance(rule, dict)]
        if len(ids) != len(set(ids)):
            errors.append(f"{where}: duplicate rule ids")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"{where}.results must be an array")
            continue
        for index, result in enumerate(results):
            errors.extend(_validate_result(f"{where}.results[{index}]", result, rules))
    return errors


def _validate_result(where: str, result: Any, rules: list[Any]) -> list[str]:
    if not isinstance(result, dict):
        return [f"{where}: result must be an object"]
    errors: list[str] = []
    rule_id = result.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        errors.append(f"{where}.ruleId missing")
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool):
        if not 0 <= index < len(rules) or rules[index].get("id") != rule_id:
            errors.append(f"{where}.ruleIndex {index} does not point at rule {rule_id!r}")
    elif rule_id not in [rule.get("id") for rule in rules if isinstance(rule, dict)]:
        errors.append(f"{where}: ruleId {rule_id!r} is not declared in tool.driver.rules")
    if result.get("level") not in SARIF_LEVELS:
        errors.append(f"{where}.level must be one of {SARIF_LEVELS}")
    text = (result.get("message") or {}).get("text")
    if not isinstance(text, str) or not text.strip():
        errors.append(f"{where}.message.text missing")
    locations = result.get("locations")
    if locations is not None:
        if not isinstance(locations, list) or not locations:
            errors.append(f"{where}.locations must be a non-empty array when present")
        else:
            for loc in locations:
                physical = ((loc or {}).get("physicalLocation") or {}).get("artifactLocation") or {}
                logical = (loc or {}).get("logicalLocations") or []
                if not isinstance(physical.get("uri"), str) and not logical:
                    errors.append(f"{where}.locations: entry has neither a uri nor logicalLocations")
    if result.get("kind", "fail") == "fail":
        fingerprint = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
        if not isinstance(fingerprint, str) or not HEX64.match(fingerprint):
            errors.append(f"{where}.partialFingerprints.primaryLocationLineHash must be 64 hex chars")
    props = result.get("properties")
    if not isinstance(props, dict):
        return [*errors, f"{where}.properties missing"]
    score = props.get("security-severity")
    try:
        if not 0.0 <= float(score) <= 10.0:
            raise ValueError
    except (TypeError, ValueError):
        errors.append(f"{where}.properties.security-severity must be a number string 0.0-10.0")
    errow = props.get("errow")
    if not isinstance(errow, dict):
        return [*errors, f"{where}.properties.errow missing"]
    if errow.get("severity") is not None and errow["severity"] not in SEVERITIES:
        errors.append(f"{where}.properties.errow.severity {errow['severity']!r} not in {SEVERITIES}")
    if errow.get("cvss") is not None and not is_number(errow["cvss"]):
        errors.append(f"{where}.properties.errow.cvss must be a number")
    for key in ("id", "target", "endpoint", "cwe", "cve", "confidence"):
        if errow.get(key) is not None and not isinstance(errow[key], str):
            errors.append(f"{where}.properties.errow.{key} must be a string")
    poc = errow.get("poc")
    if poc is not None and (not isinstance(poc, dict) or set(poc) - {"description", "script_available"}):
        errors.append(f"{where}.properties.errow.poc may only hold description/script_available")
    return errors


# --------------------------------------------------------------------------- alert validation
def validate_alert(alert: Any, *, check_level_consistency: bool = True) -> list[str]:
    if not isinstance(alert, dict):
        return ["alert must be a JSON object"]
    errors: list[str] = []
    stamp = alert.get("@timestamp")
    try:
        parse_timestamp(stamp)
    except (TypeError, ValueError, AttributeError):
        errors.append(f"@timestamp must be ISO-8601, got {stamp!r}")
    if not isinstance(alert.get("id"), str) or not alert["id"]:
        errors.append("id must be a non-empty string")
    source = alert.get("source")
    if not isinstance(source, dict) or source.get("system") not in ALERT_SOURCES:
        errors.append(f"source.system must be one of {ALERT_SOURCES}")
    elif not isinstance(source.get("stream"), str) or not source["stream"]:
        errors.append("source.stream must be a non-empty string")
    rule = alert.get("rule")
    level = None
    rule_mitre = None
    if not isinstance(rule, dict):
        errors.append("rule must be an object")
    else:
        level = rule.get("level")
        rule_mitre = rule.get("mitre")
        if not isinstance(rule.get("id"), str) or not rule["id"]:
            errors.append("rule.id must be a non-empty string")
        if not isinstance(level, int) or isinstance(level, bool) or not 0 <= level <= 15:
            errors.append("rule.level must be an integer 0-15")
            level = None
        if not isinstance(rule.get("description"), str):
            errors.append("rule.description must be a string")
        if "groups" in rule and not is_str_list(rule["groups"]):
            errors.append("rule.groups must be an array of strings")
    severity = alert.get("severity")
    if severity not in SEVERITIES:
        errors.append(f"severity must be one of {SEVERITIES}")
    elif check_level_consistency and level is not None and severity != severity_from_level(level):
        errors.append(f"severity {severity!r} disagrees with rule.level {level}")
    for scope, node in (("mitre", alert.get("mitre")), ("rule.mitre", rule_mitre)):
        if node is None:
            continue
        if not isinstance(node, dict) or any(not is_str_list(node.get(k, [])) for k in ("id", "tactic", "technique")):
            errors.append(f"{scope} must hold string arrays id/tactic/technique")
    for key in ("agent", "manager"):
        if key in alert and not isinstance(alert[key], dict):
            errors.append(f"{key} must be an object")
    for key in ("location", "full_log", "root_cause", "recommended_action"):
        if key in alert and not isinstance(alert[key], str):
            errors.append(f"{key} must be a string")
    if isinstance(alert.get("full_log"), str) and len(alert["full_log"]) > FULL_LOG_MAX:
        errors.append(f"full_log exceeds {FULL_LOG_MAX} characters")
    if "ai" in alert:
        errors.extend(_validate_ai_block(alert["ai"]))
    if isinstance(source, dict) and source.get("system") == "errow":
        errors.extend(_validate_errow_block(alert.get("errow")))
    elif "errow" in alert and not isinstance(alert["errow"], dict):
        errors.append("errow must be an object")
    return errors


def _validate_ai_block(ai: Any) -> list[str]:
    if not isinstance(ai, dict):
        return ["ai must be an object"]
    errors: list[str] = []
    if not isinstance(ai.get("engine"), str) or not ai["engine"]:
        errors.append("ai.engine must be a non-empty string")
    if ai.get("role") not in ("triage", "forensic", "heuristic"):
        errors.append("ai.role must be triage|forensic|heuristic")
    if not is_number(ai.get("confidence")):
        errors.append("ai.confidence must be a number")
    if not isinstance(ai.get("fallback"), bool):
        errors.append("ai.fallback must be a boolean")
    cost = ai.get("cost")
    gpu = cost.get("gpu_seconds") if isinstance(cost, dict) else None
    if gpu is not None and (not is_number(gpu) or gpu < 0):
        errors.append("ai.cost.gpu_seconds must be a number >= 0")
    return errors


def _validate_errow_block(errow: Any) -> list[str]:
    if not isinstance(errow, dict):
        return ["errow must be an object for source.system == errow"]
    errors = [
        f"errow.{key} must be a non-empty string"
        for key in ("run", "finding_id", "sarif_rule_id", "target")
        if not isinstance(errow.get(key), str) or not errow[key]
    ]
    fingerprint = errow.get("fingerprint")
    if not isinstance(fingerprint, str) or not HEX64.match(fingerprint):
        errors.append("errow.fingerprint must be 64 hex chars")
    if errow.get("cvss") is not None and not is_number(errow["cvss"]):
        errors.append("errow.cvss must be a number")
    for key in ("cwe", "cve", "owasp", "confidence", "endpoint"):
        if errow.get(key) is not None and not isinstance(errow[key], str):
            errors.append(f"errow.{key} must be a string")
    if isinstance(errow.get("cwe"), str) and not CWE_RE.match(errow["cwe"]):
        errors.append("errow.cwe must look like CWE-<number>")
    return errors


# --------------------------------------------------------------------------- SARIF -> alert
def _target_host(target: str) -> str:
    match = re.match(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", target)
    return match.group(1).strip("[]") if match else target


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _first_uri(result: dict[str, Any]) -> str:
    for loc in result.get("locations") or []:
        uri = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        if uri:
            return str(uri)
    return ""


def sarif_result_to_alert(
    result: dict[str, Any], rules: list[dict[str, Any]], run: str, fallback_time: datetime
) -> dict[str, Any]:
    props = result.get("properties") or {}
    errow = dict(props.get("errow") or {})
    rule_id = str(result["ruleId"])
    rule = next((r for r in rules if r.get("id") == rule_id), {})
    fingerprint = str((result.get("partialFingerprints") or {}).get("primaryLocationLineHash") or "")
    severity = sarif_severity(result)
    cwe = normalise_cwe(errow.get("cwe")) if errow.get("cwe") else (rule_id if CWE_RE.match(rule_id) else None)
    cve = errow.get("cve") or (rule_id if CVE_RE.match(rule_id) else None)
    technique_id, technique, tactic = CWE_MITRE.get(cwe or "", DEFAULT_MITRE)
    message = str((result.get("message") or {}).get("text") or rule_id)
    target = str(errow.get("target") or "")
    endpoint = str(errow.get("endpoint") or "")
    stamp = parse_timestamp(errow["timestamp"]) if errow.get("timestamp") else fallback_time
    tags = [str(t).lower() for t in ((rule.get("properties") or {}).get("tags") or [])]
    host = _target_host(target) if target else ""

    errow_block: dict[str, Any] = {
        "run": run,
        "finding_id": str(errow.get("id") or rule_id),
        "sarif_rule_id": rule_id,
        "fingerprint": fingerprint,
        "target": target,
    }
    optional = (
        ("cwe", cwe),
        ("cve", cve),
        ("owasp", CWE_OWASP.get(cwe or "")),
        ("endpoint", endpoint or None),
        ("confidence", errow.get("confidence")),
    )
    for key, value in optional:
        if value:
            errow_block[key] = value
    cvss = errow.get("cvss")
    if cvss is None and props.get("security-severity") is not None:
        cvss = float(props["security-severity"])
    if cvss is not None:
        errow_block["cvss"] = float(cvss)

    agent: dict[str, Any] = {"id": "errow", "name": host or "errow"}
    if _is_ipv4(host):
        agent["ip"] = host
    alert: dict[str, Any] = {
        "@timestamp": iso_millis(stamp),
        "id": alert_id(run, rule_id, fingerprint),
        "source": {"system": "errow", "stream": "errow.findings"},
        "rule": {
            "id": rule_id,
            "level": SEVERITY_TO_LEVEL[severity],
            "description": message.splitlines()[0][:300] if message else rule_id,
            "groups": list(dict.fromkeys(["errow", "errow_finding", *tags])),
            "mitre": {"id": [technique_id], "tactic": [tactic], "technique": [technique]},
        },
        "agent": agent,
        "manager": {"name": "errow"},
        "location": (target.rstrip("/") + endpoint) if target and endpoint else (_first_uri(result) or target),
        "full_log": message[:FULL_LOG_MAX],
        "severity": severity,
        "mitre": {"id": [technique_id], "tactic": [tactic], "technique": [technique]},
        "errow": errow_block,
    }
    if errow.get("technical_analysis"):
        alert["root_cause"] = str(errow["technical_analysis"])
    if errow.get("remediation_steps"):
        alert["recommended_action"] = str(errow["remediation_steps"])
    return alert


def alert_to_finding_view(alert: dict[str, Any]) -> dict[str, Any]:
    """Reverse mapping used by the round-trip check: what a consumer can recover from an alert."""
    errow = alert.get("errow") or {}
    return {
        "ruleId": errow.get("sarif_rule_id"),
        "severity": alert.get("severity"),
        "cwe": errow.get("cwe"),
        "cve": errow.get("cve"),
        "fingerprint": errow.get("fingerprint"),
        "target": errow.get("target"),
        "endpoint": errow.get("endpoint"),
    }


def roundtrip_errors(result: dict[str, Any], alert: dict[str, Any], run: str) -> list[str]:
    errors: list[str] = []
    view = alert_to_finding_view(alert)
    errow = (result.get("properties") or {}).get("errow") or {}
    expected_sev = sarif_severity(result)
    fingerprint = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
    expected = {
        "ruleId": result.get("ruleId"),
        "severity": expected_sev,
        "fingerprint": fingerprint,
        "target": errow.get("target") or "",
        "endpoint": errow.get("endpoint"),
    }
    for key, want in expected.items():
        if view[key] != want:
            errors.append(f"round-trip {key}: SARIF has {want!r}, alert has {view[key]!r}")
    level = alert["rule"]["level"]
    if level != SEVERITY_TO_LEVEL[expected_sev] or severity_from_level(level) != expected_sev:
        errors.append(f"round-trip severity: rule.level {level} does not map back to {expected_sev!r}")
    if errow.get("cwe") and view["cwe"] != normalise_cwe(errow["cwe"]):
        errors.append(f"round-trip CWE: SARIF {errow['cwe']!r} vs alert {view['cwe']!r}")
    if errow.get("cve") and view["cve"] != errow["cve"]:
        errors.append(f"round-trip CVE: SARIF {errow['cve']!r} vs alert {view['cve']!r}")
    mitre = alert.get("mitre") or {}
    if not (mitre.get("id") and mitre.get("tactic") and mitre.get("technique")):
        errors.append("round-trip MITRE: alert.mitre is incomplete")
    if mitre != alert["rule"].get("mitre"):
        errors.append("round-trip MITRE: alert.mitre differs from rule.mitre")
    if alert["id"] != alert_id(run, str(result.get("ruleId")), str(fingerprint)):
        errors.append("round-trip id: alert id is not sha256(run + ruleId + fingerprint)")
    logical = [ll.get("fullyQualifiedName") for loc in result.get("locations") or [] for ll in loc.get("logicalLocations") or []]
    if logical and errow.get("endpoint") and errow["endpoint"] not in logical:
        errors.append("round-trip endpoint: errow.endpoint is not among the SARIF logicalLocations")
    return errors


def fail_results(doc: dict[str, Any]) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    pairs = []
    for sarif_run in doc.get("runs") or []:
        rules = ((sarif_run.get("tool") or {}).get("driver") or {}).get("rules") or []
        pairs.extend((res, rules) for res in sarif_run.get("results") or [] if res.get("kind", "fail") == "fail")
    return pairs


def transform_sarif(doc: dict[str, Any], run: str, fallback_time: datetime | None = None) -> list[dict[str, Any]]:
    now = fallback_time or datetime.now(UTC)
    return [sarif_result_to_alert(result, rules, run, now) for result, rules in fail_results(doc)]


# --------------------------------------------------------------------------- AIIncidentAnalysis
def validate_ai(analysis: Any) -> list[str]:
    if not isinstance(analysis, dict):
        return ["AIIncidentAnalysis must be a JSON object"]
    errors = [f"unexpected property {key!r} (additionalProperties is false)" for key in sorted(set(analysis) - AI_ALLOWED)]
    for key in AI_REQUIRED_STR:
        value = analysis.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{key} is required and must be a non-empty string")
    if analysis.get("severityAssessment") not in AI_SEVERITIES:
        errors.append(f"severityAssessment must be one of {AI_SEVERITIES}")
    score = analysis.get("confidenceScore")
    if not is_number(score) or not 0 <= score <= 100:
        errors.append("confidenceScore is required and must be a number 0-100")
    if "needsVerification" in analysis and not isinstance(analysis["needsVerification"], bool):
        errors.append("needsVerification must be a boolean")
    if "gpuSeconds" in analysis and (not is_number(analysis["gpuSeconds"]) or analysis["gpuSeconds"] < 0):
        errors.append("gpuSeconds must be a number >= 0")
    for key in ("proposedDetectionRule", "proposedRemediation"):
        if key in analysis and not isinstance(analysis[key], str):
            errors.append(f"{key} must be a string")
    calls = analysis.get("toolCalls")
    if calls is not None:
        if not isinstance(calls, list):
            errors.append("toolCalls must be an array")
        else:
            for index, call in enumerate(calls):
                if not isinstance(call, dict) or set(call) != {"tool", "args", "rationale"}:
                    errors.append(f"toolCalls[{index}] must be exactly {{tool, args, rationale}}")
                elif not (
                    isinstance(call["tool"], str)
                    and call["tool"]
                    and isinstance(call["args"], dict)
                    and isinstance(call["rationale"], str)
                ):
                    errors.append(f"toolCalls[{index}]: tool/rationale must be strings and args an object")
    return errors


def ai_to_alert_fields(analysis: dict[str, Any], role: str = "triage") -> dict[str, Any]:
    heuristic = analysis["engineUsed"] == HEURISTIC_ENGINE
    technique = analysis["mitreTechnique"]
    return {
        "severity": analysis["severityAssessment"].lower(),
        "mitre": {
            "id": list(dict.fromkeys(TECHNIQUE_RE.findall(technique))),
            "tactic": [analysis["mitreTactic"]],
            "technique": [technique],
        },
        "root_cause": analysis["probableRootCause"],
        "recommended_action": analysis["recommendedImmediateAction"],
        "ai": {
            "engine": analysis["engineUsed"],
            "role": "heuristic" if heuristic else role,
            "confidence": analysis["confidenceScore"],
            "fallback": heuristic,
            "cost": {"gpu_seconds": analysis.get("gpuSeconds", 0)},
        },
    }


def normalize_vendetta_alert(raw: dict[str, Any]) -> dict[str, Any]:
    """Minimal analysisd -> sec 4.1 normalization so an AI enrichment can be merged and re-validated."""
    alert = json.loads(json.dumps(raw))
    if "@timestamp" not in alert and alert.get("timestamp"):
        alert["@timestamp"] = iso_millis(parse_timestamp(alert["timestamp"]))
    groups = set((alert.get("rule") or {}).get("groups") or [])
    if "syscheck" in groups:
        stream = "fim"
    elif "vulnerability-detector" in groups:
        stream = "vulnerability"
    elif "sca" in groups:
        stream = "sca"
    else:
        stream = "alerts"
    alert.setdefault("source", {"system": "vendetta", "stream": stream})
    level = (alert.get("rule") or {}).get("level")
    if isinstance(level, int) and "severity" not in alert:
        alert["severity"] = severity_from_level(level)
    rule_mitre = (alert.get("rule") or {}).get("mitre")
    if rule_mitre and "mitre" not in alert:
        alert["mitre"] = {k: list(rule_mitre.get(k, [])) for k in ("id", "tactic", "technique")}
    return alert


def merge_ai_into_alert(alert: dict[str, Any], analysis: dict[str, Any], role: str = "triage") -> dict[str, Any]:
    merged = json.loads(json.dumps(alert))
    merged.update(ai_to_alert_fields(analysis, role))
    return merged


# --------------------------------------------------------------------------- CLI
def default_fixtures_dir() -> Path:
    env = os.environ.get("FIXTURES_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent.parent / "tests" / "synthetic-logs"


def load_json(path: str) -> Any:
    try:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON ({exc})") from exc


def resolve_run(explicit: str | None, sarif_path: str) -> str:
    if explicit:
        return explicit
    base = Path(sarif_path).resolve().parent if sarif_path != "-" else Path.cwd()
    for name in ("run.json", "errow-run.json"):
        candidate = base / name
        if candidate.is_file():
            try:
                run_name = json.loads(candidate.read_text(encoding="utf-8")).get("run_name")
            except (OSError, ValueError):
                run_name = None
            if run_name:
                return str(run_name)
    return base.name


def write_output(target: str, text: str) -> None:
    if target == "-":
        sys.stdout.write(text)
    else:
        Path(target).write_text(text, encoding="utf-8")


class Report:
    def __init__(self, as_json: bool, quiet: bool) -> None:
        self.as_json = as_json
        self.quiet = quiet
        self.checks: list[dict[str, Any]] = []

    def add(self, name: str, errors: list[str], detail: str = "") -> None:
        self.checks.append({"check": name, "ok": not errors, "detail": detail, "errors": errors})
        if self.as_json or (self.quiet and not errors):
            return
        if errors:
            print(f"[schema-validate] FAIL {name}", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        else:
            print(f"[schema-validate] OK   {name}{': ' + detail if detail else ''}", file=sys.stderr if self.quiet else sys.stdout)

    @property
    def ok(self) -> bool:
        return all(check["ok"] for check in self.checks)

    def finish(self) -> int:
        if self.as_json:
            print(json.dumps({"ok": self.ok, "checks": self.checks}, indent=2))
        return 0 if self.ok else 1


def run_sarif(report: Report, path: str, run_name: str | None, emit: str | None) -> None:
    try:
        doc = load_json(path)
    except ValueError as exc:
        report.add(f"sarif {path}", [str(exc)])
        return
    errors = validate_sarif(doc)
    if errors:
        report.add(f"sarif {path}", errors)
        return
    run = resolve_run(run_name, path)
    pairs = fail_results(doc)
    alerts = transform_sarif(doc, run)
    problems: list[str] = []
    for (result, _rules), alert in zip(pairs, alerts, strict=True):
        fingerprint = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash", "")
        label = f"{result.get('ruleId')}@{fingerprint[:8]}"
        problems += [f"{label}: {e}" for e in validate_alert(alert)]
        problems += [f"{label}: {e}" for e in roundtrip_errors(result, alert, run)]
    total = sum(len(r.get("results") or []) for r in doc["runs"])
    report.add(f"sarif {path}", problems, f"{len(alerts)} result(s) -> alerts ({total - len(alerts)} non-fail skipped), run={run}")
    if emit and not problems:
        write_output(emit, "".join(json.dumps(a, separators=(",", ":")) + "\n" for a in alerts))


def run_ai(report: Report, path: str, alert_path: str | None, role: str, emit: str | None) -> None:
    try:
        analysis = load_json(path)
    except ValueError as exc:
        report.add(f"ai {path}", [str(exc)])
        return
    errors = validate_ai(analysis)
    engine = analysis.get("engineUsed") if isinstance(analysis, dict) else "?"
    report.add(f"ai {path}", errors, f"engine={engine}")
    if errors or not alert_path:
        return
    try:
        raw = load_json(alert_path)
    except ValueError as exc:
        report.add(f"ai-merge {alert_path}", [str(exc)])
        return
    base = normalize_vendetta_alert(raw)
    problems = [f"base alert: {e}" for e in validate_alert(base)]
    merged = merge_ai_into_alert(base, analysis, role)
    problems += [f"merged alert: {e}" for e in validate_alert(merged, check_level_consistency=False)]
    if merged["severity"] != analysis["severityAssessment"].lower():
        problems.append("merged severity does not equal the lowercased severityAssessment")
    if merged["ai"]["cost"]["gpu_seconds"] != analysis.get("gpuSeconds", 0):
        problems.append("merged ai.cost.gpu_seconds does not equal gpuSeconds")
    report.add(f"ai-merge {alert_path}", problems, f"severity {base.get('severity')} -> {merged['severity']}")
    if emit and not problems:
        write_output(emit, json.dumps(merged, separators=(",", ":")) + "\n")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print one machine-readable JSON summary")
    common.add_argument("-q", "--quiet", action="store_true", help="print failures only")
    common.add_argument("--fixtures-dir", help="fixture directory for defaults (env FIXTURES_DIR; default ../../tests/synthetic-logs)")
    parser = argparse.ArgumentParser(
        prog="schema-validate.py",
        description="Validate the Errow SARIF -> Vendetta alert round trip (contract 4.1) and AIIncidentAnalysis (4.2).",
        epilog="Exit codes: 0 valid, 1 invalid, 2 usage/unreadable input. '-' reads stdin.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_sarif = sub.add_parser("sarif", parents=[common], help="validate a SARIF file and its alert transform")
    p_sarif.add_argument("file", nargs="?", help="SARIF file (default: <fixtures>/errow-finding.sarif.json)")
    p_sarif.add_argument("--run", help="Errow run name (default: run_name of sibling run.json/errow-run.json)")
    p_sarif.add_argument("--emit-alerts", metavar="FILE", help="write the mapped alerts as NDJSON ('-' = stdout)")
    p_ai = sub.add_parser("ai", parents=[common], help="validate an AIIncidentAnalysis and its alert mapping")
    p_ai.add_argument("file", nargs="?", help="analysis file (default: <fixtures>/ai-incident-analysis.json)")
    p_ai.add_argument("--alert", help="raw/normalized alert to merge into (default: <fixtures>/vendetta-alert.json)")
    p_ai.add_argument("--no-merge", action="store_true", help="validate the schema only")
    p_ai.add_argument("--role", choices=("triage", "forensic"), default="triage")
    p_ai.add_argument("--emit-alert", metavar="FILE", help="write the merged alert as JSON ('-' = stdout)")
    p_all = sub.add_parser("all", parents=[common], help="run sarif and ai with fixture defaults")
    p_all.add_argument("--sarif")
    p_all.add_argument("--ai")
    p_all.add_argument("--alert")
    p_all.add_argument("--run")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 2
    fixtures = Path(args.fixtures_dir) if args.fixtures_dir else default_fixtures_dir()
    report = Report(args.json, args.quiet)
    try:
        if args.command == "sarif":
            run_sarif(report, args.file or str(fixtures / "errow-finding.sarif.json"), args.run, args.emit_alerts)
        elif args.command == "ai":
            alert_path = None if args.no_merge else (args.alert or str(fixtures / "vendetta-alert.json"))
            run_ai(report, args.file or str(fixtures / "ai-incident-analysis.json"), alert_path, args.role, args.emit_alert)
        else:
            run_sarif(report, args.sarif or str(fixtures / "errow-finding.sarif.json"), args.run, None)
            run_ai(report, args.ai or str(fixtures / "ai-incident-analysis.json"), args.alert or str(fixtures / "vendetta-alert.json"), "triage", None)
    except InputError as exc:
        print(f"[schema-validate] error: {exc}", file=sys.stderr)
        return 2
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
