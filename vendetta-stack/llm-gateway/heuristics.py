# Traces: PROMPT §1 Tier 4 (tier-3 deterministic fallback); CONTRACT §4.3 (heuristic fallback = deterministic MITRE/anomaly map),
#         §4.1 (level->severity map), §4.2 (AIIncidentAnalysis); CS3 server/ai/cecurAI.ts (deterministic fallback: anomaly 0.8/0.5, T1059 default).
"""Deterministic, model-free incident analysis. Same input => byte-identical output; it can never fail and uses no GPU.

Severity is the MAXIMUM over every available signal (rule level, SARIF/Errow severity, CVSS, anomaly score, matched rule
floors). Free text can therefore only ever RAISE the heuristic severity, never lower it.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from schema import SEVERITIES, severity_rank

ENGINE_NAME = "Cecur Heuristics"
HEURISTIC_MODEL = "cecur-heuristics"
DEFAULT_TACTIC = "Execution"
DEFAULT_TECHNIQUE = "T1059 - Command and Scripting Interpreter"
_MAX_TEXT = 6000
_SAFE_DISPLAY = re.compile(r"[^A-Za-z0-9 ._:/@()\-,#]")


@dataclass(frozen=True)
class HeuristicRule:
    ident: str
    pattern: re.Pattern[str] | None
    groups: frozenset[str]
    tactic: str
    technique: str
    severity: str
    root_cause: str
    action: str


def _rule(ident: str, pattern: str | None, groups: tuple[str, ...], tactic: str, technique: str, severity: str, root_cause: str, action: str) -> HeuristicRule:
    return HeuristicRule(ident, re.compile(pattern, re.I) if pattern else None, frozenset(groups), tactic, technique, severity, root_cause, action)


RULES: tuple[HeuristicRule, ...] = (
    _rule("ransomware", r"ransom|\.locked\b|\.encrypted\b|decrypt[_ -]?instructions|vssadmin\s+delete|shadow\s*cop(y|ies)", ("ransomware",),
          "Impact", "T1486 - Data Encrypted for Impact", "CRITICAL",
          "Mass file modification or backup deletion consistent with ransomware activity.",
          "Isolate the host from the network, preserve volatile evidence and disable the affected account pending incident-response approval."),
    _rule("webshell", r"web\s*shell|\bc99\b|\bb374k\b|china chopper|eval\(\$_(post|request|get)", ("web_shell", "webshell"),
          "Persistence", "T1505.003 - Web Shell", "CRITICAL",
          "A web-accessible script that executes attacker-supplied commands was written or invoked.",
          "Quarantine the file, rotate credentials reachable from the web service account and review web server access logs for the same source."),
    _rule("credential-dumping", r"mimikatz|lsass|sekurlsa|ntds\.dit|credential\s+dump|procdump.+lsass|/etc/shadow", ("credential_access", "credential_dumping"),
          "Credential Access", "T1003 - OS Credential Dumping", "HIGH",
          "A process accessed credential stores or LSASS memory, which is a credential-dumping pattern.",
          "Isolate the host, force a credential reset for accounts that logged on recently and review the parent process chain."),
    _rule("log-tampering", r"log\s+(file\s+)?(was\s+)?(cleared|deleted|truncated)|wevtutil\s+cl|clear-eventlog|history\s+-c|auditd?\s+(was\s+)?(stopped|disabled)|logging\s+disabled", ("log_clearing", "audit_tampering"),
          "Defense Evasion", "T1070 - Indicator Removal", "HIGH",
          "Audit or event logs were cleared or the logging service was stopped.",
          "Preserve the remaining logs off-host, identify the account that cleared them and review activity in the preceding hour."),
    _rule("privilege-escalation", r"privilege\s+escalation|not\s+in\s+the\s+sudoers|setuid|uac\s+bypass|token\s+manipulation|dirty\s*(pipe|cow)|pwnkit|cve-2021-4034", ("privilege_escalation", "sudo"),
          "Privilege Escalation", "T1068 - Exploitation for Privilege Escalation", "HIGH",
          "A local account attempted or achieved elevated privileges through a misconfiguration or exploit.",
          "Review the account's recent commands, patch the exploited component and revoke the elevated session."),
    _rule("persistence-ssh-keys", r"authorized_keys|ssh\s+key\s+(added|modified)", ("ssh_keys",),
          "Persistence", "T1098.004 - SSH Authorized Keys", "HIGH",
          "An SSH authorized_keys file was modified, which grants durable remote access.",
          "Validate the added key with the account owner, remove unknown keys and review recent SSH logons."),
    _rule("persistence-scheduled-task", r"\bcron(tab)?\b.*(modif|add|creat)|schtasks|scheduled\s+task\s+(created|added)|systemctl\s+enable|run\s+key|startup\s+folder|launchd", ("persistence", "scheduled_task"),
          "Persistence", "T1053 - Scheduled Task/Job", "MEDIUM",
          "A scheduled task or autostart entry was created, a common persistence mechanism.",
          "Inspect the new entry and its creator, disable it if unapproved and search the fleet for the same artifact."),
    _rule("web-exploitation", r"sql\s*injection|union\s+select|\bxss\b|cross-site|path\s+traversal|\.\./\.\./|remote\s+code\s+execution|\brce\b|log4shell|\$\{jndi:|command\s+injection|\bssrf\b|deserializ", ("web", "attack", "web_attack", "sql_injection", "xss"),
          "Initial Access", "T1190 - Exploit Public-Facing Application", "HIGH",
          "Malicious input reached an internet-facing application and matched a known exploitation pattern.",
          "Block the offending source at the edge, patch or virtually patch the application and review the affected endpoint's logs."),
    _rule("malicious-execution", r"powershell.*(-enc|encodedcommand|downloadstring|\biex\b)|cmd\.exe\s+/c|bash\s+-i|/dev/tcp/|reverse\s+shell|certutil.*-urlcache|\bmshta\b|rundll32|wscript|cscript", ("execution", "powershell", "command_execution"),
          "Execution", "T1059 - Command and Scripting Interpreter", "HIGH",
          "A scripting interpreter was launched with obfuscated or download-and-execute behaviour.",
          "Isolate the host, capture the process tree and command line, and block the referenced download location."),
    _rule("lateral-movement", r"psexec|wmic.+process\s+call|smbexec|\bwinrm\b|pass[- ]the[- ]hash|admin\$|lateral", ("lateral_movement",),
          "Lateral Movement", "T1021 - Remote Services", "HIGH",
          "Remote-service execution or pass-the-hash behaviour indicates movement between hosts.",
          "Identify the source host and account, contain both and restrict administrative protocols between segments."),
    _rule("command-and-control", r"beacon|command[- ]and[- ]control|\bc2\b|dns\s+tunnel|cobalt\s*strike|meterpreter|sliver|known\s+malicious\s+(ip|domain)", ("command_and_control", "c2"),
          "Command and Control", "T1071 - Application Layer Protocol", "HIGH",
          "Periodic or tunnelled outbound traffic matches command-and-control tooling.",
          "Block the destination at the egress proxy, isolate the host and collect network telemetry for the beaconing interval."),
    _rule("exfiltration", r"exfiltrat|large\s+outbound|rclone|mega\.nz|pastebin|upload.*archive", ("exfiltration",),
          "Exfiltration", "T1041 - Exfiltration Over C2 Channel", "HIGH",
          "An unusual volume of data left the environment towards an external destination.",
          "Throttle or block the destination, identify the data set involved and engage the data-protection owner."),
    _rule("denial-of-service", r"denial\s+of\s+service|\bddos\b|syn\s+flood", ("dos", "ddos"),
          "Impact", "T1498 - Network Denial of Service", "HIGH",
          "Traffic volume or malformed packets match a denial-of-service pattern.",
          "Engage upstream filtering, rate-limit the offending sources and confirm service health."),
    _rule("rootkit-malware", r"rootkit|rootcheck|trojan|backdoor|malware|\byara\b|eicar|\bvirus\b", ("rootcheck", "malware"),
          "Defense Evasion", "T1014 - Rootkit", "HIGH",
          "Endpoint scanning flagged a known malware or rootkit signature.",
          "Isolate the host, collect a memory image and reimage after forensic acquisition."),
    _rule("brute-force", r"brute[- ]?force|multiple\s+(failed|authentication)|authentication\s+fail|failed\s+password|invalid\s+(user|login)|logon\s+failure|\b4625\b", ("authentication_failures", "authentication_failed", "brute_force", "invalid_login"),
          "Credential Access", "T1110 - Brute Force", "MEDIUM",
          "Repeated failed authentication attempts indicate password guessing against the account or service.",
          "Block or rate-limit the source address, enforce MFA on the targeted accounts and review for a later successful logon."),
    _rule("sensitive-file-change",
          r"(?s:(syscheck|integrity|file\s+(added|modified|deleted)).*(/etc/(passwd|shadow|sudoers)|/boot/|system32|/usr/s?bin/|/bin/))"
          r"|(?s:(/etc/(passwd|shadow|sudoers)|/boot/|system32|/usr/s?bin/|/bin/).*(syscheck|integrity|file\s+(added|modified|deleted)))", (),
          "Persistence", "T1098 - Account Manipulation", "HIGH",
          "A sensitive system file changed outside an approved maintenance window.",
          "Compare the file with the package baseline, identify the modifying process and restore from a trusted source."),
    _rule("file-integrity", r"integrity\s+checksum\s+changed|file\s+(added|modified|deleted)|syscheck", ("syscheck", "fim", "syscheck_file"),
          "Impact", "T1565.001 - Stored Data Manipulation", "MEDIUM",
          "A monitored file changed and no approved change record is attached to the event.",
          "Verify the change with the file owner and restore the file from baseline if it was not approved."),
    _rule("reconnaissance", r"port\s*scan|\bnmap\b|masscan|network\s+scan|enumerat|\brecon\b", ("recon", "scan"),
          "Discovery", "T1046 - Network Service Discovery", "LOW",
          "A host probed many ports or services, consistent with network reconnaissance.",
          "Confirm the scan source is authorised, otherwise block it and monitor for follow-on exploitation."),
    _rule("vulnerability", r"cve-\d{4}-\d{3,}|vulnerab", ("vulnerability-detector", "vulnerability"),
          "Initial Access", "T1190 - Exploit Public-Facing Application", "MEDIUM",
          "An installed package or exposed service matches a published vulnerability.",
          "Apply the vendor fix or a compensating control and re-scan to confirm closure."),
    _rule("configuration-assessment", r"\bcis\b|benchmark|hardening|misconfiguration", ("sca", "configuration_assessment"),
          "Defense Evasion", "T1562 - Impair Defenses", "LOW",
          "A hardening check failed, leaving a weaker-than-baseline configuration.",
          "Remediate the failed control through configuration management and re-run the assessment."),
)

CWE_MAP: dict[int, tuple[str, str, str]] = {
    89: ("Initial Access", "T1190 - Exploit Public-Facing Application", "HIGH"),
    79: ("Initial Access", "T1189 - Drive-by Compromise", "MEDIUM"),
    77: ("Execution", "T1059 - Command and Scripting Interpreter", "HIGH"),
    78: ("Execution", "T1059 - Command and Scripting Interpreter", "HIGH"),
    94: ("Execution", "T1059 - Command and Scripting Interpreter", "HIGH"),
    95: ("Execution", "T1059 - Command and Scripting Interpreter", "HIGH"),
    502: ("Execution", "T1059 - Command and Scripting Interpreter", "HIGH"),
    22: ("Initial Access", "T1190 - Exploit Public-Facing Application", "MEDIUM"),
    23: ("Initial Access", "T1190 - Exploit Public-Facing Application", "MEDIUM"),
    36: ("Initial Access", "T1190 - Exploit Public-Facing Application", "MEDIUM"),
    918: ("Initial Access", "T1190 - Exploit Public-Facing Application", "HIGH"),
    611: ("Initial Access", "T1190 - Exploit Public-Facing Application", "HIGH"),
    352: ("Initial Access", "T1190 - Exploit Public-Facing Application", "MEDIUM"),
    287: ("Initial Access", "T1078 - Valid Accounts", "HIGH"),
    306: ("Initial Access", "T1078 - Valid Accounts", "HIGH"),
    862: ("Initial Access", "T1078 - Valid Accounts", "MEDIUM"),
    863: ("Initial Access", "T1078 - Valid Accounts", "MEDIUM"),
    639: ("Initial Access", "T1078 - Valid Accounts", "MEDIUM"),
    798: ("Credential Access", "T1552.001 - Credentials In Files", "HIGH"),
    259: ("Credential Access", "T1552.001 - Credentials In Files", "HIGH"),
    321: ("Credential Access", "T1552.001 - Credentials In Files", "HIGH"),
    434: ("Persistence", "T1505.003 - Web Shell", "HIGH"),
}
_CWE_RE = re.compile(r"cwe-(\d{1,5})", re.I)

_SEVERITY_WORDS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "moderate": "MEDIUM", "low": "LOW", "info": "LOW", "informational": "LOW", "none": "LOW"}
_SARIF_LEVELS = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


def severity_from_level(level: int) -> str:
    """Contract §4.1: 0-3 info, 4-6 low, 7-9 medium, 10-12 high, 13-15 critical (info maps to LOW; the analysis enum has no INFO)."""
    if level >= 13:
        return "CRITICAL"
    if level >= 10:
        return "HIGH"
    if level >= 7:
        return "MEDIUM"
    return "LOW"


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def severity_from_anomaly(score: float) -> str:
    if score > 1.0:
        score = score / 100.0
    if score > 0.8:
        return "CRITICAL"
    if score > 0.5:
        return "HIGH"
    if score > 0.3:
        return "MEDIUM"
    return "LOW"


def _dig(record: Any, *path: str) -> Any:
    current = record
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        value = value.strip()
    elif not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _word(value: Any) -> str | None:
    return _SEVERITY_WORDS.get(value.strip().lower()) if isinstance(value, str) else None


def _display(value: Any, limit: int = 120) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    text = " ".join(str(value).split())
    return _SAFE_DISPLAY.sub("?", text)[:limit]


def _text_of(value: Any, limit: int) -> str:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)[:limit]
    return ""


@dataclass(frozen=True)
class Features:
    groups: frozenset[str]
    text: str
    signals: tuple[str, ...]
    cwe: int | None
    mitre_tactic: str | None
    mitre_technique: str | None
    rule_id: str
    description: str
    agent: str
    location: str


def extract_features(record: Mapping[str, Any]) -> Features:
    groups_raw = _dig(record, "rule", "groups") or record.get("groups") or []
    groups = frozenset(str(g).strip().lower() for g in groups_raw if isinstance(g, (str, int))) if isinstance(groups_raw, list) else frozenset()
    stream = _dig(record, "source", "stream") or record.get("stream")
    parts = [
        _text_of(_dig(record, "rule", "description"), 400),
        _text_of(record.get("title"), 400),
        _text_of(record.get("description"), 400),
        _text_of(_dig(record, "message", "text") if isinstance(record.get("message"), Mapping) else record.get("message"), 1000),
        _text_of(record.get("ruleId"), 200),
        _text_of(_dig(record, "rule", "id"), 100),
        _text_of(record.get("location"), 300),
        _text_of(record.get("full_log"), 3000),
        _text_of(record.get("data"), 1000),
        _text_of(record.get("syscheck"), 600),
        _text_of(record.get("vulnerability"), 400),
        _text_of(_dig(record, "properties", "errow"), 800),
        _text_of(stream, 80),
        " ".join(sorted(groups)),
    ]
    text = " \n ".join(p for p in parts if p)[:_MAX_TEXT].lower()

    signals: list[str] = []
    level = _number(_dig(record, "rule", "level"))
    if level is None:
        level = _number(record.get("level"))
    if level is not None:
        signals.append(severity_from_level(int(level)))
    for candidate in (record.get("severity"), _dig(record, "properties", "errow", "severity"), _dig(record, "data", "vulnerability", "severity")):
        word = _word(candidate)
        if word:
            signals.append(word)
    sarif = record.get("level")
    if isinstance(sarif, str) and sarif.strip().lower() in _SARIF_LEVELS:
        signals.append(_SARIF_LEVELS[sarif.strip().lower()])
    for candidate in (_dig(record, "properties", "security-severity"), _dig(record, "properties", "errow", "cvss"), _dig(record, "errow", "cvss")):
        score = _number(candidate)
        if score is not None and 0.0 <= score <= 10.0:
            signals.append(severity_from_score(score))
    for candidate in (record.get("anomaly_score"), record.get("anomalyScore"), _dig(record, "data", "anomaly_score")):
        score = _number(candidate)
        if score is not None and score >= 0:
            signals.append(severity_from_anomaly(score))

    cwe = None
    cwe_text = _text_of(_dig(record, "properties", "errow", "cwe") or _dig(record, "errow", "cwe") or record.get("cwe"), 100)
    match = _CWE_RE.search(cwe_text)
    if match:
        cwe = int(match.group(1))

    mitre = _dig(record, "rule", "mitre") or record.get("mitre")
    tactic = technique = None
    if isinstance(mitre, Mapping):
        tactics = _strings(mitre.get("tactic"))
        techniques = _strings(mitre.get("technique"))
        ids = _strings(mitre.get("id"))
        if tactics:
            tactic = _display(tactics[0], 120) or None
        if ids and techniques:
            technique = f"{_display(ids[0], 20)} - {_display(techniques[0], 120)}"
        elif ids:
            technique = _display(ids[0], 20) or None
        elif techniques:
            technique = _display(techniques[0], 120) or None

    return Features(
        groups=groups,
        text=text,
        signals=tuple(signals),
        cwe=cwe,
        mitre_tactic=tactic,
        mitre_technique=technique,
        rule_id=_display(_dig(record, "rule", "id") or record.get("ruleId") or record.get("id"), 60),
        description=_display(_dig(record, "rule", "description") or record.get("title") or (_dig(record, "message", "text") if isinstance(record.get("message"), Mapping) else record.get("message")), 160),
        agent=_display(_dig(record, "agent", "name") or _dig(record, "errow", "target") or _dig(record, "properties", "errow", "target"), 80),
        location=_display(record.get("location") or _dig(record, "properties", "errow", "endpoint"), 100),
    )


def _matched_rules(features: Features) -> list[HeuristicRule]:
    return [r for r in RULES if (r.groups & features.groups) or (r.pattern is not None and r.pattern.search(features.text))]


def _max_severity(values: list[str]) -> str:
    return max(values, key=severity_rank)


def heuristic_severity(record: Mapping[str, Any]) -> str:
    """The floor that no model answer for this record may go below when the input carried injection markers."""
    features = extract_features(record)
    values = list(features.signals)
    matched = _matched_rules(features)
    values.extend(r.severity for r in matched)
    if features.cwe in CWE_MAP:
        values.append(CWE_MAP[features.cwe][2])
    return _max_severity(values) if values else "MEDIUM"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "unknown"


def _detection_rule(features: Features, tactic: str, technique: str, severity: str, rule: HeuristicRule | None) -> str:
    technique_id = technique.split(" - ", 1)[0].lower()
    title = features.description or (rule.ident if rule else "unclassified event")
    selector = sorted(features.groups)[0] if features.groups else (rule.ident if rule else "event")
    return "\n".join(
        [
            f"title: Cecur heuristic detection - {title}",
            "status: experimental",
            "description: Deterministic proposal generated without a model; analyst review is required before deployment.",
            "logsource:",
            "  product: any",
            "detection:",
            "  selection:",
            f"    rule.id: '{features.rule_id or 'unknown'}'",
            f"    rule.groups|contains: '{selector}'",
            "  condition: selection",
            f"level: {severity.lower()}",
            "tags:",
            f"  - attack.{_slug(tactic)}",
            f"  - attack.{technique_id}",
        ]
    )


def analyze(record: Mapping[str, Any], role: str = "triage") -> dict[str, Any]:
    features = extract_features(record)
    matched = _matched_rules(features)
    cwe_hit = CWE_MAP.get(features.cwe) if features.cwe is not None else None
    primary = matched[0] if matched else None

    severities = list(features.signals) + [r.severity for r in matched]
    if cwe_hit:
        severities.append(cwe_hit[2])
    severity = _max_severity(severities) if severities else "MEDIUM"

    if features.mitre_tactic and features.mitre_technique:
        tactic, technique = features.mitre_tactic, features.mitre_technique
    elif cwe_hit:
        tactic, technique = cwe_hit[0], cwe_hit[1]
    elif primary:
        tactic, technique = primary.tactic, primary.technique
    else:
        tactic, technique = DEFAULT_TACTIC, DEFAULT_TECHNIQUE

    classified = bool(primary or cwe_hit or (features.mitre_tactic and features.mitre_technique))
    confidence = 40 + (25 if classified else 0) + (15 if features.signals else 0) + (5 if features.mitre_tactic else 0)
    root_cause = primary.root_cause if primary else (
        "Weakness class reported by the scanner maps to the listed technique." if cwe_hit
        else "No deterministic rule matched; the event deviates from baseline and needs analyst review."
    )
    action = primary.action if primary else (
        "Confirm exploitability on the affected endpoint, apply the vendor or code fix and re-test." if cwe_hit
        else "Review the event context with the asset owner and escalate if the activity is not recognised."
    )
    subject = features.description or "Security event"
    where = " on " + features.agent if features.agent else ""
    summary = f"[{ENGINE_NAME}] {subject}{where}: mapped deterministically to {tactic} / {technique} at {severity} severity."

    analysis: dict[str, Any] = {
        "triageSummary": summary[:3900],
        "severityAssessment": severity,
        "mitreTactic": tactic,
        "mitreTechnique": technique,
        "probableRootCause": root_cause,
        "recommendedImmediateAction": action,
        "confidenceScore": min(confidence, 85),
        "engineUsed": ENGINE_NAME,
        "needsVerification": not classified,
        "gpuSeconds": 0.0,
    }
    if role in ("forensic", "deep", "security", "errow"):
        analysis["proposedDetectionRule"] = _detection_rule(features, tactic, technique, severity, primary)
        analysis["proposedRemediation"] = (
            f"{action} Approve any containment through the SOAR change process; this proposal was generated deterministically and was not executed."
        )
    return analysis


__all__ = ["ENGINE_NAME", "HEURISTIC_MODEL", "SEVERITIES", "analyze", "heuristic_severity", "severity_from_level"]
