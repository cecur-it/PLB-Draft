"""Convert Cfgaudit assessments into Vendetta findings and run NDJSON streams."""

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, engine

SCHEMA_VERSION = "1.0"
FINDINGS_FILE = "findings.ndjson"
RUNS_FILE = "runs.ndjson"
FINDINGS_STREAM = "cfgaudit.findings"
RUNS_STREAM = "cfgaudit.runs"
REDACTED = "[REDACTED]"
SECRET_LINE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(password(?![_-]encryption\b)|passwd|passphrase|secret|token|"
    r"api[_-]?key|apikey|authorization|"
    r"community|pre[-_]?shared[-_]?key|auth[-_]?key|auth[-_]?pass(?:word)?|"
    r"priv[-_]?pass(?:word)?|private[-_]?key|psk|key|credentials?)(?![A-Za-z0-9]).*$"
)
BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value):
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _timestamp(value=None):
    value = value or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def redact_evidence(value):
    value = BEARER.sub(lambda match: match.group(1) + REDACTED, value)
    return SECRET_LINE.sub(lambda match: match.group(1) + " " + REDACTED, value)


def asset_identity(vendor, hostname):
    identity = f"{vendor.lower()}\0{hostname.lower()}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _framework_references(refs):
    names = {
        "NIST 800-53 (indicative)": "NIST SP 800-53",
        "STIG": "DISA STIG",
        "CIS": "CIS",
    }
    frameworks = []
    for kind, name in names.items():
        for value in refs.get(kind, "").split(", "):
            if not value:
                continue
            match = re.match(r"^(.*) \[(direct|related)]$", value)
            reference = match.group(1) if match else value
            mapping = match.group(2) if match else "indicative"
            frameworks.append({"name": name, "reference": reference, "mapping": mapping})
    return frameworks


def _finding_record(finding, asset, config, run_id, timestamp, evidence_mode):
    evidence_hash = _sha256(finding.evidence)
    finding_key = _sha256({"asset_id": asset["id"], "control_id": finding.rule_id})
    finding_id = _sha256({
        "finding_key": finding_key,
        "evidence_sha256": evidence_hash,
        "schema_version": SCHEMA_VERSION,
    })
    evidence = {"sha256": evidence_hash, "items": []}
    if evidence_mode == "redacted":
        evidence["items"] = [redact_evidence(item) for item in finding.evidence]
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "finding",
        "@timestamp": timestamp,
        "doc_id": finding_id,
        "source": {"system": "cfgaudit", "stream": FINDINGS_STREAM},
        "run": {"id": run_id},
        "asset": asset,
        "config": config,
        "control": {
            "id": finding.rule_id,
            "title": finding.title,
            "frameworks": _framework_references(finding.refs),
        },
        "finding": {"id": finding_id, "key": finding_key},
        "status": "fail",
        "severity": finding.severity.lower(),
        "evidence": evidence,
        "remediation": finding.remediation,
    }


def audit_paths(paths, vendor=None, min_severity="Info", shadow="native",
                evidence_mode="redacted", run_id=None, started_at=None):
    """Audit local files and return (finding records, one run-summary record)."""
    started = started_at or datetime.now(timezone.utc)
    started_iso = _timestamp(started)
    run_id = run_id or str(uuid.uuid4())
    records = []
    assets = []
    warnings = []
    severity_counts = Counter()

    for raw_path in paths:
        path = Path(raw_path)
        try:
            content = path.read_bytes()
        except OSError as exc:
            warnings.append(f"skip {path}: {exc}")
            continue
        text = content.decode("utf-8", errors="replace")
        selected_vendor = vendor or engine.detect_vendor(text)
        if not selected_vendor:
            warnings.append(f"skip {path}: unknown vendor (use --vendor)")
            continue

        cfg = engine.Config(selected_vendor, str(path), text)
        findings = engine.audit(cfg, min_severity, shadow=shadow == "native")
        asset = {
            "id": asset_identity(selected_vendor, cfg.hostname),
            "name": cfg.hostname,
            "vendor": selected_vendor,
        }
        config = {"name": path.name, "sha256": hashlib.sha256(content).hexdigest()}
        asset_counts = Counter(f.severity.lower() for f in findings)
        severity_counts.update(asset_counts)
        assets.append({
            **asset,
            "config_sha256": config["sha256"],
            "status": "fail" if findings else "pass",
            "findings_total": len(findings),
            "severity": {name: asset_counts.get(name, 0) for name in ("critical", "high", "medium", "low", "info")},
        })
        records.extend(
            _finding_record(finding, asset, config, run_id, started_iso, evidence_mode)
            for finding in findings
        )

    completed_iso = _timestamp()
    status = "completed_with_warnings" if warnings else "completed"
    if not assets:
        status = "failed"
    run = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "run",
        "@timestamp": completed_iso,
        "doc_id": run_id,
        "source": {"system": "cfgaudit", "stream": RUNS_STREAM},
        "tool": {"name": "cfgaudit", "version": __version__},
        "run": {
            "id": run_id,
            "started_at": started_iso,
            "completed_at": completed_iso,
            "status": status,
            "min_severity": min_severity.lower(),
            "shadow_mode": shadow,
        },
        "status": status,
        "summary": {
            "files_total": len(paths),
            "files_audited": len(assets),
            "files_skipped": len(paths) - len(assets),
            "assets_audited": len({asset["id"] for asset in assets}),
            "findings_total": len(records),
            "severity": {name: severity_counts.get(name, 0) for name in ("critical", "high", "medium", "low", "info")},
        },
        "assets": assets,
        "warnings": warnings,
    }
    return records, run


def _append_ndjson(path, records):
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_streams(output_dir, findings, run):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    findings_path = output / FINDINGS_FILE
    runs_path = output / RUNS_FILE
    _append_ndjson(findings_path, findings)
    _append_ndjson(runs_path, [run])
    return findings_path, runs_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configs", nargs="+", help="network-device configuration files")
    parser.add_argument("-o", "--output-dir", default="cfgaudit-reports")
    parser.add_argument("--vendor", choices=["ios", "nxos", "asa", "paloalto", "fortinet"])
    parser.add_argument("--min-severity", choices=[name.lower() for name in engine.SEV], default="info")
    parser.add_argument("--shadow", choices=["native", "off"], default="native",
                        help="Batfish remains available through the separate Cfgaudit CLI")
    parser.add_argument("--evidence", choices=["redacted", "none"], default="redacted",
                        help="emit redacted evidence or hashes only (raw evidence is never emitted)")
    parser.add_argument("--fail-on", choices=[name.lower() for name in engine.SEV])
    args = parser.parse_args(argv)

    min_severity = args.min_severity.capitalize()
    findings, run = audit_paths(
        args.configs,
        vendor=args.vendor,
        min_severity=min_severity,
        shadow=args.shadow,
        evidence_mode=args.evidence,
    )
    findings_path, runs_path = write_streams(args.output_dir, findings, run)
    for warning in run["warnings"]:
        print(warning, file=sys.stderr)
    print(f"cfgaudit: {run['summary']['findings_total']} finding(s); "
          f"streams: {findings_path}, {runs_path}", file=sys.stderr)
    if not run["summary"]["files_audited"]:
        return 1
    if args.fail_on and any(engine.SEV[f["severity"].capitalize()] >= engine.SEV[args.fail_on.capitalize()]
                            for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
