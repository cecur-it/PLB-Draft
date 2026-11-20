import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from cfgaudit import adapter

SAMPLE = Path(__file__).parent.parent / "samples" / "edge-rtr1.cfg"
SCHEMAS = Path(__file__).parent.parent / "cfgaudit" / "schemas"
STARTED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def audit(path=SAMPLE, **kwargs):
    options = {"run_id": "test-run", "started_at": STARTED, **kwargs}
    return adapter.audit_paths([path], **options)


def validate(record, schema_name):
    schema = json.loads((SCHEMAS / schema_name).read_text())
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    ).validate(record)


def test_records_match_dedicated_schemas():
    findings, run = audit()
    assert findings
    for finding in findings:
        validate(finding, "finding.schema.json")
        assert finding["doc_id"] == finding["finding"]["id"]
        assert finding["source"]["stream"] == "cfgaudit.findings"
        assert finding["asset"]["name"] == "edge-rtr1"
        assert finding["config"]["sha256"]
        assert finding["evidence"]["sha256"]
        assert finding["control"]["frameworks"]
    validate(run, "run.schema.json")
    assert run["summary"]["findings_total"] == len(findings)
    assert run["source"]["stream"] == "cfgaudit.runs"


def test_finding_ids_are_deterministic_across_runs():
    first, first_run = audit(run_id="run-one")
    second, second_run = audit(run_id="run-two", started_at=datetime.now(timezone.utc))
    assert [item["finding"]["id"] for item in first] == [item["finding"]["id"] for item in second]
    assert [item["finding"]["key"] for item in first] == [item["finding"]["key"] for item in second]
    assert first_run["doc_id"] != second_run["doc_id"]
    assert first[0]["@timestamp"] != second[0]["@timestamp"]


def test_evidence_is_redacted_and_raw_config_is_not_emitted(tmp_path):
    config = tmp_path / "device.cfg"
    config.write_text(
        "hostname device\n"
        "snmp-server community supersecret RW\n"
        "enable password 0 plaintext\n"
        "line vty 0 4\n"
        " transport input telnet\n"
    )
    findings, run = audit(config)
    serialized = json.dumps({"findings": findings, "run": run})
    assert "supersecret" not in serialized
    assert "plaintext" not in serialized
    snmp = next(item for item in findings if item["control"]["id"] == "IOS-005")
    assert snmp["evidence"]["items"] == ["snmp-server community [REDACTED]"]
    assert adapter.redact_evidence("service password-encryption <not configured>") == \
        "service password-encryption <not configured>"


def test_redaction_covers_compound_secret_names():
    lines = [
        "set deviceconfig system snmp-setting snmp-system snmp-community-string HyphenSecret",
        "snmp_community_string UnderscoreSecret",
        "tacacs-server key GenericKeySecret",
        "snmp-server user monitor authpass AuthSecret",
    ]
    redacted = "\n".join(adapter.redact_evidence(line) for line in lines)
    for secret in ("HyphenSecret", "UnderscoreSecret", "GenericKeySecret", "AuthSecret"):
        assert secret not in redacted
    assert redacted.count("[REDACTED]") == len(lines)


def test_hashes_only_mode_preserves_evidence_identity():
    redacted, _ = audit()
    hashes_only, _ = audit(evidence_mode="none")
    assert all(item["evidence"]["items"] for item in redacted)
    assert all(item["evidence"]["items"] == [] for item in hashes_only)
    assert [item["evidence"]["sha256"] for item in redacted] == \
        [item["evidence"]["sha256"] for item in hashes_only]
    assert [item["finding"]["id"] for item in redacted] == \
        [item["finding"]["id"] for item in hashes_only]


def test_warnings_and_failed_run_status(tmp_path):
    unknown = tmp_path / "unknown.cfg"
    unknown.write_text("not a supported configuration\n")
    findings, run = audit(unknown)
    assert findings == []
    assert run["status"] == "failed"
    assert run["summary"]["files_skipped"] == 1
    assert run["warnings"]

    findings, run = adapter.audit_paths(
        [SAMPLE, unknown], run_id="partial", started_at=STARTED
    )
    assert findings
    assert run["status"] == "completed_with_warnings"
    assert run["summary"]["files_audited"] == 1
    assert run["summary"]["files_skipped"] == 1


def test_stream_writer_appends_replayable_ndjson(tmp_path):
    findings, run = audit()
    findings_path, runs_path = adapter.write_streams(tmp_path, findings, run)
    adapter.write_streams(tmp_path, findings, run)
    finding_lines = findings_path.read_text().splitlines()
    run_lines = runs_path.read_text().splitlines()
    assert len(finding_lines) == 2 * len(findings)
    assert len(run_lines) == 2
    replayed = [json.loads(line)["doc_id"] for line in finding_lines]
    assert replayed[:len(findings)] == replayed[len(findings):]
    assert json.loads(run_lines[0])["doc_id"] == "test-run"
