# Traces: PROMPT §1 Tier 4 / §2.5 (JSON-Schema-constrained output); CONTRACT §4.2 (AIIncidentAnalysis, additionalProperties:false).
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from conftest import ROOT, good_analysis, vendetta_alert
from heuristics import analyze
from schema import SCHEMA_PATH, load_schema, schema_for_role, validate_analysis

REQUIRED = [
    "triageSummary", "severityAssessment", "mitreTactic", "mitreTechnique", "probableRootCause", "recommendedImmediateAction", "confidenceScore", "engineUsed",
]


def valid(**overrides: Any) -> dict[str, Any]:
    analysis = good_analysis(engineUsed="nemotron-3-nano:30b", gpuSeconds=1.25)
    for key in ("proposedDetectionRule", "proposedRemediation"):
        analysis.pop(key)
    analysis.update(overrides)
    return analysis


def test_schema_file_is_a_valid_draft_2020_12_document() -> None:
    assert SCHEMA_PATH == ROOT / "schemas" / "ai_incident_analysis.schema.json"
    Draft202012Validator.check_schema(load_schema())
    schema = json.loads(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert schema["required"] == REQUIRED


def test_valid_triage_and_forensic_analyses() -> None:
    assert validate_analysis(valid(), "triage") == []
    forensic = good_analysis(engineUsed="gemma4:26b")
    assert validate_analysis(forensic, "forensic") == []
    assert validate_analysis(forensic, "triage") == []


@pytest.mark.parametrize("key", REQUIRED)
def test_each_required_key_is_enforced(key: str) -> None:
    analysis = valid()
    del analysis[key]
    violations = validate_analysis(analysis)
    assert violations and any(key in v for v in violations)


@pytest.mark.parametrize("key", ["proposedDetectionRule", "proposedRemediation"])
def test_forensic_role_requires_proposals(key: str) -> None:
    analysis = good_analysis(engineUsed="gemma4:26b")
    del analysis[key]
    assert validate_analysis(analysis, "triage") == []
    assert any(key in v for v in validate_analysis(analysis, "forensic"))
    assert key not in load_schema()["required"]


def test_additional_properties_are_rejected_at_every_level() -> None:
    assert validate_analysis(valid(extra="x"))
    assert validate_analysis(valid(toolCalls=[{"tool": "nmap", "args": {}, "shell": "id"}]))


@pytest.mark.parametrize("value", ["SEVERE", "high", "Info", "", None, 3])
def test_severity_enum(value: Any) -> None:
    assert validate_analysis(valid(severityAssessment=value))


@pytest.mark.parametrize("value", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_severity_enum_accepts_all_levels(value: str) -> None:
    assert validate_analysis(valid(severityAssessment=value)) == []


@pytest.mark.parametrize("value", [-0.1, 100.5, 101, "80", None, True])
def test_confidence_range_and_type(value: Any) -> None:
    assert validate_analysis(valid(confidenceScore=value))


@pytest.mark.parametrize("value", [0, 0.0, 55.5, 100])
def test_confidence_bounds_are_inclusive(value: float) -> None:
    assert validate_analysis(valid(confidenceScore=value)) == []


def test_string_lengths_and_types() -> None:
    assert validate_analysis(valid(triageSummary=""))
    assert validate_analysis(valid(triageSummary="x" * 4001))
    assert validate_analysis(valid(mitreTactic=7))
    assert validate_analysis(valid(needsVerification="yes"))
    assert validate_analysis(valid(gpuSeconds=-1))


def test_tool_calls_shape_and_bounds() -> None:
    call = {"tool": "nmap", "args": {"target": "scan-target.vendetta.lab"}, "rationale": "verify"}
    assert validate_analysis(valid(toolCalls=[call] * 5)) == []
    assert validate_analysis(valid(toolCalls=[call] * 6))
    assert validate_analysis(valid(toolCalls=[{"tool": "nmap"}]))
    assert validate_analysis(valid(toolCalls=[{"tool": "bad name!", "args": {}}]))
    assert validate_analysis(valid(toolCalls="nmap"))


@pytest.mark.parametrize("payload", [[], "text", 5, None])
def test_non_object_payloads_are_rejected(payload: Any) -> None:
    assert validate_analysis(payload) == ["schema:/ expected a JSON object"]


def test_schema_for_role_does_not_mutate_the_base_schema() -> None:
    before = copy.deepcopy(load_schema())
    schema_for_role("forensic")
    assert load_schema() == before


@pytest.mark.parametrize("role", ["triage", "forensic"])
@pytest.mark.parametrize(
    "record",
    [vendetta_alert(), {}, {"level": "error", "message": {"text": "x"}}, {"rule": {"level": 15, "groups": ["ransomware"]}}, {"anomaly_score": 0.93, "title": "odd"}],
)
def test_heuristic_analyses_always_satisfy_the_schema(record: dict[str, Any], role: str) -> None:
    assert validate_analysis(analyze(record, role), role) == []
