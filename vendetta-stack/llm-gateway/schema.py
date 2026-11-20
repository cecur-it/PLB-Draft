# Traces: PROMPT §1 Tier 4 / §2.5 (JSON-Schema-constrained output); CONTRACT §4.2 (AIIncidentAnalysis); CS3 server/ai/cecurAI.ts.
"""AIIncidentAnalysis schema loading and validation (role-aware)."""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from guardrails import validate_output_schema

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "ai_incident_analysis.schema.json"
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
FORENSIC_REQUIRED = ("proposedDetectionRule", "proposedRemediation")
# Deep, security and Errow task classes reuse the richer forensic shape; only triage stays lean.
DEEP_ROLES = frozenset({"forensic", "deep", "security", "errow"})


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=8)
def schema_for_role(role: str) -> dict[str, Any]:
    schema = copy.deepcopy(load_schema())
    if role in DEEP_ROLES:
        schema["required"] = [*schema["required"], *FORENSIC_REQUIRED]
    return schema


def validate_analysis(analysis: Any, role: str = "triage") -> list[str]:
    """Returns an empty list when valid, else `schema:<path> <message>` strings."""
    if not isinstance(analysis, dict):
        return ["schema:/ expected a JSON object"]
    return validate_output_schema(analysis, schema_for_role(role if role in DEEP_ROLES else "triage"))


def severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return -1
