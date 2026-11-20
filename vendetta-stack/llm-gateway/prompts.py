# Traces: PROMPT §1 Tier 4 / §2.5 (untrusted-data framing, JSON-only output); CONTRACT §4.2 (AIIncidentAnalysis keys), §4.4 (hard-coded
#         sampling parameters; system prompt ends "Ensure output is strictly valid JSON."); CS3 server/ai/cecurAI.ts (prompt structure).
"""System/user prompts. Sampling parameters are constants: they are not tenant-tunable (CONTRACT §4.4)."""
from __future__ import annotations

from typing import Any

from guardrails import FRAME_SYSTEM, frame_untrusted

TEMPERATURE = 0.2
TOP_P = 0.9
TOP_K = 40
RESPONSE_FORMAT = {"type": "json_object"}
JSON_SUFFIX = "Ensure output is strictly valid JSON."

_TRIAGE_KEYS = (
    "triageSummary (string, <= 4000 chars), severityAssessment (one of CRITICAL, HIGH, MEDIUM, LOW), mitreTactic (string), "
    "mitreTechnique (string, e.g. \"T1110 - Brute Force\"), probableRootCause (string), recommendedImmediateAction (string), "
    "confidenceScore (number 0-100), needsVerification (boolean, optional), "
    "toolCalls (optional array of at most 5 objects {tool, args, rationale}; proposals for a human-approved, policy-gated runner)"
)
_FORENSIC_KEYS = (
    ", proposedDetectionRule (string: a Sigma-style rule that would catch this activity), "
    "proposedRemediation (string: concrete, reversible remediation steps)"
)


ROLE_INSTRUCTIONS = {
    "triage": "Triage the security event quickly and conservatively.",
    "forensic": "Perform a deeper forensic analysis of the security event.",
    "deep": "Reason deeply across all supplied evidence (including image/OCR text) before concluding.",
    "security": "Act as a vulnerability analyst: reason about exploitability, preconditions and blast radius, then give the secure review.",
    "errow": "Act as the Errow scan agent: reason about what the finding means for this host and give a reversible remediation the operator can approve.",
}
DEEP_ROLES = frozenset({"forensic", "deep", "security", "errow"})


def system_prompt(role: str, tools: tuple[str, ...] = ()) -> str:
    forensic = role in DEEP_ROLES
    lines = [
        "You are the Cecur Vendetta SOC analyst assistant running on a sovereign, on-premises model. "
        + ROLE_INSTRUCTIONS.get(role, ROLE_INSTRUCTIONS["triage"]),
        FRAME_SYSTEM,
        "Respond with ONE JSON object and nothing else (no prose, no markdown fences). Required keys: " + _TRIAGE_KEYS + (_FORENSIC_KEYS if forensic else "") + ".",
        "Do not include engineUsed or gpuSeconds; the gateway adds them. Do not invent indicators that are absent from the data. "
        "If the evidence is thin, say so in triageSummary, lower confidenceScore and set needsVerification to true.",
    ]
    if tools:
        lines.append("toolCalls may only name these tools: " + ", ".join(tools) + ". They are proposals; they are never executed automatically.")
    lines.append(JSON_SUFFIX)
    return "\n".join(lines)


def build_messages(role: str, prompt_text: str, tools: tuple[str, ...] = ()) -> list[dict[str, str]]:
    framed = frame_untrusted(prompt_text)
    return [{"role": "system", "content": system_prompt(role, tools)}, {"role": "user", "content": framed.user}]


def sampling_params() -> dict[str, Any]:
    return {
        "temperature": TEMPERATURE,
        "top_p": TOP_P,
        "top_k": TOP_K,
        "options": {"temperature": TEMPERATURE, "top_p": TOP_P, "top_k": TOP_K},
        "response_format": dict(RESPONSE_FORMAT),
        "stream": False,
    }
