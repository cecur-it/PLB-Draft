# Traces: SECURITY §3 (Nemotron primary for vulnerability analysis and Errow; Qwensploit eval-only), §4 (declared fallbacks, degraded flag, fail-closed),
#         §6 (human-approval token for mutating tool calls), §7 (per-class token budgets), §8 (cache only high-volume classification).
from __future__ import annotations

from typing import Any

import pytest

from conftest import DEEP_MODEL, FORENSIC_MODEL, SECURITY_MODEL, TRIAGE_MODEL, Gateway, metric_value, vendetta_alert
from config import Config, ConfigError

ERROW_ALIAS = "cs3-errow-security"
SECURITY_ALIAS = "cs3-security"
APPROVAL = {"X-CS3-Approval": "ticket-CHG-1234"}


def chat_body(model: str, tools: bool = False) -> dict[str, Any]:
    body: dict[str, Any] = {"model": model, "messages": [{"role": "user", "content": "Is CVE-2024-3094 exploitable on this host?"}]}
    if tools:
        body["tools"] = [{"type": "function", "function": {"name": "isolate_host"}}]
    return body


async def security(gw: Gateway, role: str = "security") -> dict[str, Any]:
    response = await gw.post(f"/security?role={role}", vendetta_alert())
    assert response.status == 200, response.text
    return response.json()["results"][0]


async def test_security_route_pins_the_agentic_tier_with_its_own_budget_and_no_thinking(gateway: Gateway) -> None:
    result = await security(gateway)
    meta = result["meta"]
    assert (meta["model"], meta["role"], meta["task_class"], meta["fallback"]) == (SECURITY_MODEL, "security", "security", False)
    assert meta["degraded_model_fallback"] is False and meta["cache_hit"] is False
    payload = gateway.ollama.calls[0]
    assert payload["model"] == SECURITY_MODEL and payload["max_tokens"] == 2048 and payload["think"] is False
    assert payload["reasoning_effort"] == "none", "/v1 ignores think; the trace must be disabled explicitly"


async def test_deep_role_asks_for_a_thinking_trace(gateway: Gateway) -> None:
    await security(gateway, "deep")
    assert gateway.ollama.calls[0]["think"] is True
    assert "reasoning_effort" not in gateway.ollama.calls[0]


async def test_triage_is_the_only_class_that_refuses_thinking_and_is_budget_capped(gateway: Gateway) -> None:
    await gateway.post("/triage", vendetta_alert())
    payload = gateway.ollama.calls[0]
    assert payload["think"] is False and payload["max_tokens"] == 1024 and payload["reasoning_effort"] == "none"


async def test_errow_alias_answers_with_openai_shape_and_headers(gateway: Gateway) -> None:
    response = await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS))
    assert response.status == 200, response.text
    body = response.json()
    assert body["object"] == "chat.completion" and body["choices"][0]["message"]["role"] == "assistant"
    assert body["model"] == SECURITY_MODEL and body["cs3"]["task_class"] == "errow"
    assert body["cs3"]["primary_model"] == SECURITY_MODEL and body["cs3"]["needs_analyst_review"] is False
    assert response.headers["X-CS3-Degraded-Model-Fallback"] == "false"
    assert body["usage"]["total_tokens"] == 168


async def test_security_alias_is_accepted_and_the_errow_class_never_invents_json_fields(gateway: Gateway) -> None:
    response = await gateway.post("/v1/chat/completions", chat_body(SECURITY_ALIAS))
    assert response.status == 200 and response.json()["cs3"]["task_class"] == "security"
    system = gateway.ollama.calls[0]["messages"][0]["content"]
    assert "vulnerability analyst" in system and system.endswith("Ensure output is strictly valid JSON.")


async def test_errow_falls_to_gemma4_and_flags_the_degraded_run(gateway: Gateway) -> None:
    gateway.ollama.modes[SECURITY_MODEL] = "down"
    response = await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS))
    assert response.status == 200, response.text
    body = response.json()
    assert body["model"] == DEEP_MODEL and body["cs3"]["degraded_model_fallback"] is True
    assert body["cs3"]["attempted_fallbacks"] == [DEEP_MODEL] and body["cs3"]["needs_analyst_review"] is True
    assert response.headers["X-CS3-Degraded-Model-Fallback"] == "true"


async def test_every_spec_route_name_selects_its_documented_model(gateway: Gateway) -> None:
    """Spec §4.3 route names, each on the model the matrix pins for it (acceptance tests 3, 4, 11)."""
    expected = {"cs3-triage": TRIAGE_MODEL, "cs3-reasoning": FORENSIC_MODEL, "cs3-reasoning-deep": DEEP_MODEL,
                "cs3-security": SECURITY_MODEL, "cs3-errow-security": SECURITY_MODEL}
    for alias, model in expected.items():
        response = await gateway.post("/v1/chat/completions", chat_body(alias))
        assert response.status == 200, (alias, response.text)
        assert response.headers["X-CS3-Model"] == model, alias
        assert response.json()["cs3"]["primary_model"] == model, alias
    # cs3-security must stop at the deep model instead of degrading to triage
    gateway.ollama.modes[SECURITY_MODEL] = "down"
    security = await gateway.post("/v1/chat/completions", chat_body("cs3-security"))
    assert security.status == 200 and security.headers["X-CS3-Model"] == DEEP_MODEL
    assert security.json()["cs3"]["attempted_fallbacks"] == [DEEP_MODEL]


async def test_errow_never_falls_back_to_the_compliance_model(gateway: Gateway) -> None:
    gateway.ollama.modes.update({SECURITY_MODEL: "down", DEEP_MODEL: "down", TRIAGE_MODEL: "down"})
    chain = gateway.cfg.chain_for("errow")
    assert FORENSIC_MODEL not in chain
    assert chain == (SECURITY_MODEL, DEEP_MODEL)
    assert (await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS))).status == 502


async def test_exhausted_chain_fails_closed_with_a_typed_error(gateway: Gateway) -> None:
    gateway.ollama.modes.update({SECURITY_MODEL: "down", DEEP_MODEL: "down", TRIAGE_MODEL: "down"})
    response = await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS))
    assert response.status == 502 and response.json()["error"]["code"] == "chain_exhausted"
    metrics = await gateway.metrics()
    assert metric_value(metrics, "llm_gateway_requests_total", role="errow", engine="none", fallback="true") == 1


async def test_mutating_tool_call_requires_a_human_approval_token(gateway: Gateway) -> None:
    gateway.ollama.overrides[SECURITY_MODEL] = {
        "toolCalls": [{"tool": "isolate_host", "args": {"host": "scan-target.vendetta.lab"}, "rationale": "stop lateral movement"}],
    }
    blocked = await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS))
    assert blocked.status == 403 and blocked.json()["error"]["code"] == "approval_required"
    assert "isolate_host" in blocked.json()["error"]["message"] and blocked.headers["X-CS3-Model"] == SECURITY_MODEL
    approved = await gateway.post("/v1/chat/completions", chat_body(ERROW_ALIAS), headers=APPROVAL)
    assert approved.status == 200 and approved.json()["approval_required"] is True


async def test_body_level_approval_token_and_read_only_tools_are_accepted(gateway: Gateway) -> None:
    body = {**chat_body(ERROW_ALIAS), "approval_token": "CHG-42"}
    body["tools"] = [{"type": "function", "function": {"name": "nmap"}}]
    assert (await gateway.post("/v1/chat/completions", body)).status == 200


async def test_security_findings_are_never_cached_but_triage_is(make_gateway: Any) -> None:
    gw = await make_gateway({"GATEWAY_CACHE_TRIAGE": "true"})
    await gw.post("/triage", vendetta_alert())
    await gw.post("/triage", vendetta_alert())
    assert len(gw.ollama.calls) == 1
    second = await gw.post("/triage", vendetta_alert())
    meta = second.json()["results"][0]["meta"]
    assert meta["cache_hit"] is True
    # The triage and security tags are the same model, so a replay must not report the security role.
    assert meta["role"] == "triage"
    await gw.post("/security", vendetta_alert())
    await gw.post("/security", vendetta_alert())
    assert len(gw.ollama.calls) == 3


async def test_security_roles_are_allowlisted_in_the_openai_model_list(gateway: Gateway) -> None:
    ids = {entry["id"] for entry in (await gateway.get("/v1/models")).json()["data"]}
    assert {ERROW_ALIAS, SECURITY_ALIAS, SECURITY_MODEL} <= ids


def test_guard_model_must_differ_from_security_models() -> None:
    base = {"CS3_PROFILE": "onprem"}
    with pytest.raises(ConfigError, match="must differ from the security models"):
        Config.from_env({**base, "INFERENCE_MODEL_GUARD": SECURITY_MODEL})
    assert Config.from_env({**base, "INFERENCE_MODEL_GUARD": FORENSIC_MODEL}).model_guard == FORENSIC_MODEL


def test_security_budget_and_thinking_are_environment_overrides() -> None:
    cfg = Config.from_env({"CS3_PROFILE": "onprem", "INFERENCE_MAX_TOKENS_SECURITY": "4096", "INFERENCE_THINKING_SECURITY": "true"})
    assert cfg.max_tokens_for("security") == 4096
    assert cfg.chain_for("security") == (SECURITY_MODEL, "gemma4:31b")  # never degrades to triage
    # Security classes reserve their budget for tool answers; the deep fallback may still emit a reasoning trace.
    assert cfg.thinking_for("security", SECURITY_MODEL) is False
    assert cfg.thinking_for("security", "gemma4:31b") is True


def test_legacy_ollama_var_still_pins_the_security_tier() -> None:
    cfg = Config.from_env({"CS3_PROFILE": "onprem", "OLLAMA_SECURITY_MODEL": "qwensploit-v2:9b-q5"})
    assert cfg.model_security == "qwensploit-v2:9b-q5" and cfg.model_errow_security == "qwensploit-v2:9b-q5"


async def test_passthrough_pins_no_trace_for_security_classes_and_honours_an_explicit_one(gateway: Gateway) -> None:
    assert (await gateway.post("/v1/chat/completions", {"model": SECURITY_MODEL, "messages": [{"role": "user", "content": "hi"}]})).status == 200
    payload = gateway.ollama.calls[-1]
    assert (payload["model"], payload["think"], payload["reasoning_effort"]) == (SECURITY_MODEL, False, "none")
    explicit = {"model": SECURITY_MODEL, "messages": [{"role": "user", "content": "hi"}], "think": True}
    assert (await gateway.post("/v1/chat/completions", explicit)).status == 200
    assert gateway.ollama.calls[-1]["think"] is True and "reasoning_effort" not in gateway.ollama.calls[-1]


async def test_passthrough_rejects_unknown_reasoning_efforts_and_non_boolean_think(gateway: Gateway) -> None:
    base = {"model": SECURITY_MODEL, "messages": [{"role": "user", "content": "hi"}]}
    for bad in ({"reasoning_effort": "maximum"}, {"think": "yes"}):
        response = await gateway.post("/v1/chat/completions", {**base, **bad})
        assert (response.status, response.json()["error"]["code"]) == (400, "invalid_parameter")


def test_env_contract_names_win_and_errow_route_alias_resolves_to_the_security_tag() -> None:
    cfg = Config.from_env({"CS3_PROFILE": "cloud", "CS3_MODEL_SECURITY": "qwensploit-v2:9b", "CS3_MODEL_ERROW_SECURITY": "cs3-errow-security",
                           "INFERENCE_MODEL_SECURITY": "old:1b", "OLLAMA_SECURITY_MODEL": "older:1b"})
    assert (cfg.model_security, cfg.model_errow_security) == ("qwensploit-v2:9b", "qwensploit-v2:9b")


def test_deprecated_ollama_aliases_still_configure_the_tiers() -> None:
    cfg = Config.from_env({"CS3_PROFILE": "cloud", "OLLAMA_PRIMARY_MODEL": "legacy:1b", "OLLAMA_SECURITY_MODEL": "legacy:2b"})
    assert (cfg.model_triage, cfg.model_security) == ("legacy:1b", "legacy:2b")


async def test_errow_conversation_and_tool_schemas_are_forwarded_for_native_tool_calls(gateway: Gateway) -> None:
    """An agent owns its own tool loop: messages/tools go upstream untouched and native tool_calls come back (not forced JSON)."""
    tool = {"type": "function", "function": {"name": "run_command", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}}}
    history = [
        {"role": "system", "content": "You are Errow, a penetration testing agent."},
        {"role": "user", "content": "Enumerate the target."},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "call_0", "type": "function", "function": {"name": "run_command", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "call_0", "content": "200 OK"},
    ]
    gateway.ollama.modes[SECURITY_MODEL] = "tool_calls"
    response = await gateway.post("/v1/chat/completions", {"model": ERROW_ALIAS, "messages": history, "tools": [tool]})
    payload = gateway.ollama.calls_for(SECURITY_MODEL)[0]
    assert payload["messages"][0]["content"].startswith("Gateway note") and payload["messages"][1:] == history
    assert payload["tools"] == [tool] and payload["tool_choice"] == "auto"
    assert "response_format" not in payload
    assert response.status == 403  # isolate_host is mutating, so the guard still fires on native calls
    assert response.json()["error"]["code"] == "approval_required" and "isolate_host" in response.json()["error"]["message"]

    response = await gateway.post("/v1/chat/completions", {"model": ERROW_ALIAS, "messages": history, "tools": [tool]}, headers=APPROVAL)
    assert response.status == 200
    choice = response.json()["choices"][0]
    assert choice["finish_reason"] == "tool_calls" and choice["message"]["tool_calls"][0]["function"]["name"] == "isolate_host"
