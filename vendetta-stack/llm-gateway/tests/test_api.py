# Traces: PROMPT §1 Tier 4 / §2.3 / §2.5; CONTRACT §4.2 (analysis schema), §4.3 (cs3.ai.* events), §4.4 (gateway API, metrics, auth, mTLS, telemetry-loop guard).
from __future__ import annotations

import asyncio
import json
from typing import Any

import aiohttp
import pytest

from conftest import FORENSIC_MODEL, TRIAGE_MODEL, Gateway, metric_value, vendetta_alert

REQUIRED_METRICS = [
    "llm_gateway_requests_total",
    "llm_gateway_triage_latency_seconds",
    "llm_gateway_failover_total",
    "llm_gateway_queue_depth",
    "llm_gateway_output_schema_violations_total",
    "llm_gateway_prompt_injection_blocked_total",
    "llm_gateway_gpu_seconds_total",
    "llm_gateway_tokens_total",
    "llm_gateway_mcp_tool_calls_total",
    "llm_gateway_audit_chain_ok",
    "llm_gateway_spool_depth",
    "ollama_gpu_memory_util",
]


async def test_bearer_token_is_required_on_every_protected_route(gateway: Gateway) -> None:
    for method, path in (("POST", "/triage"), ("POST", "/forensic"), ("POST", "/mcp/tool_call"), ("POST", "/v1/chat/completions"), ("GET", "/v1/models")):
        missing = await gateway.request(method, path, body={} if method == "POST" else None, auth=False)
        assert missing.status == 401, path
        assert missing.json()["error"] in ("unauthorized", {"message": "a valid bearer token is required", "type": "invalid_request_error", "code": "unauthorized", "param": None})
        assert "Bearer" in missing.headers["WWW-Authenticate"]
    wrong = await gateway.request("POST", "/triage", body=vendetta_alert(), headers={"Authorization": "Bearer " + "x" * 43})
    assert wrong.status == 401
    scheme = await gateway.request("POST", "/triage", body=vendetta_alert(), headers={"Authorization": "Basic " + gateway.token})
    assert scheme.status == 401
    assert gateway.ollama.calls == []


async def test_token_comparison_does_not_accept_prefixes_or_extensions(gateway: Gateway) -> None:
    for candidate in (gateway.token[:-1], gateway.token + "x", gateway.token.upper(), ""):
        response = await gateway.request("POST", "/triage", body=vendetta_alert(), headers={"Authorization": f"Bearer {candidate}"}, auth=False)
        assert response.status == 401


async def test_health_and_metrics_are_unauthenticated(gateway: Gateway) -> None:
    assert (await gateway.get("/health", auth=False)).status == 200
    assert (await gateway.get("/metrics", auth=False)).status == 200


async def test_health_shape(gateway: Gateway) -> None:
    body = (await gateway.get("/health", auth=False)).json()
    assert body["status"] == "ok" and body["version"] == "1.0.0"
    assert body["backend"]["reachable"] is True and body["backend"]["maintenance"] is False
    assert body["backend"]["models"] == {"triage": TRIAGE_MODEL, "forensic": FORENSIC_MODEL, "deep": "gemma4:31b",
                                         "security": TRIAGE_MODEL, "errow": TRIAGE_MODEL}
    assert body["backend"]["chains"]["security"] == [TRIAGE_MODEL, "gemma4:31b"]
    assert body["backend"]["chains"]["errow"] == [TRIAGE_MODEL, "gemma4:31b"]
    assert body["backend"]["available"] == {"triage": True, "forensic": True, "deep": True, "security": True, "errow": True}
    assert body["fluent_bit"]["reachable"] is True and body["fluent_bit"]["spool_depth"] == 0
    assert body["audit"]["chain_ok"] is True and body["audit"]["chain_id"]
    assert body["mcp"]["live"] is False and {"nmap", "nuclei", "gobuster", "trufflehog"} <= set(body["mcp"]["tools"])


async def test_health_stays_200_and_reports_degraded_when_ollama_is_down(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"OLLAMA_BASE_URL": "http://127.0.0.1:9/v1"})
    response = await gateway.get("/health", auth=False)
    assert response.status == 200
    body = response.json()
    assert body["status"] == "degraded" and body["backend"]["reachable"] is False
    triage = await gateway.post("/triage", vendetta_alert())
    assert triage.status == 200
    result = triage.json()["results"][0]
    assert result["analysis"]["engineUsed"] == "Cecur Heuristics" and result["meta"]["fallback"] is True and result["meta"]["role"] == "heuristic"
    assert result["meta"]["fallback_reason"] == "backend_unavailable"


async def test_metrics_expose_every_contract_series_name(gateway: Gateway) -> None:
    await gateway.post("/triage", vendetta_alert())
    await gateway.tool_call("triage", "nmap", {"target": "scan-target.vendetta.lab", "scan_type": "-sT"})
    text = await gateway.metrics()
    for name in REQUIRED_METRICS:
        assert f"# TYPE {name} " in text, name
    assert metric_value(text, "llm_gateway_requests_total", role="triage", engine=TRIAGE_MODEL, fallback="false") == 1
    assert metric_value(text, "llm_gateway_mcp_tool_calls_total", tool="nmap", decision="dry_run") == 1
    assert metric_value(text, "llm_gateway_audit_chain_ok") == 1
    assert (metric_value(text, "llm_gateway_gpu_seconds_total", role="triage", model=TRIAGE_MODEL) or 0) > 0
    assert metric_value(text, "llm_gateway_tokens_total", direction="in", role="triage", model=TRIAGE_MODEL) == 123
    assert metric_value(text, "llm_gateway_tokens_total", direction="out", role="triage", model=TRIAGE_MODEL) == 45
    assert metric_value(text, "ollama_gpu_memory_util") == 0


async def test_gpu_memory_util_is_read_from_the_configured_file(make_gateway: Any, tmp_path: Any) -> None:
    util = tmp_path / "gpu_util"
    util.write_text("0.62\n", encoding="ascii")
    gateway: Gateway = await make_gateway({"OLLAMA_GPU_UTIL_FILE": str(util)})
    assert metric_value(await gateway.metrics(), "ollama_gpu_memory_util") == pytest.approx(0.62)
    broken: Gateway = await make_gateway({"OLLAMA_GPU_UTIL_FILE": str(tmp_path / "missing")})
    assert metric_value(await broken.metrics(), "ollama_gpu_memory_util") == 0


async def test_triage_single_record_contract_shape(gateway: Gateway) -> None:
    response = await gateway.post("/triage", vendetta_alert(), headers={"X-Request-Id": "req-abc-1", "X-Tenant-Id": "tenant-a"})
    assert response.status == 200 and response.headers["X-Request-Id"] == "req-abc-1"
    (result,) = response.json()["results"]
    assert result["alert_id"] == "1699999999.12345" and result["request_id"] == "req-abc-1"
    analysis, meta = result["analysis"], result["meta"]
    assert analysis["engineUsed"] == TRIAGE_MODEL and analysis["severityAssessment"] == "HIGH" and analysis["gpuSeconds"] > 0
    assert meta["model"] == TRIAGE_MODEL and meta["role"] == "triage" and meta["fallback"] is False and meta["fallback_reason"] is None
    assert meta["guardrail"] == {"passed": True, "violations": []} and meta["tokens_in"] == 123 and meta["tokens_out"] == 45

    (call,) = gateway.ollama.calls
    assert call["model"] == TRIAGE_MODEL and call["temperature"] == 0.2 and call["top_p"] == 0.9
    assert call["response_format"] == {"type": "json_object"}
    assert call.get("top_k") == 40 or call.get("options", {}).get("top_k") == 40
    system, user = call["messages"]
    assert system["role"] == "system" and system["content"].rstrip().endswith("Ensure output is strictly valid JSON.")
    assert user["role"] == "user" and "<untrusted_data>" in user["content"] and "</untrusted_data>" in user["content"]


async def test_triage_events_are_emitted_and_carry_no_raw_telemetry(gateway: Gateway) -> None:
    await gateway.post("/triage", vendetta_alert(), headers={"X-Tenant-Id": "tenant-a"})
    (inference,) = await gateway.events("cs3.ai.inference")
    (enrichment,) = await gateway.events("cs3.ai.enrichment")
    assert inference["tenant_id"] == "tenant-a" and inference["alert_id"] == "1699999999.12345" and inference["role"] == "triage"
    assert inference["prev_hash"] == "0" * 64 and len(inference["hash"]) == 64 and inference["chain_id"] == (await gateway.get("/health", auth=False)).json()["audit"]["chain_id"]
    assert enrichment["id"] == "1699999999.12345" and enrichment["ai"]["engine"] == TRIAGE_MODEL and enrichment["severity"] == "high"
    serialised = json.dumps([inference, enrichment])
    assert "Failed password" not in serialised and "198.51.100.23" not in serialised


async def test_forensic_endpoint_and_role_parameter_use_the_forensic_model(gateway: Gateway) -> None:
    for path in ("/forensic", "/triage?role=forensic"):
        gateway.ollama.calls.clear()
        response = await gateway.post(path, vendetta_alert())
        assert response.status == 200, path
        (result,) = response.json()["results"]
        assert result["meta"]["role"] == "forensic" and result["analysis"]["engineUsed"] == FORENSIC_MODEL, path
        assert result["analysis"]["proposedDetectionRule"] and result["analysis"]["proposedRemediation"]
        assert gateway.ollama.calls[0]["model"] == FORENSIC_MODEL


async def test_unknown_role_is_rejected(gateway: Gateway) -> None:
    response = await gateway.post("/triage?role=admin", vendetta_alert())
    assert response.status == 400 and response.json()["error"] == "invalid_role"
    assert gateway.ollama.calls == []


async def test_array_and_ndjson_bodies_are_both_accepted(gateway: Gateway) -> None:
    records = [vendetta_alert(id=f"alert-{i}") for i in range(3)]
    array = await gateway.post("/triage", records)
    assert array.status == 200 and [r["alert_id"] for r in array.json()["results"]] == ["alert-0", "alert-1", "alert-2"]
    ndjson = await gateway.request("POST", "/triage", data="\n".join(json.dumps(r) for r in records).encode(), headers={"Content-Type": "application/x-ndjson"})
    assert ndjson.status == 200 and [r["alert_id"] for r in ndjson.json()["results"]] == ["alert-0", "alert-1", "alert-2"]
    assert len({r["request_id"] for r in ndjson.json()["results"]}) == 3


async def test_alert_id_derivation(gateway: Gateway) -> None:
    errow_finding = {"doc_id": "finding-77", "severity": "high", "title": "Exposed admin panel", "target": "scan-target.vendetta.lab"}
    anonymous = {"title": "Something odd", "detail": "no id at all"}
    response = await gateway.post("/triage", [errow_finding, anonymous, dict(anonymous)])
    ids = [r["alert_id"] for r in response.json()["results"]]
    assert ids[0] == "finding-77"
    assert len(ids[1]) == 64 and ids[1] == ids[2] and all(c in "0123456789abcdef" for c in ids[1])


async def test_elasticsearch_hit_wrappers_are_unwrapped(gateway: Gateway) -> None:
    response = await gateway.post("/triage", {"_id": "es-1", "_source": vendetta_alert(id="inner-id")})
    assert response.status == 200 and response.json()["results"][0]["alert_id"] == "inner-id"


@pytest.mark.parametrize(
    "record",
    [
        {"stream": "cs3.ai.ollama", "message": "gpu busy"},
        {"tag": "cs3.ai.inference", "id": "x"},
        {"_tag": "cs3.ai.ollama"},
        {"id": "x", "stream": "CS3.AI.Enrichment"},
        {"id": "y", "source": {"stream": "cs3.ai.tool_call"}},
    ],
)
async def test_records_from_the_ai_tier_are_rejected_with_400(gateway: Gateway, record: dict[str, Any]) -> None:
    response = await gateway.post("/triage", record)
    assert response.status == 400 and response.json()["error"] == "telemetry_loop_rejected"
    assert gateway.ollama.calls == []
    assert gateway.fluent.events() == []


async def test_one_looping_record_rejects_the_whole_batch(gateway: Gateway) -> None:
    batch = [vendetta_alert(id="a"), {"stream": "cs3.ai.ollama", "message": "x"}, vendetta_alert(id="b")]
    response = await gateway.post("/forensic", batch)
    assert response.status == 400 and response.json()["error"] == "telemetry_loop_rejected"
    ndjson = "\n".join(json.dumps(r) for r in batch).encode()
    assert (await gateway.request("POST", "/triage", data=ndjson)).status == 400
    assert gateway.ollama.calls == [] and gateway.fluent.events() == []
    assert metric_value(await gateway.metrics(), "llm_gateway_guardrail_rejections_total", kind="loop") == 2


async def test_loop_markers_in_query_or_headers_are_rejected(gateway: Gateway) -> None:
    assert (await gateway.post("/triage?tag=cs3.ai.ollama", vendetta_alert())).status == 400
    assert (await gateway.post("/triage?stream=cs3.ai.inference", vendetta_alert())).status == 400
    assert (await gateway.post("/triage", vendetta_alert(), headers={"X-Fluentd-Tag": "cs3.ai.ollama"})).status == 400
    assert (await gateway.post("/triage?tag=wazuh.alerts", vendetta_alert())).status == 200


async def test_invalid_bodies_are_400_and_never_reach_the_model(gateway: Gateway) -> None:
    for raw in (b"", b"not json at all", b"42", b'"text"', b"[]", b"[1, 2]", b"{", b'{"a": NaN}'):
        response = await gateway.request("POST", "/triage", data=raw)
        assert response.status == 400, raw
        assert "error" in response.json()
    assert (await gateway.post("/triage", vendetta_alert(), headers={"X-Tenant-Id": "bad tenant!"})).status == 400
    assert gateway.ollama.calls == []


async def test_oversized_body_is_413(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"GATEWAY_MAX_BODY_BYTES": "2048"})
    response = await gateway.post("/triage", vendetta_alert(full_log="A" * 5000))
    assert response.status == 413
    assert gateway.ollama.calls == []


async def test_record_count_cap(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"GATEWAY_MAX_RECORDS": "3"})
    response = await gateway.post("/triage", [vendetta_alert(id=f"r{i}") for i in range(4)])
    assert response.status == 413 and response.json()["error"] == "too_many_records"
    assert (await gateway.post("/triage", [vendetta_alert(id=f"r{i}") for i in range(3)])).status == 200


async def test_bounded_concurrency_protects_the_kv_cache(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"GATEWAY_MAX_CONCURRENCY": "2"})
    gateway.ollama.latency_s = 0.15
    response = await gateway.post("/triage", [vendetta_alert(id=f"storm-{i}") for i in range(8)])
    assert response.status == 200 and len(response.json()["results"]) == 8
    assert gateway.ollama.max_in_flight == 2
    assert metric_value(await gateway.metrics(), "llm_gateway_queue_depth") == 0


async def test_full_queue_answers_429_with_retry_after(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"GATEWAY_MAX_CONCURRENCY": "1", "GATEWAY_MAX_QUEUE": "1"})
    gateway.ollama.latency_s = 0.4
    first = asyncio.create_task(gateway.post("/triage", [vendetta_alert(id="busy-0"), vendetta_alert(id="busy-1")]))
    await asyncio.sleep(0.15)
    flooded = await gateway.post("/triage", [vendetta_alert(id="flood-0"), vendetta_alert(id="flood-1")])
    assert flooded.status == 429 and flooded.json()["error"] == "overloaded" and int(flooded.headers["Retry-After"]) >= 1
    assert (await first).status == 200
    assert [c for c in gateway.ollama.calls if "flood-" in json.dumps(c)] == []


async def test_a_model_that_wants_tools_never_has_them_executed_by_triage(gateway: Gateway) -> None:
    response = await gateway.post("/triage", vendetta_alert())
    analysis = response.json()["results"][0]["analysis"]
    assert analysis["toolCalls"] and analysis["toolCalls"][0]["tool"] == "nmap"
    assert gateway.errow.calls == [] and gateway.errow.initializations == 0
    assert gateway.fluent.events("cs3.ai.tool_call") == []


async def test_unknown_routes_and_methods_do_not_leak_internals(gateway: Gateway) -> None:
    missing = await gateway.get("/admin", auth=True)
    assert missing.status in (401, 404)
    wrong_method = await gateway.get("/triage")
    assert wrong_method.status in (401, 404, 405)
    assert "Traceback" not in wrong_method.text and "Traceback" not in missing.text


async def test_mcp_tool_call_route_requires_a_json_object(gateway: Gateway) -> None:
    assert (await gateway.post("/mcp/tool_call", [1, 2])).status == 400
    assert (await gateway.request("POST", "/mcp/tool_call", data=b"{nope")).status == 400


async def test_openai_passthrough_clamps_temperature_and_stays_non_streaming(gateway: Gateway) -> None:
    body = {"model": TRIAGE_MODEL, "messages": [{"role": "user", "content": "hello"}], "temperature": 1.8, "top_p": 1.0, "n": 5}
    response = await gateway.post("/v1/chat/completions", body, headers={"X-Tenant-Id": "tenant-a"})
    assert response.status == 200
    assert response.json()["choices"][0]["message"]["role"] == "assistant" and response.json()["usage"]["total_tokens"] == 168
    sent = gateway.ollama.calls[-1]
    assert sent["temperature"] == 0.2 and sent["top_p"] <= 0.9 and sent["n"] == 1 and sent["stream"] is False
    assert sent.get("options", {}).get("temperature", 0.2) == 0.2

    gateway.ollama.calls.clear()
    await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": [{"role": "user", "content": "hi"}], "temperature": 0.05})
    assert gateway.ollama.calls[-1]["temperature"] == 0.05
    gateway.ollama.calls.clear()
    await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": [{"role": "user", "content": "hi"}]})
    assert gateway.ollama.calls[-1]["temperature"] == 0.2
    gateway.ollama.calls.clear()
    await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": [{"role": "user", "content": "hi"}], "temperature": -3})
    assert gateway.ollama.calls[-1]["temperature"] == 0.0


async def test_openai_passthrough_rejects_streaming_and_disallowed_models(gateway: Gateway) -> None:
    messages = [{"role": "user", "content": "hello"}]
    streaming = await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": messages, "stream": True})
    assert streaming.status == 400 and streaming.json()["error"]["code"] == "stream_not_supported"
    denied = await gateway.post("/v1/chat/completions", {"model": "gpt-4o", "messages": messages})
    assert denied.status == 403 and denied.json()["error"]["code"] == "model_not_allowed"
    assert (await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL})).status == 400
    assert (await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": [{"role": "root", "content": "x"}]})).status == 400
    assert (await gateway.post("/v1/chat/completions", {"model": 7, "messages": messages})).status == 400
    assert gateway.ollama.calls == []


async def test_openai_passthrough_is_metered_and_audited(gateway: Gateway) -> None:
    await gateway.post("/v1/chat/completions", {"model": "gemma4:31b", "messages": [{"role": "user", "content": "classify this"}]})
    text = await gateway.metrics()
    assert metric_value(text, "llm_gateway_tokens_total", direction="in", role="passthrough", model="gemma4:31b") == 123
    assert (metric_value(text, "llm_gateway_gpu_seconds_total", role="passthrough", model="gemma4:31b") or 0) > 0
    (event,) = await gateway.events("cs3.ai.inference")
    assert event["model"] == "gemma4:31b" and event["role"] == "passthrough" and event["tokens_out"] == 45
    assert "classify this" not in json.dumps(event) and len(event["input_sha256"]) == 64


async def test_openai_passthrough_errors_use_the_openai_error_shape(gateway: Gateway) -> None:
    gateway.ollama.modes[TRIAGE_MODEL] = "down"
    response = await gateway.post("/v1/chat/completions", {"model": TRIAGE_MODEL, "messages": [{"role": "user", "content": "x"}]})
    assert response.status == 502 and response.json()["error"]["code"] == "upstream_error"


async def test_models_listing_is_the_allow_list(gateway: Gateway) -> None:
    ids = {m["id"] for m in (await gateway.get("/v1/models")).json()["data"]}
    assert {TRIAGE_MODEL, FORENSIC_MODEL, "gemma4:31b"} <= ids and "gpt-4o" not in ids


async def test_fluent_bit_outage_spools_events_and_replays_them(gateway: Gateway) -> None:
    gateway.fluent.fail = True
    response = await gateway.post("/triage", vendetta_alert())
    assert response.status == 200
    health = (await gateway.get("/health", auth=False)).json()
    assert health["status"] == "degraded" and health["fluent_bit"]["reachable"] is False
    assert gateway.fluent.received == []
    gateway.fluent.fail = False
    await gateway.fluent.wait_for(2)
    assert {tag for tag, _ in gateway.fluent.received} >= {"cs3.ai.inference", "cs3.ai.enrichment"}
    assert (await gateway.get("/health", auth=False)).json()["audit"]["chain_ok"] is True


async def test_mtls_required_rejects_clients_without_a_certificate(make_gateway: Any) -> None:
    anonymous: Gateway = await make_gateway({"GATEWAY_TLS": "on", "GATEWAY_MTLS": "required"}, tls_verify=False)
    with pytest.raises(aiohttp.ClientError):
        await anonymous.get("/health", auth=False)
    trusted: Gateway = await make_gateway({"GATEWAY_TLS": "on", "GATEWAY_MTLS": "required"}, client_cert=True, tls_verify=False)
    response = await trusted.get("/health", auth=False)
    assert response.status == 200
    assert (await trusted.post("/triage", vendetta_alert())).status == 200
    assert (await trusted.post("/triage", vendetta_alert(), auth=False)).status == 401


async def test_mtls_optional_still_demands_the_bearer_token(make_gateway: Any) -> None:
    gateway: Gateway = await make_gateway({"GATEWAY_TLS": "on", "GATEWAY_MTLS": "optional"}, tls_verify=False)
    assert (await gateway.get("/health", auth=False)).status == 200
    assert (await gateway.post("/triage", vendetta_alert(), auth=False)).status == 401
    assert (await gateway.post("/triage", vendetta_alert())).status == 200


async def test_requests_are_logged_without_bodies_or_tokens(gateway: Gateway, capfd: pytest.CaptureFixture[str]) -> None:
    await gateway.post("/triage", vendetta_alert(full_log="canary-telemetry-line password=hunter2hunter2"))
    await asyncio.sleep(0.05)
    captured = capfd.readouterr()
    output = captured.out + captured.err
    assert "canary-telemetry-line" not in output and "hunter2hunter2" not in output and gateway.token not in output
