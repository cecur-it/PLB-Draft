# Traces: PROMPT §1 Tier 4 / NIST AU-9 (tamper-evident AI audit trail); CONTRACT §4.3 (hash chain, chain_id per replica, genesis, spool + replay),
#         §4.4 (llm_gateway_audit_chain_ok, llm_gateway_spool_depth), §8 (verify_audit_chain.py used by the AU-9 runbook).
from __future__ import annotations

import asyncio
import gzip
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from audit import (
    GENESIS_HASH,
    TAG_ENRICHMENT,
    TAG_INFERENCE,
    TAG_TOOL_CALL,
    AuditEmitter,
    AuditSetupError,
    AuditUnavailable,
    canonical_json,
    compute_hash,
    verify_chain,
)
from conftest import ROOT, Stack
from meter import Metrics

TOOL = ROOT / "tools" / "verify_audit_chain.py"


def inference_event(n: int) -> dict[str, Any]:
    return {"event_type": "inference", "request_id": f"req-{n}", "role": "triage", "model": "nemotron-3-nano:30b", "fallback": False,
            "tokens_in": 100 + n, "tokens_out": 20, "gpu_seconds": 0.25, "note": "naïve — ünïcode ✓"}


def tool_event(n: int) -> dict[str, Any]:
    return {"event_type": "tool_call", "request_id": f"req-{n}", "tool": "nmap", "decision": "dry_run", "violations": [], "live": False}


@pytest_asyncio.fixture
async def make_emitter(stack: Stack, tmp_path: Path) -> Any:
    created: list[AuditEmitter] = []

    async def factory(spool: Path | None = None, *, start: bool = True) -> tuple[AuditEmitter, Metrics]:
        metrics = Metrics(version="test", models=("a", "b"))
        emitter = AuditEmitter(spool_dir=spool or tmp_path / "spool", url=stack.fluent_url, metrics=metrics, backoff_base_s=0.05, backoff_max_s=0.2, post_timeout_s=2.0)
        if start:
            await emitter.start()
        else:
            emitter.open()
        created.append(emitter)
        return emitter, metrics

    yield factory
    for emitter in created:
        await emitter.close(flush_timeout_s=0.05)


def sample(metrics: Metrics, name: str) -> float:
    value = metrics.registry.get_sample_value(name)
    assert value is not None, name
    return value


def load_verifier() -> Any:
    spec = importlib.util.spec_from_file_location("verify_audit_chain", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_tool(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True, input=stdin, timeout=60, check=False)


def write_ndjson(path: Path, events: list[dict[str, Any]]) -> Path:
    path.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    return path


def test_canonical_json_is_sorted_compact_utf8() -> None:
    assert canonical_json({"b": 1, "a": {"d": [1, 2], "c": "é✓"}}) == '{"a":{"c":"é✓","d":[1,2]},"b":1}'
    assert canonical_json({"x": 3.0, "y": 0.25}) == '{"x":3,"y":0.25}'


def test_hash_definition_matches_the_contract() -> None:
    event = {"chain_id": "r1-aaaa", "seq": 1, "prev_hash": GENESIS_HASH, "event_type": "inference", "a": 1}
    expected = hashlib.sha256((GENESIS_HASH + '{"a":1,"chain_id":"r1-aaaa","event_type":"inference","prev_hash":"' + GENESIS_HASH + '","seq":1}').encode("utf-8")).hexdigest()
    assert compute_hash(GENESIS_HASH, event) == expected and GENESIS_HASH == "0" * 64
    assert compute_hash(GENESIS_HASH, {**event, "hash": "ignored"}) != expected  # the hash field itself is never excluded implicitly


async def test_emitted_chain_verifies_and_starts_at_genesis(make_emitter: Any, stack: Stack) -> None:
    emitter, metrics = await make_emitter()
    sealed = [await emitter.emit(TAG_INFERENCE if n % 2 else TAG_TOOL_CALL, inference_event(n) if n % 2 else tool_event(n)) for n in range(1, 6)]
    assert [e["seq"] for e in sealed] == [1, 2, 3, 4, 5] and sealed[0]["prev_hash"] == GENESIS_HASH
    assert len({e["chain_id"] for e in sealed}) == 1 and sealed[0]["chain_id"] == emitter.chain_id
    assert all(sealed[i]["prev_hash"] == sealed[i - 1]["hash"] for i in range(1, 5))
    assert verify_chain(sealed, require_genesis=True).ok
    assert await emitter.flush(5.0)
    delivered = stack.fluent.received
    assert [tag for tag, _ in delivered] == [TAG_INFERENCE, TAG_TOOL_CALL, TAG_INFERENCE, TAG_TOOL_CALL, TAG_INFERENCE]
    assert [body["hash"] for _, body in delivered] == [e["hash"] for e in sealed]
    assert verify_chain([body for _, body in delivered], require_genesis=True).ok
    assert sample(metrics, "llm_gateway_audit_chain_ok") == 1 and sample(metrics, "llm_gateway_spool_depth") == 0


async def test_enrichment_events_are_not_chained(make_emitter: Any, stack: Stack) -> None:
    emitter, _ = await make_emitter()
    plain = await emitter.emit(TAG_ENRICHMENT, {"id": "a-1", "severity": "high"})
    assert not {"chain_id", "seq", "prev_hash", "hash"} & plain.keys()
    first = await emitter.emit(TAG_INFERENCE, inference_event(1))
    assert first["seq"] == 1
    with pytest.raises(ValueError):
        await emitter.emit("cs3.ai.ollama", {"x": 1})


async def test_tampering_breaks_the_chain(make_emitter: Any) -> None:
    emitter, _ = await make_emitter()
    sealed = [await emitter.emit(TAG_INFERENCE, inference_event(n)) for n in range(1, 5)]
    assert verify_chain(sealed).ok

    altered = [dict(e) for e in sealed]
    altered[1]["tokens_out"] = 999
    assert not verify_chain(altered).ok

    removed = [sealed[0], sealed[2], sealed[3]]
    result = verify_chain(removed)
    assert not result.ok and any("does not follow" in err for err in result.errors)

    relinked = [dict(e) for e in sealed]
    relinked[2]["prev_hash"] = GENESIS_HASH
    assert not verify_chain(relinked).ok

    forged = [dict(e) for e in sealed]
    forged[3]["hash"] = "f" * 64
    assert not verify_chain(forged).ok
    assert not verify_chain(sealed[1:], require_genesis=True).ok and verify_chain(sealed[1:]).ok


async def test_restart_continues_the_same_chain(make_emitter: Any, stack: Stack, tmp_path: Path) -> None:
    spool = tmp_path / "restart-spool"
    first, _ = await make_emitter(spool)
    one = await first.emit(TAG_INFERENCE, inference_event(1))
    assert await first.flush(5.0)
    await first.close(flush_timeout_s=0.05)

    second, _ = await make_emitter(spool)
    two = await second.emit(TAG_TOOL_CALL, tool_event(2))
    assert second.chain_id == first.chain_id and two["chain_id"] == one["chain_id"]
    assert (two["seq"], two["prev_hash"]) == (2, one["hash"])
    assert await second.flush(5.0)
    assert verify_chain([body for _, body in stack.fluent.received], require_genesis=True).ok


async def test_restart_with_unsent_events_replays_them_in_order(make_emitter: Any, stack: Stack, tmp_path: Path) -> None:
    spool = tmp_path / "crash-spool"
    stack.fluent.fail = True
    first, _ = await make_emitter(spool)
    sealed = [await first.emit(TAG_INFERENCE, inference_event(n)) for n in range(1, 4)]
    await first.close(flush_timeout_s=0.05)
    assert stack.fluent.received == []

    stack.fluent.fail = False
    second, metrics = await make_emitter(spool)
    assert second.spool_depth == 3 and sample(metrics, "llm_gateway_spool_depth") == 3
    follow_up = await second.emit(TAG_INFERENCE, inference_event(4))
    assert follow_up["seq"] == 4 and follow_up["prev_hash"] == sealed[-1]["hash"]
    delivered = await stack.fluent.wait_for(4, TAG_INFERENCE)
    assert [e["seq"] for e in delivered] == [1, 2, 3, 4]
    assert verify_chain(delivered, require_genesis=True).ok and sample(metrics, "llm_gateway_audit_chain_ok") == 1


async def test_spool_replay_preserves_order_after_an_outage(make_emitter: Any, stack: Stack) -> None:
    stack.fluent.fail = True
    emitter, metrics = await make_emitter()
    for n in range(1, 8):
        await emitter.emit(TAG_INFERENCE if n % 3 else TAG_ENRICHMENT, inference_event(n))
    await asyncio.sleep(0.35)
    assert stack.fluent.received == [] and emitter.spool_depth == 7 and sample(metrics, "llm_gateway_spool_depth") == 7
    assert len(list((emitter._dir).glob("ev-*.json"))) == 7

    stack.fluent.fail = False
    assert await emitter.flush(10.0)
    assert [body["request_id"] for _, body in stack.fluent.received] == [f"req-{n}" for n in range(1, 8)]
    assert sample(metrics, "llm_gateway_spool_depth") == 0 and list(emitter._dir.glob("ev-*.json")) == []
    chained = [body for tag, body in stack.fluent.received if tag == TAG_INFERENCE]
    assert verify_chain(chained, require_genesis=True).ok


async def test_network_errors_are_retried_too(make_emitter: Any, stack: Stack) -> None:
    emitter, _ = await make_emitter()
    emitter._url = "http://127.0.0.1:1"
    await emitter.emit(TAG_INFERENCE, inference_event(1))
    await asyncio.sleep(0.3)
    assert emitter.spool_depth == 1
    emitter._url = stack.fluent_url
    assert await emitter.flush(10.0) and len(stack.fluent.received) == 1


async def test_permanently_rejected_chained_event_is_quarantined_and_flags_the_chain(make_emitter: Any, stack: Stack) -> None:
    stack.fluent.fail, stack.fluent.fail_status = True, 400
    emitter, metrics = await make_emitter()
    await emitter.emit(TAG_INFERENCE, inference_event(1))
    assert await emitter.flush(10.0)
    assert len(list((emitter._dir / "quarantine").iterdir())) == 1
    assert sample(metrics, "llm_gateway_audit_chain_ok") == 0 and emitter.chain_ok is False


async def test_unreadable_chain_state_starts_a_new_chain_and_alerts(make_emitter: Any, tmp_path: Path) -> None:
    spool = tmp_path / "corrupt-spool"
    first, _ = await make_emitter(spool)
    one = await first.emit(TAG_INFERENCE, inference_event(1))
    await first.flush(5.0)
    await first.close(flush_timeout_s=0.05)
    (spool / "chain-state.json").write_text("{not json", encoding="utf-8")
    second, metrics = await make_emitter(spool)
    fresh = await second.emit(TAG_INFERENCE, inference_event(2))
    assert fresh["chain_id"] != one["chain_id"] and fresh["seq"] == 1 and fresh["prev_hash"] == GENESIS_HASH
    assert sample(metrics, "llm_gateway_audit_chain_ok") == 0


async def test_one_spool_directory_per_replica(make_emitter: Any, tmp_path: Path) -> None:
    spool = tmp_path / "shared"
    await make_emitter(spool)
    with pytest.raises(AuditSetupError, match="one spool volume per replica"):
        await make_emitter(spool, start=False)


async def test_unwritable_spool_fails_closed(stack: Stack, tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="ascii")
    emitter = AuditEmitter(spool_dir=blocker / "spool", url=stack.fluent_url, metrics=Metrics(version="t"))
    with pytest.raises(AuditSetupError):
        emitter.open()
    unopened = AuditEmitter(spool_dir=tmp_path / "unopened", url=stack.fluent_url, metrics=Metrics(version="t"))
    with pytest.raises(AuditUnavailable):
        await unopened.emit(TAG_INFERENCE, inference_event(1))


async def test_full_spool_refuses_chained_events_but_drops_enrichment(make_emitter: Any, stack: Stack, tmp_path: Path) -> None:
    stack.fluent.fail = True
    metrics = Metrics(version="t")
    emitter = AuditEmitter(spool_dir=tmp_path / "small", url=stack.fluent_url, metrics=metrics, max_events=2, backoff_base_s=0.05, backoff_max_s=0.2)
    await emitter.start()
    try:
        await emitter.emit(TAG_INFERENCE, inference_event(1))
        await emitter.emit(TAG_INFERENCE, inference_event(2))
        with pytest.raises(AuditUnavailable):
            await emitter.emit(TAG_INFERENCE, inference_event(3))
        await emitter.emit(TAG_ENRICHMENT, {"id": "dropped"})
        assert emitter.spool_depth == 2 and metrics.registry.get_sample_value("llm_gateway_audit_dropped_total", {"tag": TAG_ENRICHMENT}) == 1
    finally:
        await emitter.close(flush_timeout_s=0.05)


def test_verifier_and_gateway_use_the_same_canonical_form() -> None:
    verifier = load_verifier()
    for event in ({"b": 1, "a": "é✓ — naïve"}, {"x": 3.0, "y": [1.5, {"z": None}]}, {"nested": {"k": [True, False]}, "u": "\u2028 line"}):
        assert verifier.canonical_json(event) == canonical_json(event)
        assert verifier.compute_hash(GENESIS_HASH, event) == compute_hash(GENESIS_HASH, event)


async def test_cli_verifies_an_export_of_the_gateway_chain(make_emitter: Any, tmp_path: Path) -> None:
    emitter, _ = await make_emitter()
    sealed = [await emitter.emit(TAG_INFERENCE if n % 2 else TAG_TOOL_CALL, inference_event(n) if n % 2 else tool_event(n)) for n in range(1, 8)]
    export = write_ndjson(tmp_path / "export.ndjson", sealed)

    ok = run_tool(str(export), "--require-genesis")
    assert ok.returncode == 0 and "VERIFIED: 7 events in 1 chain(s)" in ok.stdout
    assert run_tool(str(export), "--strict").returncode == 0
    report = json.loads(run_tool(str(export), "--json").stdout)
    assert report["ok"] is True and report["chains"][emitter.chain_id]["events"] == 7 and report["chains"][emitter.chain_id]["tail_hash"] == sealed[-1]["hash"]
    shuffled = write_ndjson(tmp_path / "shuffled.ndjson", list(reversed(sealed)))
    assert run_tool(str(shuffled)).returncode == 0
    assert run_tool(str(export), "--chain-id", emitter.chain_id).returncode == 0
    assert run_tool("--require-genesis", stdin=export.read_text(encoding="utf-8")).returncode == 0

    gz = tmp_path / "export.ndjson.gz"
    gz.write_bytes(gzip.compress(export.read_bytes()))
    assert run_tool(str(gz)).returncode == 0
    wrapped = tmp_path / "search.json"
    wrapped.write_text(json.dumps({"hits": {"hits": [{"_index": "cs3-ai-audit-2026.02.14", "_id": f"id{i}", "_source": e} for i, e in enumerate(sealed)]}}), encoding="utf-8")
    assert run_tool(str(wrapped)).returncode == 0
    array = tmp_path / "array.json"
    array.write_text(json.dumps(sealed), encoding="utf-8")
    assert run_tool(str(array)).returncode == 0


async def test_cli_exit_1_on_tampering_gap_fork_and_missing_genesis(make_emitter: Any, tmp_path: Path) -> None:
    emitter, _ = await make_emitter()
    sealed = [await emitter.emit(TAG_INFERENCE, inference_event(n)) for n in range(1, 6)]

    altered = [dict(e) for e in sealed]
    altered[2]["tokens_out"] = 1
    result = run_tool(str(write_ndjson(tmp_path / "altered.ndjson", altered)))
    assert result.returncode == 1 and "hash mismatch" in result.stdout and "FAILED" in result.stdout

    gap = run_tool(str(write_ndjson(tmp_path / "gap.ndjson", sealed[:2] + sealed[3:])))
    assert gap.returncode == 1 and "gap" in gap.stdout

    forked = [*sealed, {**sealed[2], "request_id": "forged"}]
    fork = run_tool(str(write_ndjson(tmp_path / "fork.ndjson", forked)))
    assert fork.returncode == 1

    tail = write_ndjson(tmp_path / "tail.ndjson", sealed[2:])
    assert run_tool(str(tail)).returncode == 0
    assert run_tool(str(tail), "--require-genesis").returncode == 1

    duplicated = write_ndjson(tmp_path / "dup.ndjson", [*sealed, sealed[-1]])
    assert run_tool(str(duplicated)).returncode == 0


def test_cli_exit_2_on_usage_and_io_errors(tmp_path: Path) -> None:
    assert run_tool(str(tmp_path / "missing.ndjson")).returncode == 2
    empty = tmp_path / "empty.ndjson"
    empty.write_text("", encoding="utf-8")
    assert run_tool(str(empty)).returncode == 2
    garbage = tmp_path / "garbage.ndjson"
    garbage.write_text("this is not json\n", encoding="utf-8")
    assert run_tool(str(garbage)).returncode == 2
    assert run_tool("--no-such-flag").returncode == 2
    nan = tmp_path / "nan.ndjson"
    nan.write_text('{"chain_id":"c","seq":NaN}\n', encoding="utf-8")
    assert run_tool(str(nan)).returncode == 2
    unknown_chain = write_ndjson(tmp_path / "c.ndjson", [{"chain_id": "c1", "seq": 1, "prev_hash": GENESIS_HASH, "hash": compute_hash(GENESIS_HASH, {"chain_id": "c1", "seq": 1, "prev_hash": GENESIS_HASH})}])
    assert run_tool(str(unknown_chain)).returncode == 0
    assert run_tool(str(unknown_chain), "--chain-id", "nope").returncode == 2


async def test_cli_verifies_peer_style_hash_over_the_contract_field_set(tmp_path: Path) -> None:
    prev = GENESIS_HASH
    events = []
    for seq in (1, 2, 3):
        body = {"chain_id": "gw-1", "seq": seq, "prev_hash": prev, "event_type": "tool_call", "request_id": f"r{seq}", "tool": "nmap", "decision": "dry_run"}
        events.append({**body, "hash": compute_hash(prev, body), "ingest_extra": "added by a pipeline"})
        prev = events[-1]["hash"]
    path = write_ndjson(tmp_path / "ingested.ndjson", events)
    assert run_tool(str(path)).returncode == 0
    assert run_tool(str(path), "--strict").returncode == 1
