#!/usr/bin/env python3
# Traces: PROMPT §1 Tier 4 / NIST AU-9 (tamper-evident AI audit trail); CONTRACT §4.3 (hash chain definition), §3 (cs3-ai-audit-*),
#         §8 (AU-9 runbook + smoke test use this verifier).
"""Verify the hash chain of an NDJSON export of cs3-ai-audit-* (stdlib only; mirrors llm-gateway/audit.py).

  hash = sha256(prev_hash + canonical_json(event without "hash"))
  canonical_json = sorted keys, no whitespace, UTF-8, integral floats written as integers, NaN/Infinity rejected

Input (files or stdin, optionally .gz): NDJSON, a JSON array, one JSON object, or an OpenSearch _search response / hits ({"_source": ...}).
Events are grouped by chain_id (one chain per gateway replica) and ordered by seq, so export order does not matter.

By default an event verifies if its hash matches over the contract's field set for its event_type OR over every field except "hash"
(tolerates fields added later by ingest pipelines). --strict requires the all-fields form only.

Exit codes: 0 every chain verifies, 1 a chain is broken (tampering, gap, fork, bad link), 2 usage / unreadable input / no events.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import sys
from typing import Any, Iterable, Iterator

GENESIS_HASH = "0" * 64
INT_LIMIT = 10**15
CHAIN_FIELDS = ("chain_id", "seq", "prev_hash")
HASHED_FIELDS: dict[str, tuple[str, ...]] = {
    "inference": (
        "@timestamp", "event_type", "request_id", "tenant_id", "incident_id", "alert_id", "model", "role", "engine_used", "fallback",
        "fallback_reason", "latency_ms", "gpu_seconds", "tokens_in", "tokens_out", "verdict", "guardrail", "input_sha256", "input_chars",
        "analysis", *CHAIN_FIELDS,
    ),
    "tool_call": (
        "@timestamp", "event_type", "request_id", "tenant_id", "incident_id", "role", "tool", "args", "target", "decision", "violations",
        "rationale", "gpu_seconds", "live", "result_summary", *CHAIN_FIELDS,
    ),
}
IGNORED_WRAPPER_KEYS = ("_id", "_index", "_type", "_score", "_version", "_seq_no", "_primary_term")
_SURROGATES = re.compile("[\ud800-\udfff]")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalise(value: Any) -> Any:
    if isinstance(value, str):
        return _SURROGATES.sub("\ufffd", value) if _SURROGATES.search(value) else value
    if isinstance(value, float) and value == value and abs(value) < INT_LIMIT and value == int(value):
        return int(value)
    if isinstance(value, dict):
        return {(normalise(k) if isinstance(k, str) else k): normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalise(v) for v in value]
    return value


def canonical_json(event: dict[str, Any]) -> str:
    return json.dumps(normalise(event), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(body)).encode("utf-8")).hexdigest()


def hash_matches(event: dict[str, Any], strict: bool) -> str | None:
    """Returns which field set reproduced the stored hash ('contract' | 'all'), or None."""
    prev = event["prev_hash"]
    full = {k: v for k, v in event.items() if k != "hash" and k not in IGNORED_WRAPPER_KEYS}
    if compute_hash(prev, full) == event["hash"]:
        return "all"
    if strict:
        return None
    fields = HASHED_FIELDS.get(str(event.get("event_type")))
    if fields and compute_hash(prev, {k: v for k, v in full.items() if k in fields}) == event["hash"]:
        return "contract"
    return None


def reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def parse_documents(text: str) -> Iterator[Any]:
    stripped = text.strip()
    if not stripped:
        return
    try:
        yield json.loads(stripped, parse_constant=reject_constant)
        return
    except ValueError:
        pass
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            yield json.loads(line, parse_constant=reject_constant)
        except ValueError as exc:
            raise ValueError(f"line {number} is not valid JSON ({exc})") from exc


def extract_events(documents: Iterable[Any]) -> Iterator[dict[str, Any]]:
    for doc in documents:
        if isinstance(doc, list):
            yield from extract_events(doc)
        elif isinstance(doc, dict):
            hits = doc.get("hits")
            if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
                yield from extract_events(hits["hits"])
            elif isinstance(doc.get("_source"), dict):
                yield doc["_source"]
            else:
                yield doc
        else:
            raise ValueError("input contains a value that is not a JSON object")


def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
        return handle.read()


def verify(events: list[dict[str, Any]], *, strict: bool, require_genesis: bool, chain_filter: str | None) -> dict[str, Any]:
    report: dict[str, Any] = {"events": 0, "duplicates": 0, "chains": {}, "errors": []}
    errors: list[str] = report["errors"]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for index, event in enumerate(events):
        chain_id, seq = event.get("chain_id"), event.get("seq")
        malformed = (
            not isinstance(chain_id, str) or not isinstance(seq, int) or isinstance(seq, bool) or seq < 1
            or not isinstance(event.get("prev_hash"), str) or not isinstance(event.get("hash"), str)
        )
        if malformed:
            errors.append(f"event #{index}: missing or malformed chain fields (chain_id/seq/prev_hash/hash)")
            continue
        if chain_filter and chain_id != chain_filter:
            continue
        grouped.setdefault(chain_id, []).append(event)

    for chain_id, items in sorted(grouped.items()):
        items.sort(key=lambda e: e["seq"])
        info: dict[str, Any] = {"events": 0, "first_seq": items[0]["seq"], "last_seq": items[-1]["seq"], "ok": True, "tail_hash": None}
        tail: dict[str, Any] | None = None
        for event in items:
            seq = event["seq"]
            if tail is not None and seq == tail["seq"]:
                if event["hash"] == tail["hash"]:
                    if hash_matches(event, strict) is None:
                        errors.append(f"chain {chain_id} seq {seq}: duplicate event carries the same hash but altered content")
                        info["ok"] = False
                    else:
                        report["duplicates"] += 1
                    continue
                errors.append(f"chain {chain_id} seq {seq}: two different events share this seq (fork)")
                info["ok"] = False
                continue
            report["events"] += 1
            info["events"] += 1
            if not _HEX64.match(event["hash"]) or not _HEX64.match(event["prev_hash"]):
                errors.append(f"chain {chain_id} seq {seq}: hash fields are not 64 lowercase hex characters")
                info["ok"] = False
            elif hash_matches(event, strict) is None:
                errors.append(f"chain {chain_id} seq {seq}: hash mismatch (event content was altered or hashed differently)")
                info["ok"] = False
            if tail is None:
                if require_genesis and (seq != 1 or event["prev_hash"] != GENESIS_HASH):
                    errors.append(f"chain {chain_id} seq {seq}: chain does not start at genesis (seq 1, prev_hash 64 zeros)")
                    info["ok"] = False
            else:
                if seq != tail["seq"] + 1:
                    errors.append(f"chain {chain_id}: gap between seq {tail['seq']} and {seq}")
                    info["ok"] = False
                if event["prev_hash"] != tail["hash"]:
                    errors.append(f"chain {chain_id} seq {seq}: prev_hash does not equal the hash of seq {tail['seq']}")
                    info["ok"] = False
            tail = event
        info["tail_hash"] = tail["hash"] if tail else None
        report["chains"][chain_id] = info
    report["ok"] = not errors and all(c["ok"] for c in report["chains"].values())
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verify_audit_chain.py", description="Verify the hash chain of an NDJSON export of cs3-ai-audit-*.", epilog="exit codes: 0 verified, 1 broken chain, 2 usage/IO error")
    parser.add_argument("files", nargs="*", default=["-"], help="NDJSON / JSON files (.gz ok); '-' or no argument reads stdin")
    parser.add_argument("--strict", action="store_true", help="hash every field except 'hash' (no contract field-set fallback)")
    parser.add_argument("--require-genesis", action="store_true", help="each chain must start at seq 1 with prev_hash of 64 zeros (full export)")
    parser.add_argument("--chain-id", help="verify only this chain")
    parser.add_argument("--json", action="store_true", help="print a machine-readable report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    events: list[dict[str, Any]] = []
    for path in args.files:
        try:
            events.extend(extract_events(parse_documents(read_text(path))))
        except (OSError, ValueError, UnicodeError) as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
    if not events:
        print("error: no events in input", file=sys.stderr)
        return 2
    report = verify(events, strict=args.strict, require_genesis=args.require_genesis, chain_filter=args.chain_id)
    if args.chain_id and not report["chains"] and not report["errors"]:
        print(f"error: chain {args.chain_id} not found in input", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        for chain_id, info in report["chains"].items():
            print(f"chain {chain_id}: {info['events']} events, seq {info['first_seq']}..{info['last_seq']}, {'OK' if info['ok'] else 'BROKEN'}")
        for error in report["errors"][:50]:
            print(f"  ! {error}")
        if len(report["errors"]) > 50:
            print(f"  ! ... {len(report['errors']) - 50} more")
        print(f"{'VERIFIED' if report['ok'] else 'FAILED'}: {report['events']} events in {len(report['chains'])} chain(s), {report['duplicates']} duplicate(s) ignored")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
