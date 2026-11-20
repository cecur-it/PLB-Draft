"""Pure record builders for the errow shipper streams (no I/O).

Every builder takes already-parsed Errow artifacts and returns ``(key, content_hash, record)`` tuples or
plain records. The record shapes follow CONTRACT §15; field names are Errow's own (SARIF names for findings),
never renamed here. Nothing in this module can emit ``poc_script_code`` or code/payload bodies: see
``sanitize.drop_keys`` / ``elide_code`` / ``omit_tool_args``.

Traces: PROMPT §2.3 (errow-shipper), CONTRACT §8.4, §15; errow/errow/report/{sarif,state,coverage}.py,
errow/errow/llm/request_log.py, errow/errow/telemetry/{logging,posthog}.py, errow/errow/tools/threat_model/tools.py.
"""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime
from typing import Any

from sanitize import drop_keys, elide_code, omit_tool_args, sanitize_text, sanitize_value
from store import canonical, sha256_hex

STREAMS: tuple[str, ...] = (
    "findings", "runs", "transcripts", "threat_models", "coverage", "llm_logs", "mcp_events", "runtime_events",
    "tui_events", "cloud_events", "telemetry", "agent_state", "report_artifacts", "proxy", "tooling", "viewer",
)
SHIPPER_WRITES: tuple[str, ...] = tuple(s for s in STREAMS if s != "mcp_events")  # mcp_events: errow-mcp + gateway
BASE_KEYS = ("@timestamp", "stream", "run", "source", "doc_id")
_FINDING_PROSE = (
    "technical_analysis", "impact", "confidence_rationale", "counterevidence", "severity_change_conditions",
    "remediation_steps", "fix_verification",
)
SEVERITIES = ("critical", "high", "medium", "low", "info")
_LOG_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{3}) ([A-Z]+)\s+(\S+) (\S+) ([^\s:]+): (.*)$", re.DOTALL
)
_LLM_FIELD = re.compile(r"(\w+)=(\S*)")
_TERMINAL_STATUSES = frozenset({"completed", "failed", "stopped", "cancelled", "canceled", "error", "aborted"})
OUTPUT_PREVIEW_CHARS = 500


def iso(dt: datetime) -> str:
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now_iso() -> str:
    return iso(datetime.now(UTC))


def epoch_iso(seconds: float) -> str:
    return iso(datetime.fromtimestamp(seconds, UTC))


def parse_ts(value: Any) -> str | None:
    """Errow writes ``YYYY-MM-DD HH:MM:SS UTC``, ISO-8601 (with offset) or SQLite ``CURRENT_TIMESTAMP``."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return epoch_iso(float(seconds))
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4]
    try:
        dt = datetime.fromisoformat(text.replace(" ", "T", 1) if "T" not in text else text)
    except ValueError:
        return None
    return iso(dt if dt.tzinfo else dt.replace(tzinfo=UTC))


def make_record(stream: str, run: str, ts: str, doc_id: str, content: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {"@timestamp": ts, "stream": stream, "run": run, "source": "errow", "doc_id": doc_id}
    record.update({k: v for k, v in content.items() if k not in BASE_KEYS})
    return record


def chash(content: Any) -> str:
    return sha256_hex(canonical(content))[:32]


def _elide_tree(value: Any) -> Any:
    if isinstance(value, str):
        return elide_code(value)
    if isinstance(value, dict):
        return {k: _elide_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_elide_tree(v) for v in value]
    return value


def scrub(value: Any) -> Any:
    """drop never-emit keys, elide fenced code, then the edge sanitisation (control chars, cap, redaction)."""
    return sanitize_value(_elide_tree(drop_keys(value)))


# ------------------------------------------------------------------ findings (findings.sarif)
def _rule_for(rules: list[Any], result: dict[str, Any]) -> dict[str, Any] | None:
    rule_id = result.get("ruleId")
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules) and isinstance(rules[idx], dict) and rules[idx].get("id") == rule_id:
        return rules[idx]
    for rule in rules:
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            return rule
    return None


def finding_doc_id(run: str, result: dict[str, Any]) -> str:
    rule_id = str(result.get("ruleId") or "")
    fp = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash") if isinstance(result.get("partialFingerprints"), dict) else None
    if fp:
        return sha256_hex(run + rule_id + str(fp))
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    errow = props.get("errow") if isinstance(props.get("errow"), dict) else {}
    anchor = errow.get("id") or errow.get("surface") or canonical(result.get("message") or "")
    return sha256_hex(run + rule_id + str(anchor))


def is_coverage_result(result: dict[str, Any]) -> bool:
    return result.get("level") == "none" or result.get("kind") not in (None, "fail")


def _finding_content(result: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    res = drop_keys(copy.deepcopy(result))
    message = res.get("message")
    if isinstance(message, dict) and isinstance(message.get("text"), str):
        message["text"] = elide_code(message["text"])
    props = res.get("properties")
    errow = props.get("errow") if isinstance(props, dict) else None
    if isinstance(errow, dict):
        for key in _FINDING_PROSE:
            if isinstance(errow.get(key), str):
                errow[key] = elide_code(errow[key])
        poc = errow.get("poc")
        if isinstance(poc, dict) and isinstance(poc.get("description"), str):
            poc["description"] = elide_code(poc["description"])
    out_rule = None
    if rule is not None:
        out_rule = drop_keys(copy.deepcopy(rule))
        for key in ("help", "fullDescription", "shortDescription"):
            part = out_rule.get(key)
            if isinstance(part, dict):
                out_rule[key] = {k: elide_code(v) if isinstance(v, str) else v for k, v in part.items()}
    res["rule"] = out_rule
    return sanitize_value(res)


def finding_records(run: str, sarif: Any, now: str, *, include_coverage: bool = False) -> list[tuple[str, str, dict[str, Any]]]:
    out: list[tuple[str, str, dict[str, Any]]] = []
    runs = sarif.get("runs") if isinstance(sarif, dict) else None
    for sarif_run in runs if isinstance(runs, list) else []:
        if not isinstance(sarif_run, dict):
            continue
        driver = ((sarif_run.get("tool") or {}).get("driver") or {}) if isinstance(sarif_run.get("tool"), dict) else {}
        rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
        for result in sarif_run.get("results") or []:
            if not isinstance(result, dict) or (is_coverage_result(result) and not include_coverage):
                continue
            doc_id = finding_doc_id(run, result)
            content = _finding_content(result, _rule_for(rules, result))
            props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            errow = props.get("errow") if isinstance(props.get("errow"), dict) else {}
            ts = parse_ts(errow.get("timestamp")) or now
            out.append((doc_id, chash(content), make_record("findings", run, ts, doc_id, content)))
    return out


# ------------------------------------------------------------------ snapshot documents
def run_record(run: str, doc: Any, now: str) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(doc, dict):
        return None
    content = scrub(doc)
    h = chash(content)
    return h, make_record("runs", run, now, sha256_hex(run + "runs" + h), content)


def coverage_record(run: str, doc: Any, now: str) -> tuple[str, dict[str, Any]] | None:
    if not isinstance(doc, dict):
        return None
    content = scrub(doc)
    h = chash({k: v for k, v in content.items() if k != "generated_at"})
    return h, make_record("coverage", run, now, sha256_hex(run + "coverage" + h), content)


def threat_model_records(run: str, doc: Any, now: str) -> list[tuple[str, str, dict[str, Any]]]:
    out: list[tuple[str, str, dict[str, Any]]] = []
    if not isinstance(doc, dict):
        return out
    for identity, entry in doc.items():
        if not isinstance(entry, dict):
            continue
        amendments = [
            {"at": a.get("at"), "by": a.get("by"), "content": a.get("content")}
            for a in entry.get("amendments") or [] if isinstance(a, dict)
        ]
        content = scrub({
            "identity": str(identity),
            "target": entry.get("target") or str(identity),
            "written_at": entry.get("written_at"),
            "written_by": entry.get("written_by"),
            "content": entry.get("content") or "",
            "amendments": amendments,
            "amendment_count": len(amendments),
        })
        h = chash(content)
        stamps = [parse_ts(entry.get("written_at"))] + [parse_ts(a["at"]) for a in amendments]
        ts = max((s for s in stamps if s), default=now)
        out.append((str(identity), h, make_record("threat_models", run, ts, sha256_hex(run + "threat_models" + str(identity) + h), content)))
    return out


# ------------------------------------------------------------------ agents
def _cached_tokens(details: Any) -> int:
    if isinstance(details, dict):
        return int(details.get("cached_tokens") or 0)
    if isinstance(details, list):
        return sum(int(d.get("cached_tokens") or 0) for d in details if isinstance(d, dict))
    return 0


def agent_state_records(run: str, graph: dict[str, Any], usage_agents: list[Any], db_stats: dict[str, dict[str, Any]],
                        now: str) -> list[tuple[str, str, dict[str, Any]]]:
    statuses = graph.get("statuses") if isinstance(graph.get("statuses"), dict) else {}
    names = graph.get("names") if isinstance(graph.get("names"), dict) else {}
    parents = graph.get("parent_of") if isinstance(graph.get("parent_of"), dict) else {}
    errors = graph.get("errors") if isinstance(graph.get("errors"), dict) else {}
    metadata = graph.get("metadata") if isinstance(graph.get("metadata"), dict) else {}
    usage = {str(u.get("agent_id")): u for u in usage_agents if isinstance(u, dict) and u.get("agent_id")}
    ids = list(dict.fromkeys([*map(str, statuses), *usage, *db_stats]))
    out: list[tuple[str, str, dict[str, Any]]] = []
    for agent_id in ids:
        meta = metadata.get(agent_id) if isinstance(metadata.get(agent_id), dict) else {}
        u = usage.get(agent_id, {})
        db = db_stats.get(agent_id, {})
        parent = parents.get(agent_id)
        content = scrub({
            "agent_id": agent_id,
            "agent_name": names.get(agent_id) or u.get("agent_name") or agent_id,
            "status": str(statuses.get(agent_id) or "unknown"),
            "role": "subagent" if parent else "root",
            "parent_id": parent or None,
            "task": str(meta.get("task") or ""),
            "skills": [str(s) for s in meta.get("skills") or []] if isinstance(meta.get("skills"), list) else [],
            "model": u.get("model"),
            "tokens": {
                "input": int(u.get("input_tokens") or 0),
                "output": int(u.get("output_tokens") or 0),
                "total": int(u.get("total_tokens") or 0),
                "cached": _cached_tokens(u.get("input_tokens_details")),
                "requests": int(u.get("requests") or 0),
            },
            "cost": float(u.get("cost") or 0.0),
            "messages": int(db.get("messages") or 0),
            "last_message_at": db.get("last_message_at"),
            "error": errors.get(agent_id),
        })
        h = chash(content)
        out.append((agent_id, h, make_record("agent_state", run, now, sha256_hex(run + "agent_state" + agent_id + h), content)))
    return out


def _json_or_raw(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text")
                parts.append(text if isinstance(text, str) else f"[{part.get('type', 'part')}]")
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False, default=str)


def message_records(run: str, row_id: int, session_id: str, created_at: Any, raw: Any, agent_name: str,
                    tool_names: dict[str, str], now: str) -> list[tuple[str, dict[str, Any]]]:
    """Transcript (+ tooling) records for one ``agent_messages`` row; ``(stream, record)`` pairs."""
    item = _json_or_raw(raw)
    if not isinstance(item, dict):
        item = {"role": "unknown", "content": raw}
    ts = parse_ts(created_at) or now
    kind = str(item.get("type") or "message")
    base = {"agent": agent_name, "agent_id": session_id, "message_id": row_id}
    mid = f"{session_id}:{row_id}:"
    if kind == "reasoning":
        return []
    if kind == "function_call":
        name = str(item.get("name") or "unknown")
        call_id = str(item.get("call_id") or item.get("id") or "")
        args = omit_tool_args(_json_or_raw(item.get("arguments")))
        tool_names[f"{run}|{call_id}"] = name
        rendered = scrub(args)
        summary = f"{name}({canonical(rendered)})" if not isinstance(rendered, str) else f"{name}({rendered})"
        doc_t = sha256_hex(run + "transcripts" + mid + sha256_hex(summary))
        doc_c = sha256_hex(run + "tooling" + mid + "call" + call_id)
        return [
            ("transcripts", make_record("transcripts", run, ts, doc_t, {**base, "role": "assistant", "type": kind,
                                                                      "tool": name, "call_id": call_id,
                                                                      "content": sanitize_text(summary)})),
            ("tooling", make_record("tooling", run, ts, doc_c, {**base, "event_type": "tool_call", "tool": name,
                                                              "call_id": call_id, "arguments": rendered})),
        ]
    if kind == "function_call_output":
        call_id = str(item.get("call_id") or "")
        output = _text_of(item.get("output"))
        tool = tool_names.get(f"{run}|{call_id}")
        shown = sanitize_text(elide_code(output))
        doc_t = sha256_hex(run + "transcripts" + mid + sha256_hex(output))
        doc_c = sha256_hex(run + "tooling" + mid + "result" + call_id)
        return [
            ("transcripts", make_record("transcripts", run, ts, doc_t, {**base, "role": "tool", "type": kind,
                                                                      "tool": tool, "call_id": call_id,
                                                                      "content": shown})),
            ("tooling", make_record("tooling", run, ts, doc_c, {
                **base, "event_type": "tool_result", "tool": tool, "call_id": call_id,
                "output_chars": len(output), "output_sha256": sha256_hex(output),
                "output_preview": sanitize_text(elide_code(output), OUTPUT_PREVIEW_CHARS)})),
        ]
    role = str(item.get("role") or "unknown")
    text = _text_of(item.get("content"))
    content = f"[omitted:{len(text)} chars]" if role == "system" else sanitize_text(elide_code(text))
    doc_t = sha256_hex(run + "transcripts" + mid + sha256_hex(text))
    return [("transcripts", make_record("transcripts", run, ts, doc_t, {**base, "role": role, "type": kind, "content": content}))]


# ------------------------------------------------------------------ errow.log
def parse_log_line(line: str) -> dict[str, Any] | None:
    m = _LOG_LINE.match(line)
    if not m:
        return None
    stamp, millis, level, scan_id, agent_id, logger_name, message = m.groups()
    ts = parse_ts(f"{stamp}.{millis}")
    return {
        "ts": ts, "level": level, "scan_id": None if scan_id == "-" else scan_id,
        "agent_id": None if agent_id == "-" else agent_id, "logger": logger_name, "message": message,
    }


def _num(value: str, cast: Any = int) -> Any:
    if value in ("", "-"):
        return None
    try:
        return cast(value)
    except ValueError:
        return None


def parse_llm_request(message: str) -> dict[str, Any]:
    """``llm_request key=value ...`` (llm/request_log.py ``_log_line_sink``); never carries prompt bodies."""
    body = message[len("llm_request "):]
    error = None
    if " error=" in body:
        body, error = body.split(" error=", 1)
    f = {k: v for k, v in _LLM_FIELD.findall(body)}

    def val(key: str) -> str | None:
        v = f.get(key)
        return None if v in (None, "", "-") else v

    in_tok, out_tok, cached = _num(f.get("in", "")), _num(f.get("out", "")), _num(f.get("cached", ""))
    status = _num(f.get("status", ""))
    out = {
        "route": val("route"), "provider": val("provider"), "upstream_provider": val("upstream"),
        "upstream_error": val("upstream_error"), "model": val("model"), "api_host": val("host"),
        "outcome": val("outcome"), "status": status, "status_code": status,
        "provider_request_id": val("request_id"), "response_id": val("response_id"),
        "streaming": f.get("stream") == "1", "duration_ms": _num(f.get("duration_ms", "")),
        "latency_ms": _num(f.get("duration_ms", "")), "ttft_ms": _num(f.get("ttft_ms", "")),
        "request_bytes": _num(f.get("req_bytes", "")), "response_bytes": _num(f.get("res_bytes", "")),
        "finish_reason": val("finish"),
        "tokens": {"input": in_tok, "output": out_tok, "cached": cached,
                   "total": (in_tok or 0) + (out_tok or 0) if in_tok is not None or out_tok is not None else None},
        "cost_usd": _num(f.get("cost", ""), float), "agent_id": val("agent"), "attempt": _num(f.get("attempt", "")),
    }
    if error is not None:
        out["error"] = sanitize_text(error.strip(), 2000)
    return out


def classify_log(logger_name: str, message: str) -> str:
    if logger_name == "errow.llm.request_log" and message.startswith("llm_request "):
        return "llm_logs"
    parts = set(logger_name.lower().split("."))
    if "tui" in parts:
        return "tui_events"
    if "viewer" in parts:
        return "viewer"
    if "cloud" in parts:
        return "cloud_events"
    return "runtime_events"


def log_events(run: str, lines: list[tuple[int, str]], now: str) -> list[tuple[str, dict[str, Any]]]:
    """Group ``(byte_offset, line)`` pairs into events (continuation lines join the previous record)."""
    groups: list[tuple[int, dict[str, Any] | None, list[str]]] = []
    for offset, line in lines:
        parsed = parse_log_line(line)
        if parsed is None and groups:
            groups[-1][2].append(line)
        else:
            groups.append((offset, parsed, [line] if parsed is None else []))
    out: list[tuple[str, dict[str, Any]]] = []
    for offset, parsed, extra in groups:
        if parsed is None:
            parsed = {"ts": None, "level": "UNKNOWN", "scan_id": None, "agent_id": None, "logger": "errow.log",
                      "message": extra[0]}
            extra = extra[1:]
        message = "\n".join([parsed["message"], *extra]) if extra else parsed["message"]
        stream = classify_log(parsed["logger"], message)
        doc_id = sha256_hex(f"{run}|errow.log|{offset}|{sha256_hex(message)}")
        ts = parsed["ts"] or now
        content: dict[str, Any] = {"level": parsed["level"], "logger": parsed["logger"],
                                   "scan_id": parsed["scan_id"], "agent_id": parsed["agent_id"]}
        if stream == "llm_logs":
            content.update(parse_llm_request(message))
        else:
            content["message"] = sanitize_text(elide_code(message))
        out.append((stream, make_record(stream, run, ts, doc_id, content)))
    return out


# ------------------------------------------------------------------ artifacts and telemetry
ARTIFACT_KINDS = {".pdf": "pdf", ".sarif": "sarif", ".json": "json", ".md": "md"}


def artifact_kind(name: str) -> str | None:
    dot = name.rfind(".")
    return ARTIFACT_KINDS.get(name[dot:].lower()) if dot > 0 else None


def artifact_record(run: str, rel: str, sha: str, size: int, now: str) -> dict[str, Any]:
    path = f"{run}/{rel}"
    name = rel.rsplit("/", 1)[-1]
    return make_record("report_artifacts", run, now, sha256_hex(run + path + sha),
                       {"artifact": name, "path": path, "sha256": sha, "bytes": size, "kind": artifact_kind(name)})


def telemetry_events(run: str, run_json: dict[str, Any], new_findings: list[dict[str, Any]], finding_counts: dict[str, int],
                     seen: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Events Errow would send to PostHog (telemetry/posthog.py), derived from run artifacts: ``(discriminator, props)``.

    Errow keeps no local telemetry file, so this is a mirror of the *shape* of scan_started /
    finding_reported / scan_ended, built from run.json and findings.sarif; ``seen`` records what was emitted.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    usage = run_json.get("llm_usage") if isinstance(run_json.get("llm_usage"), dict) else {}
    agents = usage.get("agents") if isinstance(usage.get("agents"), list) else []
    targets = run_json.get("targets_info") if isinstance(run_json.get("targets_info"), list) else []
    whitebox = any(isinstance(t, dict) and t.get("type") in ("repository", "local_code") for t in targets)
    if not seen.get("started"):
        model = next((a.get("model") for a in agents if isinstance(a, dict) and a.get("model")), None)
        out.append(("scan_started", {
            "model": model or "unknown", "auth_mode": run_json.get("auth_mode") or "api_key",
            "scan_mode": run_json.get("scan_mode") or "unknown", "scan_type": "whitebox" if whitebox else "blackbox",
            "has_instructions": bool(str(run_json.get("instruction") or "").strip()),
        }))
    for res in new_findings:
        props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
        errow = props.get("errow") if isinstance(props.get("errow"), dict) else {}
        out.append((f"finding_reported:{res.get('doc_id')}", {
            "severity": str(errow.get("severity") or "unknown").lower(),
            "cwe": str(errow.get("cwe") or "").strip().lower() or "unknown", "is_cve": bool(errow.get("cve")),
        }))
    status = str(run_json.get("status") or "")
    if not seen.get("ended") and status in _TERMINAL_STATUSES:
        start, end = parse_ts(run_json.get("start_time")), parse_ts(run_json.get("end_time"))
        duration = None
        if start and end:
            duration = round((datetime.fromisoformat(end.replace("Z", "+00:00"))
                              - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds())
        out.append(("scan_ended", {
            "auth_mode": run_json.get("auth_mode") or "api_key", "exit_reason": status, "duration_seconds": duration,
            "vulnerabilities_total": sum(finding_counts.get(k, 0) for k in SEVERITIES),
            **{f"vulnerabilities_{k}": finding_counts.get(k, 0) for k in SEVERITIES},
            "llm_requests": int(usage.get("requests") or 0), "llm_input_tokens": int(usage.get("input_tokens") or 0),
            "llm_output_tokens": int(usage.get("output_tokens") or 0), "llm_tokens": int(usage.get("total_tokens") or 0),
            "llm_cost": float(usage.get("cost") or 0.0),
            **({"llm_providers": sorted(usage["providers"])} if isinstance(usage.get("providers"), dict) and usage["providers"] else {}),
        }))
    return out
