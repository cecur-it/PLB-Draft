#!/usr/bin/env python3
"""Generate dashboards/saved-objects.ndjson (OpenSearch Dashboards 2.17 import format).

The NDJSON is a build artefact of this file: edit here, then run
    python3 dashboards/build_saved_objects.py          # rewrites saved-objects.ndjson
    python3 dashboards/build_saved_objects.py --check  # exit 1 when the file is stale
Standard library only; every reference between objects is verified before writing.
"""
import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE / "saved-objects.ndjson"
UPDATED_AT = "2026-11-12T00:00:00.000Z"
VERSION = "WzEsMV0="
DEFAULT_INDEX = "vs-ip-vendetta-alerts"

# (id suffix, index pattern, time field): one per index family of CONTRACT s3.
INDEX_PATTERNS = [
    ("vendetta-alerts", "vendetta-alerts-*", "@timestamp"),
    ("errow-findings", "errow-findings-*", "@timestamp"),
    ("errow-runs", "errow-runs-*", "@timestamp"),
    ("errow-transcripts", "errow-transcripts-*", "@timestamp"),
    ("errow-threat-models", "errow-threat-models-*", "@timestamp"),
    ("errow-coverage", "errow-coverage-*", "@timestamp"),
    ("errow-llm-logs", "errow-llm-logs-*", "@timestamp"),
    ("errow-mcp", "errow-mcp-*", "@timestamp"),
    ("errow-runtime", "errow-runtime-*", "@timestamp"),
    ("errow-proxy", "errow-proxy-*", "@timestamp"),
    ("errow-tooling", "errow-tooling-*", "@timestamp"),
    ("errow-tui", "errow-tui-*", "@timestamp"),
    ("errow-cloud", "errow-cloud-*", "@timestamp"),
    ("errow-telemetry", "errow-telemetry-*", "@timestamp"),
    ("errow-agent-state", "errow-agent-state-*", "@timestamp"),
    ("errow-viewer", "errow-viewer-*", "@timestamp"),
    ("errow-report-artifacts", "errow-report-artifacts-*", "@timestamp"),
    ("errow-sarif", "errow-sarif-*", "@timestamp"),
    ("cs3-ai-inference", "cs3-ai-inference-*", "@timestamp"),
    ("cs3-ai-audit", "cs3-ai-audit-*", "@timestamp"),
]

IP_ALERTS = "vs-ip-vendetta-alerts"
IP_FINDINGS = "vs-ip-errow-findings"
IP_INFERENCE = "vs-ip-cs3-ai-inference"
IP_AUDIT = "vs-ip-cs3-ai-audit"

SEARCH_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"


def dumps(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def envelope(obj_id, obj_type, attributes, references, migration):
    return {
        "id": obj_id,
        "type": obj_type,
        "attributes": attributes,
        "references": references,
        "migrationVersion": migration,
        "updated_at": UPDATED_AT,
        "version": VERSION,
    }


def search_source(query):
    return dumps(
        {"query": {"language": "kuery", "query": query}, "filter": [], "indexRefName": SEARCH_REF}
    )


def index_pattern(suffix, title, time_field):
    return envelope(
        "vs-ip-" + suffix,
        "index-pattern",
        {"title": title, "timeFieldName": time_field},
        [],
        {"index-pattern": "7.6.0"},
    )


def saved_search(obj_id, title, description, ip_id, query, columns, sort_field="@timestamp"):
    attrs = {
        "title": title,
        "description": description,
        "hits": 0,
        "columns": columns,
        "sort": [[sort_field, "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
    }
    refs = [{"name": SEARCH_REF, "type": "index-pattern", "id": ip_id}]
    return envelope(obj_id, "search", attrs, refs, {"search": "7.9.3"})


def visualization(obj_id, title, description, ip_id, query, vis_state):
    attrs = {
        "title": title,
        "visState": dumps(vis_state),
        "uiStateJSON": "{}",
        "description": description,
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
    }
    refs = [{"name": SEARCH_REF, "type": "index-pattern", "id": ip_id}]
    return envelope(obj_id, "visualization", attrs, refs, {"visualization": "7.10.0"})


def count_metric(agg_id="1"):
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def stat_metric(agg_id, kind, field):
    return {"id": agg_id, "enabled": True, "type": kind, "schema": "metric", "params": {"field": field}}


def terms_bucket(agg_id, field, schema, size, order_by="1"):
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": schema,
        "params": {
            "field": field,
            "orderBy": order_by,
            "order": "desc",
            "size": size,
            "otherBucket": False,
            "otherBucketLabel": "Other",
            "missingBucket": False,
            "missingBucketLabel": "Missing",
        },
    }


def pie(title, field, size=10):
    return {
        "title": title,
        "type": "pie",
        "aggs": [count_metric(), terms_bucket("2", field, "segment", size)],
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        },
    }


def table(title, bucket_field, size, extra_metrics=()):
    aggs = [count_metric()]
    aggs.extend(extra_metrics)
    aggs.append(terms_bucket("9", bucket_field, "bucket", size))
    return {
        "title": title,
        "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
        },
    }


def metric_tile(title, kind, field):
    return {
        "title": title,
        "type": "metric",
        "aggs": [stat_metric("1", kind, field)],
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48},
            },
        },
    }


def stacked_over_time(title, group_field):
    return {
        "title": title,
        "type": "histogram",
        "aggs": [
            count_metric(),
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "schema": "segment",
                "params": {
                    "field": "@timestamp",
                    "useNormalizedOpenSearchInterval": True,
                    "scaleMetricValues": False,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {},
                },
            },
            terms_bucket("3", group_field, "group", 6),
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "filter": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Count"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "stacked",
                    "data": {"label": "Count", "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "lineWidth": 2,
                    "showCircles": True,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
        },
    }


def dashboard(obj_id, title, description, panels):
    """panels: list of (type, id, x, y, w, h)."""
    panel_defs = []
    references = []
    for index, (ptype, pid, x, y, w, h) in enumerate(panels):
        panel_defs.append(
            {
                "version": "2.17.1",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(index + 1)},
                "panelIndex": str(index + 1),
                "embeddableConfig": {},
                "panelRefName": "panel_%d" % index,
            }
        )
        references.append({"name": "panel_%d" % index, "type": ptype, "id": pid})
    attrs = {
        "title": title,
        "description": description,
        "hits": 0,
        "panelsJSON": dumps(panel_defs),
        "optionsJSON": dumps({"hidePanelTitles": False, "useMargins": True}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-24h",
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": dumps({"query": {"language": "kuery", "query": ""}, "filter": []})},
    }
    return envelope(obj_id, "dashboard", attrs, references, {"dashboard": "7.9.3"})


def build():
    objects = [index_pattern(*row) for row in INDEX_PATTERNS]

    objects += [
        saved_search(
            "vs-search-alerts-high-critical",
            "Vendetta alerts: high and critical",
            "Every high or critical alert, Wazuh and Errow/AI-derived alike.",
            IP_ALERTS,
            "severity:high or severity:critical",
            ["severity", "rule.id", "rule.description", "agent.name", "source.system", "location"],
        ),
        saved_search(
            "vs-search-errow-high-findings",
            "Errow findings: high and critical",
            "Raw Errow findings (SARIF results) rated high or critical.",
            IP_FINDINGS,
            "severity:high or severity:critical",
            ["severity", "cwe", "rule.name", "properties.errow.target", "properties.errow.endpoint", "properties.errow.cvss"],
        ),
        saved_search(
            "vs-search-ai-fallbacks",
            "LLM inference: heuristic fallbacks",
            "Requests answered by Cecur Heuristics because the model backend was unavailable or rejected.",
            IP_INFERENCE,
            "fallback:true",
            ["role", "engine_used", "fallback_reason", "alert_id", "latency_ms"],
        ),
        saved_search(
            "vs-search-audit-guardrail",
            "LLM audit: guardrail violations and denied tool calls",
            "Hash-chained cs3-ai-audit events where the guardrail failed or a tool call was not allowed.",
            IP_AUDIT,
            "guardrail.passed:false or decision:deny or decision:denied",
            ["event_type", "tool", "decision", "violations", "chain_id", "seq"],
        ),
    ]

    objects += [
        visualization("vs-vis-alerts-by-severity", "Alerts by severity", "", IP_ALERTS, "", pie("Alerts by severity", "severity")),
        visualization("vs-vis-alerts-over-time", "Alerts over time by severity", "", IP_ALERTS, "", stacked_over_time("Alerts over time by severity", "severity")),
        visualization("vs-vis-alerts-by-source", "Alerts by source system", "", IP_ALERTS, "", pie("Alerts by source system", "source.system")),
        visualization(
            "vs-vis-alerts-top-rules",
            "Top rules by alert count",
            "",
            IP_ALERTS,
            "",
            table("Top rules by alert count", "rule.id", 15, [stat_metric("2", "max", "rule.level")]),
        ),
        visualization("vs-vis-alerts-mitre-tactics", "ATT&CK tactics", "", IP_ALERTS, "", table("ATT&CK tactics", "mitre.tactic", 15)),
        visualization("vs-vis-alerts-top-agents", "Noisiest agents", "", IP_ALERTS, "", table("Noisiest agents", "agent.name", 15)),
        visualization("vs-vis-alerts-ai-role", "AI-enriched alerts by role", "", IP_ALERTS, "ai.role:*", pie("AI-enriched alerts by role", "ai.role")),
        visualization("vs-vis-errow-findings-by-severity", "Errow findings by severity", "", IP_FINDINGS, "", pie("Errow findings by severity", "severity")),
        visualization("vs-vis-errow-findings-by-cwe", "Errow findings by CWE", "", IP_FINDINGS, "", table("Errow findings by CWE", "cwe", 25)),
        visualization("vs-vis-errow-findings-by-owasp", "Errow findings by OWASP Top 10:2021", "", IP_FINDINGS, "", pie("Errow findings by OWASP Top 10:2021", "owasp")),
        visualization("vs-vis-errow-findings-over-time", "Errow findings over time", "", IP_FINDINGS, "", stacked_over_time("Errow findings over time", "severity")),
        visualization(
            "vs-vis-errow-findings-top-targets",
            "Targets by finding count",
            "",
            IP_FINDINGS,
            "",
            table("Targets by finding count", "properties.errow.target", 15, [stat_metric("2", "max", "properties.errow.cvss")]),
        ),
        visualization("vs-vis-errow-findings-max-cvss", "Highest CVSS", "", IP_FINDINGS, "", metric_tile("Highest CVSS", "max", "properties.errow.cvss")),
        visualization("vs-vis-ai-by-engine", "Inferences by engine", "", IP_INFERENCE, "", pie("Inferences by engine", "engine_used")),
        visualization("vs-vis-ai-fallback-ratio", "Fallback ratio", "", IP_INFERENCE, "", pie("Fallback ratio", "fallback")),
        visualization("vs-vis-ai-verdicts", "Verdicts", "", IP_INFERENCE, "", pie("Verdicts", "verdict")),
        visualization(
            "vs-vis-ai-latency-gpu",
            "Latency, GPU seconds and tokens by role",
            "",
            IP_INFERENCE,
            "",
            table(
                "Latency, GPU seconds and tokens by role",
                "role",
                10,
                [
                    stat_metric("2", "avg", "latency_ms"),
                    stat_metric("3", "sum", "gpu_seconds"),
                    stat_metric("4", "sum", "tokens_in"),
                    stat_metric("5", "sum", "tokens_out"),
                ],
            ),
        ),
        visualization("vs-vis-ai-over-time", "Inferences over time by role", "", IP_INFERENCE, "", stacked_over_time("Inferences over time by role", "role")),
        visualization("vs-vis-audit-events", "Audit events by type", "", IP_AUDIT, "", table("Audit events by type", "event_type", 15)),
        visualization("vs-vis-audit-decisions", "Audit decisions", "", IP_AUDIT, "decision:*", pie("Audit decisions", "decision")),
    ]

    objects += [
        dashboard(
            "vs-dash-vendetta-alerts-overview",
            "Vendetta alerts overview",
            "Alert volume, severity, sources, ATT&CK tactics and AI enrichment across vendetta-alerts-*.",
            [
                ("visualization", "vs-vis-alerts-by-severity", 0, 0, 16, 14),
                ("visualization", "vs-vis-alerts-by-source", 16, 0, 16, 14),
                ("visualization", "vs-vis-alerts-ai-role", 32, 0, 16, 14),
                ("visualization", "vs-vis-alerts-over-time", 0, 14, 48, 15),
                ("visualization", "vs-vis-alerts-top-rules", 0, 29, 24, 15),
                ("visualization", "vs-vis-alerts-mitre-tactics", 24, 29, 24, 15),
                ("visualization", "vs-vis-alerts-top-agents", 0, 44, 48, 14),
                ("search", "vs-search-alerts-high-critical", 0, 58, 48, 18),
            ],
        ),
        dashboard(
            "vs-dash-errow-findings",
            "Errow findings by severity and CWE",
            "Offensive-platform findings: severity, CWE, OWASP Top 10:2021 category, targets and CVSS.",
            [
                ("visualization", "vs-vis-errow-findings-by-severity", 0, 0, 16, 14),
                ("visualization", "vs-vis-errow-findings-by-owasp", 16, 0, 20, 14),
                ("visualization", "vs-vis-errow-findings-max-cvss", 36, 0, 12, 14),
                ("visualization", "vs-vis-errow-findings-over-time", 0, 14, 48, 15),
                ("visualization", "vs-vis-errow-findings-by-cwe", 0, 29, 24, 17),
                ("visualization", "vs-vis-errow-findings-top-targets", 24, 29, 24, 17),
                ("search", "vs-search-errow-high-findings", 0, 46, 48, 18),
            ],
        ),
        dashboard(
            "vs-dash-llm-audit-inference",
            "LLM audit and inference",
            "Sovereign LLM tier: engines, fallbacks, latency/GPU cost, verdicts and the hash-chained audit trail.",
            [
                ("visualization", "vs-vis-ai-by-engine", 0, 0, 16, 14),
                ("visualization", "vs-vis-ai-fallback-ratio", 16, 0, 16, 14),
                ("visualization", "vs-vis-ai-verdicts", 32, 0, 16, 14),
                ("visualization", "vs-vis-ai-over-time", 0, 14, 48, 15),
                ("visualization", "vs-vis-ai-latency-gpu", 0, 29, 48, 14),
                ("visualization", "vs-vis-audit-events", 0, 43, 24, 15),
                ("visualization", "vs-vis-audit-decisions", 24, 43, 24, 15),
                ("search", "vs-search-ai-fallbacks", 0, 58, 48, 16),
                ("search", "vs-search-audit-guardrail", 0, 74, 48, 16),
            ],
        ),
    ]
    return objects


def verify(objects):
    ids = {}
    for obj in objects:
        key = (obj["type"], obj["id"])
        if key in ids:
            raise SystemExit("duplicate saved object %s/%s" % key)
        ids[key] = obj
    for obj in objects:
        for ref in obj["references"]:
            if (ref["type"], ref["id"]) not in ids:
                raise SystemExit("%s/%s references missing %s/%s" % (obj["type"], obj["id"], ref["type"], ref["id"]))
    if ("index-pattern", DEFAULT_INDEX) not in ids:
        raise SystemExit("default index pattern %s is not defined" % DEFAULT_INDEX)
    for obj in objects:
        if obj["type"] in ("visualization", "dashboard"):
            json.loads(obj["attributes"].get("visState") or obj["attributes"]["panelsJSON"])


def render(objects):
    lines = [dumps(obj) for obj in objects]
    lines.append(dumps({"exportedCount": len(objects), "missingRefCount": 0, "missingReferences": []}))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when saved-objects.ndjson is stale")
    parser.add_argument("--out", default=str(TARGET), help="output file (default: %(default)s)")
    args = parser.parse_args()
    objects = build()
    verify(objects)
    text = render(objects)
    out = pathlib.Path(args.out)
    if args.check:
        if not out.exists() or out.read_text(encoding="utf-8") != text:
            print("%s is stale: run dashboards/build_saved_objects.py" % out, file=sys.stderr)
            return 1
        print("%s is up to date (%d objects)" % (out, len(objects)))
        return 0
    out.write_text(text, encoding="utf-8")
    print("wrote %s (%d objects)" % (out, len(objects)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
