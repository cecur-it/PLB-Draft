#!/usr/bin/env python3
# Traces: PROMPT §5 Observability (dashboards as code), CONTRACT §3 (index prefixes), §4.4 (metric names)
"""Offline consistency checks for grafana/dashboards/*.json against the rest of the stack.

* structure: uid/title/schemaVersion, unique uids and panel ids, grid inside 24 columns without overlap, /d/<uid> links resolve
* datasources: every panel/target/variable datasource uid is provisioned in provisioning/datasources/datasources.yml
* Prometheus: every metric name is known (known-metrics.txt, llm-gateway/meter.py) and every expr parses (rules file for promtool)
* OpenSearch: every field used in aggregations/queries exists in the matching index template; terms aggregations are not on text fields
Stdlib only. Usage: check_dashboards.py [--rules-out FILE]
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STACK = os.path.dirname(ROOT)
TEMPLATES = os.path.join(STACK, "opensearch", "index-templates")
ES_TEMPLATE = {
    "cs3-os-vendetta-alerts": "vendetta-alerts-template.json",
    "cs3-os-errow-findings": "errow-findings-template.json",
    "cs3-os-errow-runs": "errow-runs-template.json",
    "cs3-os-errow-llm": "errow-generic-template.json",
    "cs3-os-errow-mcp": "errow-generic-template.json",
    "cs3-os-ai-inference": "cs3-ai-inference-template.json",
    "cs3-os-ai-audit": "cs3-ai-audit-template.json",
}
METRIC_RE = re.compile(r"\b((?:fluentbit|fluentd|cs3|llm_gateway|ollama)_[A-Za-z0-9_]+)")
SUFFIX_RE = re.compile(r"_(bucket|count|sum)$")
TERMS_OK = {"keyword", "ip", "boolean", "long", "integer", "double", "float", "date"}

passed = failed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  PASS  {msg}")


def bad(msg):
    global failed
    failed += 1
    print(f"  FAIL  {msg}", file=sys.stderr)


def check(cond, msg):
    ok(msg) if cond else bad(msg)


def provisioned_uids():
    text = open(os.path.join(ROOT, "provisioning", "datasources", "datasources.yml"), encoding="utf-8").read()
    return set(re.findall(r"^\s+uid:\s*(\S+)", text, re.M))


def gateway_metrics():
    path = os.path.join(STACK, "llm-gateway", "meter.py")
    if not os.path.isfile(path):
        return None
    return set(re.findall(r'"((?:llm_gateway|ollama)_[a-z0-9_]+)"', open(path, encoding="utf-8").read()))


def known_metrics():
    lines = open(os.path.join(HERE, "known-metrics.txt"), encoding="utf-8").read().splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def mapping(uid, cache={}):
    if uid not in cache:
        path = os.path.join(TEMPLATES, ES_TEMPLATE[uid])
        cache[uid] = json.load(open(path, encoding="utf-8"))["template"]["mappings"]["properties"] if os.path.isfile(path) else None
    return cache[uid]


def resolve(props, dotted):
    node = {"properties": props}
    for part in dotted.split("."):
        children = node.get("properties")
        if children is None:
            return {"type": node.get("type", "object"), "dynamic": True}
        if part not in children:
            return None
        node = children[part]
    return node


def walk_panels(panels):
    for p in panels:
        yield p
        yield from walk_panels(p.get("panels", []))


def ds_uids(obj):
    ds = obj.get("datasource")
    if isinstance(ds, dict) and "uid" in ds:
        yield ds["uid"]


def to_promql(expr):
    expr = expr.replace("$__rate_interval", "5m").replace("$__interval", "1m").replace("$__range", "6h")
    return re.sub(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", ".*", expr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rules-out", help="write every Prometheus expression as a recording-rule file for promtool check rules")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(ROOT, "dashboards", "*.json")))
    check(len(files) == 4, f"4 dashboards present ({', '.join(os.path.basename(f) for f in files)})")
    dashboards = {f: json.load(open(f, encoding="utf-8")) for f in files}
    uids = [d.get("uid") for d in dashboards.values()]
    check(len(set(uids)) == len(uids) and all(u and len(u) <= 40 for u in uids), "dashboard uids are unique and <= 40 chars")

    provisioned = provisioned_uids()
    known = known_metrics()
    gateway = gateway_metrics()
    allknown = known | (gateway or set())
    if gateway is None:
        print("  WARN  llm-gateway/meter.py not found: gateway metric names are not cross-checked")
    rules = []

    for path, dash in dashboards.items():
        name = os.path.basename(path)
        check(dash.get("schemaVersion") == 39 and dash.get("title") and dash.get("panels"), f"{name}: schemaVersion 39, title and panels present")
        panels = list(walk_panels(dash["panels"]))
        ids = [p["id"] for p in panels]
        check(len(set(ids)) == len(ids), f"{name}: panel ids are unique")

        top = [p for p in dash["panels"] if p.get("type") != "row"]
        boxes = [(p["gridPos"]["x"], p["gridPos"]["y"], p["gridPos"]["w"], p["gridPos"]["h"]) for p in top]
        inside = all(x >= 0 and w > 0 and x + w <= 24 for x, _, w, _ in boxes)
        overlap = any(
            a is not b and a[0] < b[0] + b[2] and b[0] < a[0] + a[2] and a[1] < b[1] + b[3] and b[1] < a[1] + a[3]
            for a in boxes for b in boxes
        )
        check(inside and not overlap, f"{name}: {len(top)} panels fit the 24-column grid without overlap")

        links_ok = all(
            (m := re.match(r"^/d/([a-z0-9-]+)$", link["url"])) is None or m.group(1) in uids
            for link in dash.get("links", [])
        )
        check(links_ok, f"{name}: dashboard links resolve")

        used = set()
        for var in dash.get("templating", {}).get("list", []):
            used.update(ds_uids(var))
        for p in panels:
            used.update(ds_uids(p))
            for t in p.get("targets", []):
                used.update(ds_uids(t))
        check(used <= provisioned, f"{name}: datasource uids {sorted(used)} are provisioned" + ("" if used <= provisioned else f" (missing {sorted(used - provisioned)})"))

        metrics, es_problems, es_checked = set(), [], 0
        for var in dash.get("templating", {}).get("list", []):
            metrics.update(METRIC_RE.findall(var.get("definition", "")))
        for p in panels:
            for t in p.get("targets", []):
                if "expr" in t:
                    metrics.update(METRIC_RE.findall(t["expr"]))
                    rules.append((f"{name}#{p['id']}{t['refId']}", to_promql(t["expr"])))
                    continue
                uid = t.get("datasource", {}).get("uid")
                props = mapping(uid) if uid in ES_TEMPLATE else None
                if props is None:
                    continue
                fields = [m["field"] for m in t.get("metrics", []) if "field" in m]
                fields += [b["field"] for b in t.get("bucketAggs", []) if "field" in b]
                fields += re.findall(r"(?:^|[\s(])(?:_exists_:)?([A-Za-z@][\w@]*(?:\.[\w-]+)*):", t.get("query", ""))
                fields = [f for f in fields if f != "_exists_"]
                for f in fields:
                    es_checked += 1
                    node = resolve(props, f)
                    if node is None:
                        es_problems.append(f"{p['id']}:{f} not in template")
                for b in t.get("bucketAggs", []):
                    if b["type"] == "terms":
                        node = resolve(props, b["field"])
                        if node is not None and node.get("type") not in TERMS_OK and not node.get("dynamic"):
                            es_problems.append(f"{p['id']}:terms on {b['field']} ({node.get('type', 'object')})")
        unknown = sorted(m for m in metrics if m not in allknown and SUFFIX_RE.sub("", m) not in allknown)
        if gateway is None:
            unknown = [m for m in unknown if not m.startswith(("llm_gateway_", "ollama_"))]
        check(not unknown, f"{name}: {len(metrics)} metric names exist" + (f" (unknown: {unknown})" if unknown else ""))
        check(not es_problems, f"{name}: {es_checked} OpenSearch field references match the index templates" + (f" ({es_problems})" if es_problems else ""))

    if args.rules_out:
        doc = {"groups": [{"name": "dashboard-exprs", "rules": [{"record": f"dash:expr{i}", "expr": e} for i, (_, e) in enumerate(rules)]}]}
        json.dump(doc, open(args.rules_out, "w", encoding="utf-8"))
    print(f"SUMMARY pass={passed} fail={failed} promql_exprs={len(rules)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
