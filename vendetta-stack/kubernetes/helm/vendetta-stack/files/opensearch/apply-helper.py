#!/usr/bin/env python3
"""JSON helper for apply.sh (python3 standard library only).

The pinned OpenSearch image ships bash, curl and python3 but no jq, so apply.sh
delegates every JSON operation here. Commands read the JSON document to
inspect on stdin and write the result to stdout.

  body KIND FILE REPLICAS   final request body: replica rewrite + stack marker
  marker KIND               marker stored in a body or in a GET response
  get PATH                  value at a/b/0/c (strings raw, others compact JSON)
  settings-match FILE       exit 0 when every persistent setting of FILE is set
  ism-sig                   [[index_patterns, priority]...] of an ISM policy
  repo-path                 first path.repo of a _nodes/settings response
  repo-body LOCATION        body of the fs snapshot repository
  write-indices             number of indices flagged is_write_index (_alias)
  setting-missing KEY VALUE number of indices of a flat _settings response whose KEY differs from VALUE
  validate KIND FILE        structural check, prints a one-line description
"""
import hashlib
import json
import sys

KINDS = ("template", "pipeline", "ism")
MARK_PREFIX = "[stack-sha256:"
MARK_SUFFIX = "]"


def load_file(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def compact(doc):
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def digest(doc):
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def clamp_replicas(node, limit):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "replica_count" and isinstance(value, dict):
                current = value.get("number_of_replicas")
                if isinstance(current, int) and current > limit:
                    value["number_of_replicas"] = limit
            else:
                clamp_replicas(value, limit)
    elif isinstance(node, list):
        for item in node:
            clamp_replicas(item, limit)


def cmd_body(kind, path, replicas):
    doc = load_file(path)
    if replicas != "keep":
        count = int(replicas)
        if kind == "template":
            settings = doc.setdefault("template", {}).setdefault("settings", {})
            settings["index.number_of_replicas"] = count
        elif kind == "ism":
            clamp_replicas(doc, count)
    marker = digest(doc)
    if kind == "template":
        doc.setdefault("_meta", {})["stack_sha256"] = marker
    elif kind == "pipeline":
        doc["description"] = "%s %s%s%s" % (doc.get("description", ""), MARK_PREFIX, marker, MARK_SUFFIX)
    else:
        policy = doc["policy"]
        policy["description"] = "%s %s%s%s" % (policy.get("description", ""), MARK_PREFIX, marker, MARK_SUFFIX)
    print(compact(doc))


def description_marker(text):
    start = (text or "").rfind(MARK_PREFIX)
    if start < 0:
        return ""
    start += len(MARK_PREFIX)
    end = text.find(MARK_SUFFIX, start)
    return text[start:end] if end > start else ""


def cmd_marker(kind):
    doc = json.load(sys.stdin)
    if kind == "template":
        if "index_templates" in doc:
            doc = doc["index_templates"][0]["index_template"]
        print((doc.get("_meta") or {}).get("stack_sha256", ""))
    elif kind == "pipeline":
        if "processors" not in doc and len(doc) == 1:
            doc = next(iter(doc.values()))
        print(description_marker(doc.get("description", "")))
    else:
        print(description_marker(doc.get("policy", {}).get("description", "")))


def cmd_get(path):
    value = json.load(sys.stdin)
    for part in [p for p in path.split("/") if p != ""]:
        if isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError):
                return
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return
    if isinstance(value, str):
        print(value)
    elif isinstance(value, bool):
        print("true" if value else "false")
    else:
        print(compact(value))


def normalise(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def cmd_settings_match(path):
    desired = load_file(path).get("persistent", {})
    current = json.load(sys.stdin).get("persistent", {})
    for key, value in desired.items():
        if key not in current or normalise(current[key]) != normalise(value):
            return 1
    return 0


def cmd_ism_sig():
    doc = json.load(sys.stdin)
    templates = doc.get("policy", {}).get("ism_template") or []
    print(compact([[t.get("index_patterns"), t.get("priority")] for t in templates]))


def cmd_repo_path():
    doc = json.load(sys.stdin)
    for node in (doc.get("nodes") or {}).values():
        settings = node.get("settings") or {}
        value = (settings.get("path") or {}).get("repo", settings.get("path.repo"))
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, str) and value:
            print(value)
            return


def cmd_repo_body(location):
    print(compact({"type": "fs", "settings": {"location": location, "compress": True}}))


def cmd_write_indices():
    doc = json.load(sys.stdin)
    count = 0
    for entry in doc.values():
        for alias in (entry.get("aliases") or {}).values():
            if alias.get("is_write_index") is True:
                count += 1
    print(count)


def cmd_setting_missing(key, want):
    doc = json.load(sys.stdin)
    missing = 0
    for entry in doc.values():
        if (entry.get("settings") or {}).get(key) != want:
            missing += 1
    print(missing)


def check_ism(doc):
    policy = doc["policy"]
    states = policy["states"]
    names = [state["name"] for state in states]
    if len(set(names)) != len(names):
        raise ValueError("duplicate state names")
    if policy["default_state"] not in names:
        raise ValueError("default_state is not a state")
    for state in states:
        for transition in state.get("transitions", []):
            if transition["state_name"] not in names:
                raise ValueError("transition to unknown state %s" % transition["state_name"])
    return "%d states, ism_template=%s" % (
        len(states),
        compact([[t["index_patterns"], t.get("priority")] for t in policy.get("ism_template", [])]),
    )


def cmd_validate(kind, path):
    doc = load_file(path)
    if kind == "template":
        if not doc.get("index_patterns") or "template" not in doc:
            raise ValueError("index_patterns/template missing")
        print("patterns=%s priority=%s" % (compact(doc["index_patterns"]), doc.get("priority")))
    elif kind == "pipeline":
        if not doc.get("processors") or not doc.get("on_failure"):
            raise ValueError("processors/on_failure missing")
        print("%d processors, on_failure=%d" % (len(doc["processors"]), len(doc["on_failure"])))
    else:
        print(check_ism(doc))


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    if cmd in ("body", "marker", "validate") and (not args or args[0] not in KINDS):
        sys.stderr.write("apply-helper: KIND must be one of %s\n" % ", ".join(KINDS))
        return 2
    try:
        if cmd == "body":
            cmd_body(args[0], args[1], args[2])
        elif cmd == "marker":
            cmd_marker(args[0])
        elif cmd == "get":
            cmd_get(args[0])
        elif cmd == "settings-match":
            return cmd_settings_match(args[0])
        elif cmd == "ism-sig":
            cmd_ism_sig()
        elif cmd == "repo-path":
            cmd_repo_path()
        elif cmd == "repo-body":
            cmd_repo_body(args[0])
        elif cmd == "write-indices":
            cmd_write_indices()
        elif cmd == "setting-missing":
            cmd_setting_missing(args[0], args[1])
        elif cmd == "validate":
            cmd_validate(args[0], args[1])
        else:
            sys.stderr.write("apply-helper: unknown command %s\n" % cmd)
            return 2
    except (ValueError, KeyError, IndexError, OSError) as exc:
        sys.stderr.write("apply-helper: %s: %s\n" % (cmd, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
