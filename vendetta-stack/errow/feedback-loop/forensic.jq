# forensic.jq - request builders and text hygiene for the advisory llm-gateway POST /forensic calls.
# Traces: CONTRACT §4.2 (AIIncidentAnalysis, proposedDetectionRule/proposedRemediation), §4.4 (/forensic), §6 (feedback loop),
#         PROMPT §2.5 (LLM steps of the bidirectional loop). Used with: jq -L <this dir> 'include "forensic"; ...'
# Every request is built from a WHITELIST of the normalized record (normalize-finding.jq output), never from the raw SARIF
# result, so proof-of-concept bodies (properties.errow.poc_*), payloads and tool output cannot reach the gateway. Strings are
# additionally scrubbed for credential shapes before they leave the host.

def redact:
  gsub("-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*(-----END [A-Z ]*PRIVATE KEY-----)?"; "[REDACTED]")
  | gsub("(?<k>bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}"; "\(.k) [REDACTED]"; "i")
  | gsub("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*"; "[REDACTED]")
  | gsub("(AKIA|ASIA)[0-9A-Z]{16}"; "[REDACTED]")
  | gsub("sk-[A-Za-z0-9_-]{16,}"; "[REDACTED]")
  | gsub("(?<k>(pass(word|wd)?|secret|token|api[_-]?key|authorization)[\"']?\\s*[=:]\\s*[\"']?)[^\\s,;\"']{3,}"; "\(.k)[REDACTED]"; "i");

def redact_all: walk(if type == "string" then redact else . end);

def cap($n): if type == "string" and length > $n then .[0:$n] else . end;

# model output / free text: control characters (except \n and \t) removed, length capped
def clean($n): (. // "") | tostring | gsub("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]"; "") | cap($n);

def compact: with_entries(select(.value != null and .value != ""));

# single-line, trimmed, capped (MITRE labels, engine names)
def oneline($n): (. // "") | tostring | gsub("\\s+"; " ") | sub("^ +"; "") | sub(" +$"; "") | .[0:$n];

# normalized finding (fingerprint, run, rule_id, severity, cwe, cve, cvss, title, description, remediation, target, endpoint)
def finding_request:
  {id: .fingerprint,
   incident_id: ("ERW-" + .fingerprint[0:12]),
   source: {system: "errow-feedback", stream: "errow.findings"},
   rule: ({id: .rule_id, description: .title} | compact),
   severity: .severity,
   title: .title,
   description: .description,
   remediation: .remediation,
   cwe: .cwe, cve: .cve, cvss: .cvss,
   target: .target, endpoint: .endpoint,
   errow: ({fingerprint: .fingerprint, run: .run, target: .target, endpoint: .endpoint, cwe: .cwe, cve: .cve} | compact)}
  | compact
  | redact_all;

# normalized threat-model entry (run, identity, doc_id, target, content, amendments[])
def threat_request:
  {id: .doc_id,
   incident_id: ("tm-" + .doc_id[0:12]),
   source: {system: "errow-feedback", stream: "errow.threat_models"},
   title: ("Errow threat model for " + .target),
   target: .target,
   description: ([.content] + (.amendments // []) | map(select(. != "")) | join("\n\n") | cap(6000)),
   errow: ({run: .run, target: .target} | compact)}
  | compact
  | redact_all;

# SCA alert payload (already stripped of .errow and clipped by vendetta-to-errow.sh)
def alert_request: del(.errow) | redact_all;

# --- threat-model input normalisation ---------------------------------------------------------------------------------
# Accepts shipper `threat_models` records (NDJSON/array) and the raw errow_runs/<run>/.state/threat_models.json map.
def is_entry: type == "object" and ((.content? | type) == "string");

def tm_norm($run; $identity):
  {run: ((.run // $run) // ""),
   identity: (($identity // .identity // .target // "") | tostring),
   doc_id: ((.doc_id // "") | tostring),
   target: (((.target // $identity // .identity // "") | tostring) | clean(200)),
   written_by: ((.written_by // "") | tostring | clean(80)),
   content: (.content | clean(20000)),
   amendments: [(.amendments // [])[]? | select(type == "object") | (.content // "") | clean(4000)]};

def threat_entries($run):
  (if type == "array" then .[] else . end)
  | if type != "object" then {invalid: "record is not a JSON object"}
    elif is_entry then tm_norm($run; null)
    elif ([.[]? | select(is_entry)] | length) > 0 then
      to_entries[] | . as $e | select($e.value | is_entry) | $e.value | tm_norm($run; $e.key)
    else {invalid: "unrecognised threat-model record (expected shipper threat_models records or a threat_models.json map)"}
    end;
