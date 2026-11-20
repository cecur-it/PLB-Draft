# Normalizes the Errow finding shapes the feedback loop receives into flat records.
# Traces: CONTRACT §15 (shipper `findings` record = raw SARIF result + `rule`), §4.1 (normalized alert), SARIF 2.1.0.
# Accepted per input document (NDJSON stream, JSON array, or one document):
#   1. SARIF log      {"runs":[{"tool":{"driver":{"rules":[..]}},"results":[..]}]}   (run name from --arg run)
#   2. shipper record SARIF result keys at top level + "rule" + "run"/"doc_id"
#   3. Vendetta alert normalized alert with errow.fingerprint (sarif-to-vendetta-alert output)
# Anything else becomes {"invalid": "<reason>"} so the caller can count and report it.

def docs: if type == "array" then .[] | docs else . end;

def hostof:
  (. // "")
  | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "")
  | sub("^[^@/]*@"; "")
  | split("/")[0]
  | if startswith("[") then (split("]")[0] | ltrimstr("[")) else split(":")[0] end;

def level_severity: ({"error": "high", "warning": "medium", "note": "low", "none": "info"}[(. // "")] // "medium");

def severity_or_null:
  ((. // "") | tostring | ascii_downcase) as $s
  | if (["critical", "high", "medium", "low", "info"] | index($s)) then $s else null end;

def clip($n): tostring | if length > $n then .[0:$n] else . end;

def from_result($run):
  (.properties.errow // {}) as $e
  | ((.message.text // "") | tostring) as $text
  | ($e.target // "") as $target
  | {
      fingerprint: (.partialFingerprints.primaryLocationLineHash // ""),
      doc_id: (.doc_id // ""),
      run: ((.run // $run) // ""),
      rule_id: (.ruleId // ""),
      severity: (($e.severity | severity_or_null) // (.level | level_severity)),
      cwe: ($e.cwe // ""),
      cve: ($e.cve // ""),
      cvss: ($e.cvss // null),
      title: ($text | split("\n")[0] | clip(200)),
      description: ($text | clip(2000)),
      remediation: (($e.remediation_steps // "") | clip(1000)),
      target: $target,
      host: ($target | hostof),
      endpoint: ($e.endpoint // "")
    };

def from_alert($run):
  .errow as $e
  | ($e.target // "") as $target
  | {
      fingerprint: ($e.fingerprint // ""),
      doc_id: (.id // ""),
      run: (($e.run // $run) // ""),
      rule_id: ($e.sarif_rule_id // .rule.id // ""),
      severity: ((.severity | severity_or_null) // "medium"),
      cwe: ($e.cwe // ""),
      cve: ($e.cve // ""),
      cvss: ($e.cvss // null),
      title: ((.rule.description // "") | clip(200)),
      description: ((.full_log // "") | clip(2000)),
      remediation: ((.recommended_action // "") | clip(1000)),
      target: $target,
      host: (if $target != "" then ($target | hostof) else (.agent.name // "") end),
      endpoint: ($e.endpoint // "")
    };

docs
| if type != "object" then {invalid: "record is not a JSON object"}
  elif has("runs") then
    (.runs[]? | .results[]? | from_result($run))
  elif has("ruleId") then
    from_result($run)
  elif ((.errow? | type) == "object") and (.errow.fingerprint? != null) then
    from_alert($run)
  else
    {invalid: "unrecognised record shape (expected SARIF log, shipper finding or Vendetta alert with errow.fingerprint)"}
  end
