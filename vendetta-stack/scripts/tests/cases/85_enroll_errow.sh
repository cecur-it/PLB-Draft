# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted awk/jq programs are intentional
# Cases: enroll-errow.sh against an mTLS mock of errow-mcp (:9103) and a TLS mock of the Errow cloud.

# policy_tools_json <policy.yaml> — keys under `tools:` as a JSON array (same rule the script applies)
policy_tools_json() {
  awk '/^tools:/{t=1; next} /^[A-Za-z_]+:/{t=0} t && /^  [A-Za-z0-9_]+:/{k=$1; sub(/:$/,"",k); print k}' "$1" | sort | jq -R . | jq -sc .
}

# ee_spec <out.json> — EE_TOOLS (JSON array, default = policy), EE_HEALTH (HTTP status), EE_INIT (0 = no initialize method)
ee_spec() {
  local out=$1 tools=${EE_TOOLS:-}
  [[ -n "$tools" ]] || tools="$(policy_tools_json "$TREE/llm-gateway/mcp_policy.yaml")"
  jq -n --arg pki "$TREE/pki" --argjson tools "$tools" --argjson health "${EE_HEALTH:-200}" --arg init "${EE_INIT:-1}" '
    {listeners: [
      {name: "mcp", tls: {cert: "\($pki)/errow-mcp.crt", key: "\($pki)/errow-mcp.key", ca: "\($pki)/ca.crt", require_client_cert: true},
       routes: {"GET /health": {status: $health, json: {status: (if $health == 200 then "ok" else "unavailable" end)}},
                "POST /mcp": {jsonrpc: ({"tools/list": {tools: ($tools | map({name: ., description: "d", inputSchema: {type: "object"}}))}}
                  + (if $init == "1" then {initialize: {protocolVersion: "2025-03-26", capabilities: {}, serverInfo: {name: "errow-mcp", version: "1.0.0"}}} else {} end))}}},
      {name: "cloud", tls: {cert: "\($pki)/llm-gateway.crt", key: "\($pki)/llm-gateway.key", ca: "\($pki)/ca.crt", require_client_cert: false},
       routes: {"GET /": {status: 200, text: "errow"}}}
    ]}' >"$out"
}

ee_start() { # <mock-name> — sets EE_PID, EE_PORT, EE_CLOUD_PORT
  ee_spec "$WORK/$1.json"
  start_mock "$1" "$WORK/$1.json"
  EE_PID=$MOCK_LAST_PID
  EE_PORT="$(mock_port "$1" mcp)"
  EE_CLOUD_PORT="$(mock_port "$1" cloud)"
}

ee_args() { # <errow-home> — sets EE_ARGS for the running mock
  EE_ARGS=("$S/enroll-errow.sh" --mcp-url "https://errow-mcp:$EE_PORT/mcp" --mcp-resolve "errow-mcp:$EE_PORT:127.0.0.1" --errow-home "$1")
}

case_enroll_errow_validation() {
  local home tok
  new_tree_pki eev || return 1
  home="$WORK/eev-home"
  local base=("$S/enroll-errow.sh" --skip-smoke --no-config --errow-home "$home")
  t_run "--help" 0 "$S/enroll-errow.sh" --help
  out_has "help documents the exit codes" 'Exit codes: 0 ok'
  t_run "unknown option" 2 "${base[@]}" --bogus
  t_run "invalid --name" 2 "${base[@]}" --name 'a b'
  t_run "--mcp-url must be https" 2 "${base[@]}" --mcp-url http://errow-mcp:9103/mcp
  t_run "--mcp-url may not carry credentials" 2 "${base[@]}" --mcp-url 'https://user:pw@errow-mcp:9103/mcp'
  t_run "missing token file" 2 "${base[@]}" --token-file "$WORK/none"

  t_run "valid token, defaults" 0 "${base[@]}"
  out_has "token validated" 'token file valid \(mode 600\)'
  out_has "cloud off by default" 'Errow cloud disabled'
  out_has "empty skeleton is NOT created with --no-config" 'would create the empty targets skeleton'
  check_not "no skeleton written" test -e "$TREE/errow/config/targets.yaml"

  tok="$WORK/eev.tok"
  printf 'too-short' >"$tok"; chmod 600 "$tok"
  t_run "token shorter than 32 chars" 2 "${base[@]}" --token-file "$tok"
  printf '%s %s' "$(printf 'a%.0s' {1..20})" "$(printf 'b%.0s' {1..20})" >"$tok"
  t_run "token containing whitespace" 2 "${base[@]}" --token-file "$tok"
  printf '%s' "$(printf 'k%.0s' {1..40})" >"$tok"; chmod 644 "$tok"
  t_run "world-readable token → policy refusal" 3 "${base[@]}" --token-file "$tok"
  out_has "mode named" 'world-readable \(mode 644\)'
  t_run "--allow-loose-token-perms downgrades to a warning" 0 "${base[@]}" --token-file "$tok" --allow-loose-token-perms
  out_has "warned" 'allowed by --allow-loose-token-perms'
  out_lacks "token value never logged" 'kkkkkkkkkkkkkkkk'

  CS3_PROFILE=onprem OPENAI_API_KEY=sk-test t_run "FailClosed: cloud LLM key under onprem → 3" 3 "${base[@]}"
  out_has "FailClosedError" 'FailClosedError'
  out_lacks "key value never printed" 'sk-test'
  ERROW_CLOUD_ENABLED=true CS3_PROFILE=airgap t_run "Errow cloud in air-gap → 3" 3 "${base[@]}"
  out_has "egress named" 'forbidden with CS3_PROFILE=airgap'
}

case_enroll_errow_targets() {
  local f home yamlstub
  new_tree_pki eet || return 1
  home="$WORK/eet-home"
  f="$WORK/eet-targets.yaml"
  local base=("$S/enroll-errow.sh" --skip-smoke --no-config --errow-home "$home" --targets-file "$f")

  t_run "missing targets file + --no-config: reported, not created" 0 "${base[@]}"
  check_not "not created" test -e "$f"
  t_run "missing targets file + --skip-smoke without --no-config creates the skeleton" 0 "$S/enroll-errow.sh" --skip-smoke --errow-home "$home" --targets-file "$f"
  check "skeleton created" test -f "$f"
  mode_is "skeleton mode" 644 "$f"
  out_has "skeleton valid" 'targets file valid'
  t_run "default location is errow/config/targets.yaml" 0 "$S/enroll-errow.sh" --skip-smoke --no-config --dry-run --errow-home "$home"
  out_has "default path used" 'errow/config/targets\.yaml'

  printf 'hostnames: [scanme.example.com]\ncidrs:\n  - 10.20.0.0/16\n  - 2001:db8::/32\ndomains:\n  - "*.lab.example.com"\nrepo_paths:\n  - /srv/repos/app\n' >"$f"
  t_run "valid allow-list" 0 "${base[@]}"
  out_has "accepted" 'targets file valid'

  printf 'cidrs: [0.0.0.0/0]\n' >"$f"
  t_run "/0 CIDR → policy refusal (3)" 3 "${base[@]}"
  out_has "refusal named" 'matches every address'
  printf 'cidrs: ["::/0"]\n' >"$f"
  t_run "::/0 CIDR → policy refusal (3)" 3 "${base[@]}"
  printf 'cidrs: [10.0.0.0/33]\n' >"$f"
  t_run "invalid CIDR → verification failure (1)" 1 "${base[@]}"
  out_has "fail-closed explained" 'errow-mcp would refuse it'
  printf 'secrets: [x]\n' >"$f"
  t_run "unknown key → failure (1)" 1 "${base[@]}"
  out_has "keys named" 'only hostnames, cidrs, domains, repo_paths are allowed'
  printf 'repo_paths: [relative/path]\n' >"$f"
  t_run "relative repo path → failure (1)" 1 "${base[@]}"
  printf 'repo_paths: [/srv/../etc]\n' >"$f"
  t_run "repo path with .. → failure (1)" 1 "${base[@]}"
  printf 'hostnames: ["bad host!"]\n' >"$f"
  t_run "invalid hostname → failure (1)" 1 "${base[@]}"
  printf 'hostnames: [a\n' >"$f"
  t_run "YAML syntax error → failure (1)" 1 "${base[@]}"
  printf 'cidrs: [127.0.0.0/8]\nhostnames: [localhost]\n' >"$f"
  t_run "an entry inside a denied range is accepted but warned about" 0 "${base[@]}"
  out_has "denied-wins warning" 'overlaps the policy.s denied ranges'

  # without PyYAML the script falls back to a small parser; prove it enforces the same rules
  yamlstub="$WORK/noyaml"
  mkdir -p "$yamlstub"
  printf 'raise ImportError("PyYAML disabled for this test")\n' >"$yamlstub/yaml.py"
  printf 'hostnames: [scanme.example.com]\ncidrs:\n  - 10.20.0.0/16\nrepo_paths:\n  - /srv/repos/app\n' >"$f"
  PYTHONPATH="$yamlstub" t_run "fallback parser accepts a valid file" 0 "${base[@]}"
  printf 'cidrs:\n  - 0.0.0.0/0\n' >"$f"
  PYTHONPATH="$yamlstub" t_run "fallback parser refuses /0 (3)" 3 "${base[@]}"
  printf 'bogus: [x]\n' >"$f"
  PYTHONPATH="$yamlstub" t_run "fallback parser refuses unknown keys (1)" 1 "${base[@]}"
}

case_enroll_errow_smoke() {
  local home cfg side before n
  new_tree_pki ees || return 1
  home="$WORK/ees-home"
  cfg="$home/mcp-servers.json"
  side="$home/mcp-mtls.json"
  ee_start ees
  ee_args "$home"
  local args=("${EE_ARGS[@]}" --skip-cloud)

  t_run "--dry-run: all checks, no writes" 0 "${args[@]}" --dry-run
  out_has "/health checked" 'errow-mcp /health HTTP 200'
  out_has "initialize answered" 'initialize: errow-mcp 1\.0\.0'
  out_has "tools match the policy" 'tools/list matches the policy \(13 tools\)'
  out_has "would write the entry" 'would write .*mcp-servers\.json'
  check_not "dry-run created no home" test -e "$home"

  t_run "enrol" 0 "${args[@]}"
  out_has "summary" 'errow enrolled: entry=vendetta-errow-mcp url=https://errow-mcp:[0-9]+/mcp smoke=passed'
  check "config written" test -f "$cfg"
  mode_is "config mode" 600 "$cfg"
  mode_is "sidecar mode" 600 "$side"
  mode_is "errow home mode" 700 "$home"
  eq "entry url" "https://errow-mcp:$EE_PORT/mcp" "$(jq -r '.[0].url' "$cfg")"
  eq "entry transport" http "$(jq -r '.[0].transport' "$cfg")"
  eq "allow-list equals the policy" "$(policy_tools_json "$TREE/llm-gateway/mcp_policy.yaml")" "$(jq -c '.[0].allowed_tools' "$cfg")"
  eq "sidecar points at the stack identity" "$TREE/pki/errow.crt" "$(jq -r '.servers["vendetta-errow-mcp"].cert' "$side")"
  eq "sidecar CA" "$TREE/pki/ca.crt" "$(jq -r '.servers["vendetta-errow-mcp"].ca' "$side")"
  check_not "the API token is never copied into the Errow config" grep -qF "$(cat "$TREE/secrets/errow_api_token")" "$cfg" "$side"
  check "the mock served the mTLS requests" test "$(req_count ees '.listener == "mcp" and .path == "/mcp"')" -ge 2

  before="$(tree_hashes "$home")"
  t_run "re-enrolling is idempotent" 0 "${args[@]}"
  out_has "config unchanged" 'mcp-servers\.json already up to date'
  out_has "sidecar unchanged" 'mcp-mtls\.json already up to date'
  eq "nothing changed on disk" "$before" "$(tree_hashes "$home")"
  n="$(find "$home" -name '*.bak.*' | wc -l | tr -d ' ')"
  eq "no backup churn" 0 "$n"

  jq -c '. + [{name: "other", transport: "http", url: "https://other.example/mcp"}] | map(if .name == "vendetta-errow-mcp" then .url = "https://stale.example/mcp" else . end)' "$cfg" >"$cfg.new"
  mv -f "$cfg.new" "$cfg"; chmod 600 "$cfg"
  t_run "a stale entry is replaced, others preserved" 0 "${args[@]}"
  eq "entry refreshed" "https://errow-mcp:$EE_PORT/mcp" "$(jq -r '.[] | select(.name == "vendetta-errow-mcp") | .url' "$cfg")"
  eq "foreign entry kept" "https://other.example/mcp" "$(jq -r '.[] | select(.name == "other") | .url' "$cfg")"
  eq "no duplicate entry" 2 "$(jq length "$cfg")"
  eq "previous file kept as a backup" 1 "$(find "$home" -name 'mcp-servers.json.bak.*' | wc -l | tr -d ' ')"

  t_run "a second entry name is appended" 0 "${args[@]}" --name errow-second
  eq "three entries" 3 "$(jq length "$cfg")"

  printf '{"not":"a list"}' >"$cfg"
  t_run "an existing non-list config is never overwritten (1)" 1 "${args[@]}"
  out_has "explained" 'not a JSON list'
  eq "file untouched" '{"not":"a list"}' "$(cat "$cfg")"
  rm -f -- "$cfg"

  t_run "--no-config validates only" 0 "${args[@]}" --no-config
  check_not "no config written" test -e "$cfg"
  t_run "--skip-smoke still writes the entry" 0 "${args[@]}" --skip-smoke
  out_has "smoke skipped in the summary" 'smoke=skipped'
  check "entry written" test -f "$cfg"
  rm -rf -- "$home"

  MCP_ALLOWED_CLIENTS=llm-gateway t_run "client certificate not in MCP_ALLOWED_CLIENTS → failure (1)" 1 "${args[@]}"
  out_has "allow-list named" 'not in MCP_ALLOWED_CLIENTS'
  check_not "nothing written on failure" test -e "$home"
  MCP_ALLOWED_CLIENTS='*' t_run "a wildcard allow-list accepts any client" 0 "${args[@]}" --no-config

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/ees-bad.key" -out "$WORK/ees-bad.crt" -subj "/CN=errow" -days 2 2>/dev/null
  t_run "client certificate not issued by the stack CA → exit 5" 5 "${args[@]}" --client-cert "$WORK/ees-bad.crt" --client-key "$WORK/ees-bad.key"
  out_has "rejection explained" 'not reachable / client certificate rejected'
  t_run "errow-mcp down → exit 5" 5 "$S/enroll-errow.sh" --mcp-url "https://errow-mcp:1/mcp" --mcp-resolve "errow-mcp:1:127.0.0.1" --errow-home "$home"
  check_not "nothing written when unreachable" test -e "$home"

  t_run "unreadable mTLS key is a usage error" 2 "${args[@]}" --client-key "$WORK/missing.key"

  # Errow cloud (opt-in): probed over verified TLS, no credentials sent
  ERROW_CLOUD_ENABLED=true ERROW_CLOUD_URL="https://localhost:$EE_CLOUD_PORT" CURL_CA_BUNDLE="$TREE/pki/ca.crt" t_run "cloud reachable with a trusted certificate" 0 "${EE_ARGS[@]}" --no-config
  out_has "cloud probe reported" 'Errow cloud reachable \(HTTP 200, TLS verified\)'
  ERROW_CLOUD_ENABLED=true ERROW_CLOUD_URL="https://localhost:$EE_CLOUD_PORT" t_run "cloud with an untrusted certificate → failure (1)" 1 "${EE_ARGS[@]}" --no-config
  out_has "TLS failure named" 'unreachable or TLS verification failed'
  ERROW_CLOUD_ENABLED=true ERROW_CLOUD_URL="https://localhost:$EE_CLOUD_PORT" t_run "--skip-cloud bypasses the probe" 0 "${EE_ARGS[@]}" --skip-cloud --no-config
  ERROW_CLOUD_ENABLED=true ERROW_CLOUD_URL="http://localhost:1" t_run "ERROW_CLOUD_URL must be https" 2 "${EE_ARGS[@]}" --no-config
  eq "the cloud listener never saw an Authorization header" 0 "$(req_count ees '.listener == "cloud" and .has_auth == true')"
  stop_mock "$EE_PID"
}

case_enroll_errow_drift() {
  local home tools
  new_tree_pki eed || return 1
  home="$WORK/eed-home"
  tools="$(policy_tools_json "$TREE/llm-gateway/mcp_policy.yaml")"

  EE_TOOLS="$(jq -c 'map(select(. != "wafw00f"))' <<<"$tools")" ee_start eed1
  ee_args "$home"
  t_run "server is missing a policy tool → failure (1)" 1 "${EE_ARGS[@]}" --skip-cloud
  out_has "missing tool named" 'missing on server: wafw00f'
  out_has "remedy given" 'sync-mcp-policy\.sh --check'
  check_not "no config written on drift" test -e "$home"
  stop_mock "$EE_PID"

  EE_TOOLS="$(jq -c '. + ["rogue_tool"]' <<<"$tools")" ee_start eed2
  ee_args "$home"
  t_run "server exposes a tool the policy does not allow → failure (1)" 1 "${EE_ARGS[@]}" --skip-cloud
  out_has "extra tool named" 'only on server: rogue_tool'
  stop_mock "$EE_PID"

  EE_TOOLS='[]' ee_start eed3
  ee_args "$home"
  t_run "empty tools/list → failure (1)" 1 "${EE_ARGS[@]}" --skip-cloud
  out_has "empty named" 'tools/list returned no tools'
  stop_mock "$EE_PID"

  EE_HEALTH=503 ee_start eed4
  ee_args "$home"
  t_run "unhealthy errow-mcp → failure (1)" 1 "${EE_ARGS[@]}" --skip-cloud
  out_has "status named" 'GET /health returned HTTP 503'
  stop_mock "$EE_PID"

  EE_INIT=0 ee_start eed5
  ee_args "$home"
  t_run "JSON-RPC initialize error → failure (1)" 1 "${EE_ARGS[@]}" --skip-cloud
  out_has "initialize failure named" 'initialize failed'
  check_not "still nothing written" test -e "$home"
  stop_mock "$EE_PID"
}
