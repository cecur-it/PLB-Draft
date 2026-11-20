# shellcheck shell=bash
# Cases: enroll-ollama.sh against an mTLS mock of the worker proxy (:11443) and a mock gateway /health.

# eo_spec <out.json> — EO_HOST (bind address of the worker proxy), EO_VERSION, EO_TAGS (JSON array), EO_GW_REACH (true|false),
# EO_GW_SLOW=1 (first /health answers unreachable), EO_EXPOSE=1 (a listener on 0.0.0.0:11434)
eo_spec() {
  local out=$1
  jq -n --arg pki "$TREE/pki" --arg host "${EO_HOST:-127.0.0.1}" --arg ver "${EO_VERSION:-0.40.5}" \
    --argjson tags "${EO_TAGS:-[\"nemotron-3-nano:30b\",\"gemma4:26b\",\"gemma4:31b\",\"qwensploit-v2:9b\"]}" --argjson reach "${EO_GW_REACH:-true}" \
    --arg slow "${EO_GW_SLOW:-0}" --arg expose "${EO_EXPOSE:-0}" '
    def health($r): {json: {status: (if $r then "ok" else "degraded" end), backend: {reachable: $r, models: ["gemma4:26b"]}, version: "1.0.0"}};
    {listeners: ([
      {name: "node", host: $host, tls: {cert: "\($pki)/ollama-1.crt", key: "\($pki)/ollama-1.key", ca: "\($pki)/ca.crt", require_client_cert: true},
       routes: {"GET /api/version": {json: {version: $ver}}, "GET /api/tags": {json: {models: ($tags | map({name: ., model: .}))}}}},
      {name: "gw", tls: {cert: "\($pki)/llm-gateway.crt", key: "\($pki)/llm-gateway.key", ca: "\($pki)/ca.crt", require_client_cert: false},
       routes: {"GET /health": (if $slow == "1" then {sequence: [health(false), health($reach)]} else health($reach) end)}}
    ] + (if $expose == "1" then [{name: "exposed", host: "0.0.0.0", port: 11434, routes: {"GET /api/version": {json: {version: $ver}}}}] else [] end))}' >"$out"
}

eo_start() { # <mock-name> — sets EO_PID, EO_NODE_PORT, EO_GW_URL
  eo_spec "$WORK/$1.json"
  start_mock "$1" "$WORK/$1.json"
  EO_PID=$MOCK_LAST_PID
  EO_NODE_PORT="$(mock_port "$1" node)"
  EO_GW_URL="https://localhost:$(mock_port "$1" gw)"
}

docker_shim() { # <shim-dir> — `docker inspect` answers from SHIM_PORT_BINDINGS; `docker exec NAME cmd…` runs cmd locally
  write_shim "$1" docker <<'EOF'
#!/usr/bin/env bash
case "$1" in
  inspect)
    case "$*" in
      *PortBindings*) if [[ -n "${SHIM_PORT_BINDINGS:-}" ]]; then printf '%s\n' "$SHIM_PORT_BINDINGS"; else echo '{}'; fi ;;
      *) echo '127.0.0.1 ' ;;
    esac ;;
  exec) shift 2; exec "$@" ;;
  *) echo "docker shim: unsupported: $*" >&2; exit 1 ;;
esac
EOF
}

# nonloop_ips — routable addresses of this host (never loopback)
nonloop_ips() { hostname -I 2>/dev/null | tr ' ' '\n' | grep -Ev '^(127\.|$)' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true; }

case_enroll_ollama_usage() {
  new_tree_pki eou || return 1
  local base=("$S/enroll-ollama.sh" --skip-gateway)
  t_run "--help" 0 "$S/enroll-ollama.sh" --help
  out_has "help documents the exit codes" 'Exit codes: 0 enrolled'
  t_run "--node is required" 2 "${base[@]}" --address 10.0.0.1
  t_run "an address source is required" 2 "${base[@]}" --node n1
  t_run "--container and --local are exclusive" 2 "${base[@]}" --node n1 --container c --local
  t_run "invalid node name" 2 "${base[@]}" --node 'bad name' --address 10.0.0.1
  t_run "invalid --port" 2 "${base[@]}" --node n1 --address 10.0.0.1 --port 70000
  t_run "--models-dir must exist" 2 "${base[@]}" --node n1 --address 10.0.0.1 --models-dir "$WORK/missing"
  t_run "--gateway-url must be https" 2 "$S/enroll-ollama.sh" --node n1 --address 10.0.0.1 --gateway-url http://localhost:9101
  t_run "client key must be readable" 2 "${base[@]}" --node n1 --address 10.0.0.1 --client-key "$WORK/missing.key"
  t_run "an unapproved model is refused (3)" 3 "${base[@]}" --node n1 --address 10.0.0.1 --models llama3:8b
  out_has "approved models listed" 'approved: gemma4:26b'
  t_run "--remove of an unknown node is a no-op" 0 "$S/enroll-ollama.sh" --remove ghost
  out_has "reported" 'not enrolled'
}

case_enroll_ollama_checks() {
  local store sha
  new_tree_pki eoc || return 1
  store="$WORK/eoc-store"
  eo_start eoc
  local base=("$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port "$EO_NODE_PORT" --skip-gateway)

  t_run "healthy node, unverified blobs, loopback address → refused for DNS discovery (2)" 2 "${base[@]}"
  out_has "version verified over mTLS" 'Ollama version 0\.40\.5 \(pinned 0\.40\.5\)'
  out_has "11434 check" '11434 is not exposed'
  out_has "models present" 'model nemotron-3-nano:30b present'
  out_has "unverified blobs are warned about" 'NOT verified against models\.json'
  out_has "loopback refusal explained" 'refusing to register the loopback address'
  check_not "nothing registered" test -e "$TREE/ollama/ollama-lb/workers.d/n1.json"

  t_run "--version overrides the pin" 1 "${base[@]}" --version 0.41.0
  out_has "version mismatch named" "expected the pinned 0\\.41\\.0"
  t_run "--models all requires gemma4:31b too (present here)" 2 "${base[@]}" --models all
  t_run "--models none skips tag checks" 2 "${base[@]}" --models none
  stop_mock "$EO_PID"

  EO_VERSION=0.40.4 eo_start eoc2
  t_run "version drift → verification failure (1)" 1 "$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port "$EO_NODE_PORT" --skip-gateway
  out_has "drift named" "Ollama version is '0\\.40\\.4', expected the pinned 0\\.40\\.5"
  out_has "not registered" 'failed 1 check'
  stop_mock "$EO_PID"

  EO_TAGS='["gemma4:26b"]' eo_start eoc3
  t_run "required model missing on the node → failure (1)" 1 "$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port "$EO_NODE_PORT" --skip-gateway
  out_has "missing model named" 'required model nemotron-3-nano:30b is not present'
  stop_mock "$EO_PID"

  eo_start eoc4
  base=("$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port "$EO_NODE_PORT" --skip-gateway)
  t_run "--release without a model store is refused (3)" 3 "${base[@]}" --release
  out_has "unverifiable store named" 'cannot be verified'
  CS3_PROFILE=airgap t_run "CS3_PROFILE=airgap implies --release (3)" 3 "${base[@]}"
  make_model_store "$store" nemotron-3-nano:30b fixture >/dev/null
  make_model_store "$store" gemma4:26b fixture >/dev/null
  jq '(.models[].sha256) = "<pinned-per-release>"' "$TREE/ollama/models.json" >"$WORK/eoc.sentinel.json"
  t_run "sentinel pins under --release → policy refusal (3)" 3 "${base[@]}" --release --models-dir "$store" --models-json "$WORK/eoc.sentinel.json"
  out_has "sentinel named" 'sentinel'
  fixture_models "$TREE" "$store"
  t_run "pinned + matching store, loopback → blobs verified, then loopback refusal (2)" 2 "${base[@]}" --models-dir "$store" --release
  out_has "sha256 verified" 'nemotron-3-nano:30b: sha256 [0-9a-f]{64} matches models\.json'
  out_has "both required models verified" 'gemma4:26b: sha256 [0-9a-f]{64} matches models\.json'

  sha="$(jq -r '.models[] | select(.id == "gemma4:26b") | .sha256' "$TREE/ollama/models.json")"
  pin_models_json "$TREE/ollama/models.json" gemma4:26b "$(printf 'f%.0s' {1..64})"
  t_run "pin mismatch → integrity refusal (3)" 3 "${base[@]}" --models-dir "$store"
  out_has "mismatch named" 'sha256 mismatch — models\.json pins f{64}'
  pin_models_json "$TREE/ollama/models.json" gemma4:26b "$sha"
  printf 'tampered' >>"$store/blobs/sha256-$sha"
  t_run "blob content not matching its digest → integrity refusal (3)" 3 "${base[@]}" --models-dir "$store"
  out_has "tamper named" 'corrupt or tampered'
  stop_mock "$EO_PID"

  t_run "node unreachable → exit 5" 5 "$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port 1 --skip-gateway
  out_has "reachability explained" 'not reachable'

  # a certificate the CA never issued is refused by the worker proxy
  eo_start eoc5
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/intruder.key" -out "$WORK/intruder.crt" -subj "/CN=intruder" -days 2 2>/dev/null
  t_run "client certificate not issued by the stack CA → exit 5" 5 "$S/enroll-ollama.sh" --node n1 --address 127.0.0.1 --port "$EO_NODE_PORT" --skip-gateway \
    --client-cert "$WORK/intruder.crt" --client-key "$WORK/intruder.key"
  stop_mock "$EO_PID"
}

case_enroll_ollama_register() {
  local ip ip2 store inv sh before
  local -a ips
  new_tree_pki eor || return 1
  store="$WORK/eor-store"
  sh="$(shims_dir eor)"
  inv="$TREE/ollama/ollama-lb/workers.d"
  fixture_models "$TREE" "$store"
  mapfile -t ips < <(nonloop_ips)
  ip=${ips[0]:-}
  ip2=${ips[1]:-}

  if [[ -n "$ip" ]]; then
    EO_HOST=0.0.0.0 eo_start eor
    local args=("$S/enroll-ollama.sh" --node n1 --address "$ip" --port "$EO_NODE_PORT" --models-dir "$store" --gateway-url "$EO_GW_URL" --wait 15)

    t_run "--dry-run verifies but writes nothing" 0 "${args[@]}" --dry-run
    out_has "dry-run shows the inventory entry" 'would write .*n1\.json'
    check_not "dry-run: no inventory" test -e "$inv/n1.json"
    check_not "dry-run: no hosts file" test -e "$TREE/ollama/ollama-lb/workers.hosts"

    t_run "enroll a routable node → registered" 0 "${args[@]}"
    out_has "summary" "enrolled: node=n1 address=$ip version=0\\.40\\.5 models=3"
    out_has "gateway confirmed" 'gateway /health: status ok, Ollama backend reachable'
    out_has "DNS record printed" "ollama-workers\\. IN A $ip"
    check "inventory written" test -f "$inv/n1.json"
    eq "inventory address" "$ip" "$(jq -r .address "$inv/n1.json")"
    eq "inventory discovery model" dns-hosts "$(jq -r .discovery "$inv/n1.json")"
    eq "inventory records the verified pins" 3 "$(jq -r .verification.pinnedVerified "$inv/n1.json")"
    eq "inventory records the blob source" "dir:$store" "$(jq -r .verification.blobSource "$inv/n1.json")"
    check "hosts file carries the DNS record" grep -qx "$ip ollama-workers # n1" "$TREE/ollama/ollama-lb/workers.hosts"

    before="$(tree_hashes "$TREE/ollama/ollama-lb")"
    t_run "re-enrolling is idempotent" 0 "${args[@]}"
    out_has "inventory unchanged" 'already up to date'
    out_has "hosts unchanged" 'workers\.hosts unchanged'
    eq "no file changed" "$before" "$(tree_hashes "$TREE/ollama/ollama-lb")"

    if [[ -n "$ip2" ]]; then
      t_run "a second node adds a second DNS record" 0 "$S/enroll-ollama.sh" --node n2 --address "$ip2" --port "$EO_NODE_PORT" --models-dir "$store" --skip-gateway
      check "second record present" grep -qx "$ip2 ollama-workers # n2" "$TREE/ollama/ollama-lb/workers.hosts"
      check "first record kept" grep -qx "$ip ollama-workers # n1" "$TREE/ollama/ollama-lb/workers.hosts"
      "$S/enroll-ollama.sh" --remove n2 >/dev/null 2>&1
    fi

    t_run "--remove --dry-run changes nothing" 0 "$S/enroll-ollama.sh" --remove n1 --dry-run
    check "still enrolled after dry-run remove" test -f "$inv/n1.json"
    t_run "--remove de-registers the node" 0 "$S/enroll-ollama.sh" --remove n1
    check_not "inventory entry removed" test -e "$inv/n1.json"
    check_not "hosts line removed" grep -q "ollama-workers # n1" "$TREE/ollama/ollama-lb/workers.hosts"

    CS3_PROFILE=airgap t_run "air-gap profile with verified pins enrols" 0 "${args[@]}"
    t_run "--skip-gateway skips the confirmation" 0 "${args[@]}" --skip-gateway
    out_has "skip noted" 'gateway confirmation skipped'
    "$S/enroll-ollama.sh" --remove n1 >/dev/null 2>&1
    stop_mock "$EO_PID"

    EO_HOST=0.0.0.0 EO_GW_SLOW=1 eo_start eor2
    t_run "gateway slow to see the backend → polled until reachable" 0 "$S/enroll-ollama.sh" --node n1 --address "$ip" --port "$EO_NODE_PORT" --gateway-url "$EO_GW_URL" --wait 20
    "$S/enroll-ollama.sh" --remove n1 >/dev/null 2>&1
    stop_mock "$EO_PID"

    EO_HOST=0.0.0.0 EO_GW_REACH=false eo_start eor3
    t_run "gateway never sees the backend → failure (1), node stays registered" 1 "$S/enroll-ollama.sh" --node n1 --address "$ip" --port "$EO_NODE_PORT" --gateway-url "$EO_GW_URL" --wait 5
    out_has "gateway failure named" 'did not report backend\.reachable=true'
    check "inventory kept for diagnosis" test -f "$inv/n1.json"
    "$S/enroll-ollama.sh" --remove n1 >/dev/null 2>&1
    stop_mock "$EO_PID"

    if [[ -z "$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ':11434$' || true)" ]]; then
      EO_HOST=0.0.0.0 EO_EXPOSE=1 eo_start eor4
      t_run "11434 reachable beyond loopback → policy refusal (3)" 3 "$S/enroll-ollama.sh" --node n1 --address "$ip" --port "$EO_NODE_PORT" --skip-gateway
      out_has "exposure named" 'port 11434 is reachable beyond loopback'
      check_not "nothing registered" test -e "$inv/n1.json"
      stop_mock "$EO_PID"
    else
      pass "11434 exposure case skipped: the port is in use on this host"
    fi
  else
    pass "routable-address cases skipped: this host has no non-loopback IPv4 address"
  fi

  # compose worker (--container): found through the network alias, blobs hashed through `docker exec`
  docker_shim "$sh"
  eo_start eor5
  local cargs=("$S/enroll-ollama.sh" --node ollama-1 --container vs-ollama-1 --container-models-dir "$store" --port "$EO_NODE_PORT" --gateway-url "$EO_GW_URL" --wait 10)
  PATH="$sh:$PATH" t_run "compose worker enrols via the network alias" 0 "${cargs[@]}"
  out_has "blobs hashed in the container" 'gemma4:26b: sha256 [0-9a-f]{64} matches'
  eq "discovery is the compose alias" compose-alias "$(jq -r .discovery "$inv/ollama-1.json")"
  eq "blob source" "container:vs-ollama-1" "$(jq -r .verification.blobSource "$inv/ollama-1.json")"
  check_not "compose workers get no hosts line" grep -q "ollama-1" "$TREE/ollama/ollama-lb/workers.hosts"
  SHIM_PORT_BINDINGS='{"11434/tcp":[{"HostIp":"0.0.0.0","HostPort":"11434"}]}' PATH="$sh:$PATH" t_run "11434 published on 0.0.0.0 → policy refusal (3)" 3 "${cargs[@]}"
  out_has "published port named" 'port 11434 is reachable beyond loopback'
  SHIM_PORT_BINDINGS='{"11434/tcp":[{"HostIp":"127.0.0.1","HostPort":"11434"}]}' PATH="$sh:$PATH" t_run "11434 published on 127.0.0.1 is fine" 0 "${cargs[@]}"
  stop_mock "$EO_PID"
}
