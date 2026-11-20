# shellcheck shell=bash
# Cases: healthcheck.sh against mock endpoints (healthy / degraded / unhealthy, --json, loop-guard invariant,
# Ollama loopback-only invariant, certificate expiry, FailClosed).

# health_spec <out.json> — mock endpoints for every probed service; HS_* variables tune the answers
health_spec() {
  local out=$1 pw
  pw="$(<"$TREE/secrets/opensearch_admin_password")"
  jq -n --arg pw "$pw" --arg pki "$TREE/pki" --arg osst "${HS_OS_STATUS:-green}" --arg gwst "${HS_GW_STATUS:-ok}" \
    --argjson spool "${HS_SPOOL:-0}" --arg chain "${HS_CHAIN:-1}" --argjson fdq "${HS_FD_QUEUE:-1}" \
    --argjson models "${HS_MODELS:-[\"gemma4:26b\",\"nemotron-3-nano:30b\"]}" --argjson reach "${HS_REACH:-true}" '
    def tls($n; $m): {cert: "\($pki)/\($n).crt", key: "\($pki)/\($n).key", ca: "\($pki)/ca.crt", require_client_cert: $m};
    def fd: {"GET /api/plugins.json": {json: {plugins: [{output_plugin: true, buffer_queue_length: $fdq, buffer_total_queued_size: 1024, retry_count: 0}]}}};
    {listeners: [
      {name: "os", tls: tls("opensearch"; false), auth: {basic: "admin:\($pw)"},
       routes: {"GET /_cluster/health": {json: {status: $osst, number_of_nodes: 1, unassigned_shards: 0, active_shards_percent_as_number: 100}}}},
      {name: "fb", routes: {"GET /api/v1/health": {text: "ok"}, "GET /api/v1/storage": {json: {storage_layer: {chunks: {fs_chunks: 3, fs_chunks_down: 0}}}}}},
      {name: "fd1", routes: fd}, {name: "fd2", routes: fd},
      {name: "fd1m", routes: {"GET /metrics": {text: "# metrics\n"}}}, {name: "fd2m", routes: {"GET /metrics": {text: "# metrics\n"}}},
      {name: "dash", routes: {"GET /api/status": {json: {status: {overall: {state: "green"}}}}}},
      {name: "prom", routes: {"GET /-/ready": {text: "Prometheus Server is Ready.\n"}}},
      {name: "graf", routes: {"GET /api/health": {json: {database: "ok"}}}},
      {name: "am", routes: {"GET /-/ready": {text: "OK"}}},
      {name: "gw", tls: tls("llm-gateway"; false),
       routes: {"GET /health": {json: {status: $gwst, backend: {reachable: $reach, models: $models}, fluent_bit: {reachable: true, spool_depth: $spool}, version: "1.0.0"}},
                "GET /metrics": {text: "# HELP llm_gateway_audit_chain_ok chain\nllm_gateway_audit_chain_ok \($chain)\n"}}},
      {name: "fbk", routes: {"GET /health": {json: {status: "ok"}}}},
      {name: "mcp", tls: tls("errow-mcp"; true), routes: {"GET /health": {json: {status: "ok"}}}}
    ]}' >"$out"
}

# hc_env — HC_URL_* overrides for the running mock (ports from mock $1)
hc_env() {
  local m=$1
  HC_ENV=(
    "HC_URL_OPENSEARCH=https://localhost:$(mock_port "$m" os)"
    "HC_URL_FLUENT_BIT=http://127.0.0.1:$(mock_port "$m" fb)"
    "HC_URL_FLUENTD_1=http://127.0.0.1:$(mock_port "$m" fd1)" "HC_URL_FLUENTD_2=http://127.0.0.1:$(mock_port "$m" fd2)"
    "HC_URL_FLUENTD_1_METRICS=http://127.0.0.1:$(mock_port "$m" fd1m)" "HC_URL_FLUENTD_2_METRICS=http://127.0.0.1:$(mock_port "$m" fd2m)"
    "HC_URL_DASHBOARDS=http://127.0.0.1:$(mock_port "$m" dash)" "HC_URL_PROMETHEUS=http://127.0.0.1:$(mock_port "$m" prom)"
    "HC_URL_GRAFANA=http://127.0.0.1:$(mock_port "$m" graf)" "HC_URL_ALERTMANAGER=http://127.0.0.1:$(mock_port "$m" am)"
    "HC_URL_LLM_GATEWAY=https://localhost:$(mock_port "$m" gw)" "HC_URL_ERROW_FEEDBACK=http://127.0.0.1:$(mock_port "$m" fbk)"
    "HC_URL_ERROW_MCP=https://localhost:$(mock_port "$m" mcp)"
  )
}

ss_shim() { # <shim-dir> — fake `ss`; SHIM_SS_LISTEN holds the local addresses to report as listening
  write_shim "$1" ss <<'EOF'
#!/usr/bin/env bash
for a in ${SHIM_SS_LISTEN:-127.0.0.1:11434 127.0.0.1:9200}; do
  printf 'LISTEN 0 4096 %s 0.0.0.0:*\n' "$a"
done
EOF
}

case_health_levels() {
  local pid
  new_tree_pki hc || return 1
  HS_OS_STATUS=green health_spec "$WORK/hc.json"
  start_mock hc "$WORK/hc.json"
  pid=$MOCK_LAST_PID
  hc_env hc
  local sh
  sh="$(shims_dir hc)"
  ss_shim "$sh"

  PATH="$sh:$PATH" t_run "healthy stack → exit 0" 0 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "OpenSearch green" 'opensearch +OK .*cluster green'
  out_has "Fluent Bit health + backlog" 'fluent-bit +OK .*backlog 3 chunk'
  out_has "both Fluentd aggregators" 'fluentd \(active-active\) +OK .*both aggregators healthy'
  out_has "llm-gateway ok" 'llm-gateway +OK .*ok; ollama backend reachable=true models=2'
  out_has "audit chain intact" 'audit chain +OK'
  out_has "errow-mcp mTLS" 'errow-mcp +OK .*mTLS ok'
  out_has "errow-feedback" 'errow-feedback +OK'
  out_has "dashboards/prometheus/grafana" 'prometheus +OK'
  out_has "loopback invariant" 'ollama loopback-only +OK'
  out_has "loop guard proven on the shipped Fluent Bit tree" 'loopguard +OK .*cannot match cs3\.ai'
  out_has "failclosed row" 'failclosed +OK'
  out_has "pki row" 'pki +OK'
  out_has "summary line" 'healthy \(exit 0\)'

  t_run "--json report" 0 env "${HC_ENV[@]}" PATH="$sh:$PATH" "$S/healthcheck.sh" --no-docker --transport host --json
  check "--json output is valid JSON" jq -e . "$T_OUT"
  eq "--json status" healthy "$(jq -r '.status // .overall // empty' "$T_OUT" 2>/dev/null)"
  check "--json has per-check rows" jq -e '(.checks // .results) | length > 8' "$T_OUT"

  # --- degraded: llm-gateway degraded
  stop_mock "$pid"
  HS_GW_STATUS=degraded health_spec "$WORK/hc2.json"
  start_mock hc2 "$WORK/hc2.json"
  hc_env hc2
  PATH="$sh:$PATH" t_run "gateway status=degraded → exit 1" 1 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "degraded explained" 'llm-gateway +WARN .*heuristic fallback'
  stop_mock "$MOCK_LAST_PID"

  HS_SPOOL=9000 health_spec "$WORK/hc3.json"
  start_mock hc3 "$WORK/hc3.json"
  hc_env hc3
  PATH="$sh:$PATH" t_run "spool depth over the fail threshold → degraded" 1 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "spool row FAIL" 'llm-gateway spool +FAIL'
  PATH="$sh:$PATH" t_run "HC_SPOOL_FAIL raises the threshold" 0 env "${HC_ENV[@]}" HC_SPOOL_FAIL=20000 HC_SPOOL_WARN=10000 "$S/healthcheck.sh" --no-docker --transport host
  stop_mock "$MOCK_LAST_PID"

  # --- degraded: the sanctioned security model is not loaded
  HS_MODELS='["gemma4:26b"]' health_spec "$WORK/hc3b.json"
  start_mock hc3b "$WORK/hc3b.json"
  hc_env hc3b
  PATH="$sh:$PATH" t_run "security model not loaded → degraded" 1 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "security model warning" 'ollama security model +WARN .*fail closed'
  PATH="$sh:$PATH" t_run "GATEWAY_SECURITY_ENABLED=false tolerates the missing security model" 0 env "${HC_ENV[@]}" GATEWAY_SECURITY_ENABLED=false "$S/healthcheck.sh" --no-docker --transport host
  out_lacks "no security model row when /security is disabled" 'ollama security model +(OK|WARN|FAIL)'
  PATH="$sh:$PATH" t_run "configured primary model not loaded → degraded" 1 env "${HC_ENV[@]}" OLLAMA_PRIMARY_MODEL=gemma4:31b "$S/healthcheck.sh" --no-docker --transport host
  out_has "primary model named" 'ollama models +WARN .*primary model gemma4:31b not loaded'
  stop_mock "$MOCK_LAST_PID"

  HS_CHAIN=0 health_spec "$WORK/hc4.json"
  start_mock hc4 "$WORK/hc4.json"
  hc_env hc4
  PATH="$sh:$PATH" t_run "broken audit chain is critical → unhealthy (exit 2)" 2 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "audit chain FAIL" 'audit chain +FAIL'
  stop_mock "$MOCK_LAST_PID"

  HS_OS_STATUS=red health_spec "$WORK/hc5.json"
  start_mock hc5 "$WORK/hc5.json"
  hc_env hc5
  PATH="$sh:$PATH" t_run "OpenSearch red → unhealthy (exit 2)" 2 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  PATH="$sh:$PATH" t_run "--skip opensearch ignores that check" 0 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host --skip opensearch
  PATH="$sh:$PATH" t_run "--only restricts the checks" 0 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host --only prometheus,grafana
  out_lacks "--only: opensearch not probed" 'opensearch +(OK|FAIL)'
  stop_mock "$MOCK_LAST_PID"

  HS_OS_STATUS=yellow HS_FD_QUEUE=40 health_spec "$WORK/hc6.json"
  start_mock hc6 "$WORK/hc6.json"
  hc_env hc6
  PATH="$sh:$PATH" t_run "yellow cluster + growing Fluentd buffer → degraded" 1 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "yellow is a warning" 'opensearch +WARN .*cluster yellow'
  out_has "Fluentd queue warning" 'fluentd-1 +WARN .*buffer queue 40'
  PATH="$sh:$PATH" t_run "one aggregator down → degraded (redundancy lost)" 1 env "${HC_ENV[@]}" HC_URL_FLUENTD_2=http://127.0.0.1:1 "$S/healthcheck.sh" --no-docker --transport host
  out_has "redundancy warning" 'only one aggregator healthy'
  PATH="$sh:$PATH" t_run "both aggregators down → unhealthy" 2 env "${HC_ENV[@]}" HC_URL_FLUENTD_1=http://127.0.0.1:1 HC_URL_FLUENTD_2=http://127.0.0.1:1 \
    "$S/healthcheck.sh" --no-docker --transport host
  out_has "no aggregator" 'no Fluentd aggregator is healthy'
  PATH="$sh:$PATH" t_run "OpenSearch unreachable → unhealthy" 2 env "${HC_ENV[@]}" HC_URL_OPENSEARCH=https://localhost:1 "$S/healthcheck.sh" --no-docker --transport host
  stop_mock "$MOCK_LAST_PID"

  HS_FD_QUEUE=400 health_spec "$WORK/hc7.json"
  start_mock hc7 "$WORK/hc7.json"
  hc_env hc7
  PATH="$sh:$PATH" t_run "every Fluentd buffer stuck → unhealthy" 2 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host
  out_has "queue FAIL" 'fluentd-1 +FAIL .*not draining'
  PATH="$sh:$PATH" t_run "HC_FLUENTD_QUEUE_FAIL raises the threshold" 1 env "${HC_ENV[@]}" HC_FLUENTD_QUEUE_FAIL=9999 "$S/healthcheck.sh" --no-docker --transport host
  stop_mock "$MOCK_LAST_PID"
  t_run "no endpoint reachable at all → unhealthy" 2 env HC_URL_OPENSEARCH=https://localhost:1 HC_URL_FLUENT_BIT=http://127.0.0.1:1 HC_URL_LLM_GATEWAY=https://localhost:1 \
    "$S/healthcheck.sh" --no-docker --transport host --only opensearch,fluent-bit,llm-gateway
}

case_health_invariants() {
  local sh pid
  new_tree_pki hci || return 1
  sh="$(shims_dir hci)"
  ss_shim "$sh"
  HS_OS_STATUS=green health_spec "$WORK/hci.json"
  start_mock hci "$WORK/hci.json"
  pid=$MOCK_LAST_PID
  hc_env hci

  SHIM_SS_LISTEN="0.0.0.0:11434" PATH="$sh:$PATH" t_run "Ollama listening on 0.0.0.0:11434 → unhealthy" 2 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host --only ollama
  out_has "exposure named" 'ollama loopback-only +FAIL .*0\.0\.0\.0:11434'
  SHIM_SS_LISTEN="127.0.0.1:11434" PATH="$sh:$PATH" t_run "Ollama bound to 127.0.0.1 only → healthy" 0 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host --only ollama
  SHIM_SS_LISTEN="[::1]:11434" PATH="$sh:$PATH" t_run "Ollama bound to ::1 only → healthy" 0 env "${HC_ENV[@]}" "$S/healthcheck.sh" --no-docker --transport host --only ollama

    # loop guard: the Console leg must not be able to match cs3.ai.*
  t_run "loopguard on the shipped tree" 0 "$S/healthcheck.sh" --no-docker --only loopguard --fluent-bit-dir "$TREE/fluent-bit"
  out_has "loopguard OK" 'loopguard +OK'
  sed 's/Match_Regex                   ^(host\\..*|v1_logs|/Match_Regex                   ^(cs3\\.ai\\..*|host\\..*|v1_logs|/' \
    "$TREE/fluent-bit/legs/10-console.conf" >"$TREE/fluent-bit/legs/10-console.conf.new" \
    && mv -f "$TREE/fluent-bit/legs/10-console.conf.new" "$TREE/fluent-bit/legs/10-console.conf"
  check "fixture: the Console leg regex now admits cs3.ai.*" grep -q 'Match_Regex.*(cs3\\.ai' "$TREE/fluent-bit/legs/10-console.conf"
  t_run "loopguard detects a Console leg that admits cs3.ai.ollama" 2 "$S/healthcheck.sh" --no-docker --only loopguard --fluent-bit-dir "$TREE/fluent-bit"
  out_has "telemetry loop named" 'loopguard +FAIL .*telemetry loop possible: Console leg in .*10-console\.conf matches cs3\.ai\.ollama'
  cp -- "$REAL_STACK/fluent-bit/legs/10-console.conf" "$TREE/fluent-bit/legs/10-console.conf"
  sed 's/cs3\\.ai\\.(inference|tool_call|enrichment)/cs3\\.ai\\..*/' "$TREE/fluent-bit/conf.d/90-outputs.conf" \
    >"$TREE/fluent-bit/conf.d/90-outputs.conf.new" \
    && mv -f "$TREE/fluent-bit/conf.d/90-outputs.conf.new" "$TREE/fluent-bit/conf.d/90-outputs.conf"
  check "fixture: the Fluentd forward output now admits cs3.ai.ollama" grep -qF 'cs3\.ai\..*|cs3' "$TREE/fluent-bit/conf.d/90-outputs.conf"
  t_run "loopguard detects a forward output that admits cs3.ai.ollama" 2 "$S/healthcheck.sh" --no-docker --only loopguard --fluent-bit-dir "$TREE/fluent-bit"
  out_has "forward output named" 'forward output .fluentd_forward. in .*90-outputs\.conf would forward cs3\.ai\.ollama'
  t_run "no Fluent Bit config → loopguard SKIP, nothing verified → unhealthy" 2 "$S/healthcheck.sh" --no-docker --only loopguard --fluent-bit-dir "$TREE/nonexistent"
  out_has "SKIP row" 'loopguard +SKIP'

  # FailClosed
  CS3_PROFILE=airgap OPENAI_API_KEY=sk-test-not-a-secret t_run "FailClosed violation → unhealthy" 2 "$S/healthcheck.sh" --no-docker --only failclosed
  out_has "FailClosedError reported" 'FailClosedError|failclosed +FAIL'
  out_lacks "key value never printed" 'sk-test-not-a-secret'
  t_run "FailClosed ok in a clean environment" 0 "$S/healthcheck.sh" --no-docker --only failclosed

  # certificate expiry
  t_run "pki: fresh certificates → healthy" 0 "$S/healthcheck.sh" --no-docker --only pki
  t_run "pki: --cert-warn-days beyond the validity → degraded" 1 "$S/healthcheck.sh" --no-docker --only pki --cert-warn-days 800
  out_has "expiry warning names the rotation script" 'rotate-certs\.sh'
  rm -f -- "$TREE/pki"/*.crt
  t_run "pki: no certificates → degraded" 1 "$S/healthcheck.sh" --no-docker --only pki
  stop_mock "$pid"
  t_run "bad --only name is a usage error" 64 "$S/healthcheck.sh" --no-docker --only nonsense
  t_run "bad --transport is a usage error" 64 "$S/healthcheck.sh" --transport carrier-pigeon
}

case_health_kubernetes() {
  local sh
  new_tree_pki hck || return 1
  sh="$(shims_dir hck)"
  write_shim "$sh" kubectl <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"get svc"*) echo "${SHIM_K8S_SVC:-{\"items\":[]}}" ;;
  *"get pods"*) echo "${SHIM_K8S_PODS:-{\"items\":[]}}" ;;
  *) echo "kubectl shim: unsupported: $*" >&2; exit 1 ;;
esac
EOF
  SHIM_K8S_SVC='{"items":[{"metadata":{"name":"ollama"},"spec":{"type":"NodePort","ports":[{"port":11434,"targetPort":11434,"nodePort":31434}]}}]}' \
    PATH="$sh:$PATH" t_run "a NodePort Service for 11434 is unhealthy" 2 "$S/healthcheck.sh" --kubernetes --only ollama
  out_has "Service named" 'Service ollama \(NodePort\)'
  SHIM_K8S_SVC='{"items":[{"metadata":{"name":"ollama"},"spec":{"type":"ClusterIP","ports":[{"port":11434,"targetPort":11434}]}}]}' \
    PATH="$sh:$PATH" t_run "a ClusterIP Service for 11434 is fine" 0 "$S/healthcheck.sh" --kubernetes --only ollama
  SHIM_K8S_PODS='{"items":[{"metadata":{"name":"ollama-0"},"spec":{"containers":[{"ports":[{"containerPort":11434,"hostPort":11434}]}]}}]}' \
    PATH="$sh:$PATH" t_run "a hostPort for 11434 is unhealthy" 2 "$S/healthcheck.sh" --kubernetes --only ollama
  out_has "hostPort named" 'Pod ollama-0 hostPort'
}

# hc_docker_shim <dir> — fake docker/compose for the container-IP fallback.
# Env: SHIM_RUNNING="svc …" running services · SHIM_IPS="svc=ip[,ip] …" · SHIM_HEALTH · SHIM_PROJECT · SHIM_NAME_STYLE=1
# (`compose ps -q` finds nothing, only `docker inspect <project>-<svc>-1` does) · SHIM_LOG (every call is appended)
hc_docker_shim() {
  write_shim "$1" docker <<'EOF'
#!/usr/bin/env bash
if [[ -n "${SHIM_LOG:-}" ]]; then printf 'docker %s\n' "$*" >>"$SHIM_LOG"; fi
running() { [[ " ${SHIM_RUNNING:-} " == *" $1 "* ]]; }
ips_of() { local p; for p in ${SHIM_IPS:-}; do if [[ "${p%%=*}" == "$1" ]]; then printf '%s ' "${p#*=}" | tr ',' ' '; return; fi; done; }
proj=${SHIM_PROJECT:-vendetta-stack}
case "${1:-}" in
  info | ps) exit 0 ;;
  compose)
    case "$*" in
      *"version --short"*) echo v2.32.4 ;;
      *"ps --services"*) for s in ${SHIM_RUNNING:-}; do echo "$s"; done ;;
      *"ps -q "*) if [[ -z "${SHIM_NAME_STYLE:-}" ]]; then all="$*"; echo "cid-${all##* }"; fi ;;
    esac ;;
  inspect)
    target=${*: -1}
    fmt=${*: -2:1}
    case "$target" in
      cid-*) svc=${target#cid-} ;;
      "$proj"-*-1) svc=${target#"$proj"-}; svc=${svc%-1} ;;
      *) exit 1 ;;
    esac
    running "$svc" || exit 1
    case "$fmt" in
      *State.Running*) echo true ;;
      *IPAddress*) ips_of "$svc"; echo ;;
      *Health*) echo "${SHIM_HEALTH:-healthy}" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 0 ;;
esac
EOF
}

# hc_curl_shim <dir> — logs argv and the curl config read from stdin (SHIM_CURL_LOG), then runs the real curl found past the shim directory
hc_curl_shim() {
  write_shim "$1" curl <<'EOF'
#!/usr/bin/env bash
self_dir="$(cd "$(dirname "$0")" && pwd)"
real="$(PATH="${PATH//"$self_dir":/}" command -v curl)" || exit 99
if [[ "$real" -ef "$0" ]]; then echo "curl shim: no real curl behind the shim" >&2; exit 99; fi
cfg="$(cat)"
{ printf 'ARGV: %s\n' "$*"; printf '%s\n' "$cfg"; } >>"${SHIM_CURL_LOG:-/dev/null}"
printf '%s' "$cfg" | "$real" "$@"
EOF
}

# hc_fd_spec <out.json> <host-1> [host-2] — Fluentd monitor_agent (24220) and metrics (24231) mocks on their real in-container ports
hc_fd_spec() {
  jq -n --arg h1 "$2" --arg h2 "${3:-}" '
    def fd($n; $h): [
      {name: $n, host: $h, port: 24220, routes: {"GET /api/plugins.json": {json: {plugins: [{output_plugin: true, buffer_queue_length: 1, buffer_total_queued_size: 1024, retry_count: 0}]}}}},
      {name: "\($n)m", host: $h, port: 24231, routes: {"GET /metrics": {text: "# metrics\n"}}}];
    {listeners: (fd("a"; $h1) + (if $h2 == "" then [] else fd("b"; $h2) end))}' >"$1"
}

# hc_errow_spec <out.json> <mcp-host> <fbk-host> <mcp-cert-name> — errow-feedback (9102) and errow-mcp (9103, mTLS) mocks
hc_errow_spec() {
  jq -n --arg mh "$2" --arg fh "$3" --arg cert "$4" --arg pki "$TREE/pki" '
    {listeners: [
      {name: "fbk", host: $fh, port: 9102, routes: {"GET /health": {json: {status: "ok"}}}},
      {name: "mcp", host: $mh, port: 9103, tls: {cert: "\($pki)/\($cert).crt", key: "\($pki)/\($cert).key", ca: "\($pki)/ca.crt", require_client_cert: true},
       routes: {"GET /health": {json: {status: "ok"}}}}]}' >"$1"
}

# A container IP is simulated with a routable local address of this host (127.0.0.2+ is not reachable in every sandbox);
# 127.0.0.1 doubles as the "dead" container IP: it answers the host-port probe with a refusal, so it fails fast.
case_health_container_ip() {
  local sh pid_a pid_c pid_d nodocker t shimlog curllog lip dead=127.0.0.1
  local -a ips
  mapfile -t ips < <(nonloop_ips)
  lip=${ips[0]:-}
  new_tree_pki hip || return 1
  sh="$(shims_dir hip)"
  hc_docker_shim "$sh"
  hc_curl_shim "$sh"
  shimlog="$WORK/hip-docker.log"
  curllog="$WORK/hip-curl.log"
  : >"$shimlog"
  check_not "precondition: nothing listens on 127.0.0.1:24220 (the host port Compose does not publish)" bash -c 'exec 3<>/dev/tcp/127.0.0.1/24220'
  check_not "precondition: nothing listens on 127.0.0.1:9103" bash -c 'exec 3<>/dev/tcp/127.0.0.1/9103'

  # --- unpublished ports: Fluentd answers only on the container IP; the first IP of fluentd-1 is dead
  if [[ -n "$lip" ]]; then
    hc_fd_spec "$WORK/hip-a.json" "$lip"
    start_mock hip-a "$WORK/hip-a.json"
    pid_a=$MOCK_LAST_PID
    PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vendetta-stack \
      SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$dead,$lip fluentd-2=$lip" HC_TCP_TIMEOUT=1 \
      t_run "unpublished Fluentd ports → reached through container IPs → healthy" 0 "$S/healthcheck.sh" --only fluentd --timeout 3
    out_has "fluentd-1 verified over the container IP" 'fluentd-1 +OK .*monitor_agent ok.*:24231/metrics ok'
    out_has "fluentd-2 verified over the container IP" 'fluentd-2 +OK '
    out_has "aggregate row OK" 'fluentd \(active-active\) +OK .*both aggregators healthy'
    eq "monitor_agent queried once per aggregator on the container IP" 2 "$(req_count hip-a '.listener == "a" and .path == "/api/plugins.json"')"
    check "curl was told the service name for the container IP (--resolve)" grep -Fq "resolve = \"fluentd-1:24220:$lip\"" "$curllog"
    check "the second IP (first one that answers the TCP probe) is used" grep -Fq "resolve = \"fluentd-1:24231:$lip\"" "$curllog"
    check_not "the dead container IP is never used for a request" grep -Fq "resolve = \"fluentd-1:24220:$dead\"" "$curllog"

    # --- same, with the container found by name only (`compose ps -q` empty) in a custom project (COMPOSE_PROJECT_NAME)
    : >"$shimlog"
    PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vsproj SHIM_PROJECT=vsproj SHIM_NAME_STYLE=1 \
      SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$lip fluentd-2=$lip" \
      t_run "container located as <project>-<svc>-1 (COMPOSE_PROJECT_NAME honoured) → healthy" 0 "$S/healthcheck.sh" --only fluentd --timeout 3
    out_has "found by container name" 'fluentd-1 +OK '
    check "docker inspect used the <project>-<svc>-1 name" grep -Fq 'inspect -f {{.State.Running}} vsproj-fluentd-1-1' "$shimlog"
    PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vendetta-stack SHIM_PROJECT=vsproj SHIM_NAME_STYLE=1 \
      SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$lip fluentd-2=$lip" \
      t_run "container not found under the configured project → unchanged FAIL" 2 "$S/healthcheck.sh" --only fluentd --timeout 3
    out_has "connection refused on the host port" 'fluentd-1 +FAIL .*connection refused'
    out_has "no aggregator" 'fluentd \(active-active\) +FAIL .*no Fluentd aggregator is healthy'

    # --- one aggregator verified over its IP, the other only healthy per Docker
    PATH="$sh:$PATH" SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$dead fluentd-2=$lip" SHIM_HEALTH=healthy HC_TCP_TIMEOUT=1 COMPOSE_PROJECT_NAME=vendetta-stack \
      t_run "one aggregator verified, one only healthy per docker → degraded" 1 "$S/healthcheck.sh" --only fluentd --timeout 3
    out_has "one verified aggregator" 'fluentd-2 +OK '
    out_has "redundancy note mentions docker-only" 'only one aggregator healthy \(no redundancy\).*healthy per docker'
    stop_mock "$pid_a"
  else
    pass "no routable non-loopback address on this host: container-IP success paths not exercised"
  fi

  # --- healthy per Docker but unreachable from the host (monitor_agent binds the container loopback) → WARN, never OK
  PATH="$sh:$PATH" SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$dead fluentd-2=$dead" SHIM_HEALTH=healthy HC_TCP_TIMEOUT=1 COMPOSE_PROJECT_NAME=vendetta-stack \
    t_run "unreachable but healthy per docker → degraded (exit 1)" 1 "$S/healthcheck.sh" --only fluentd --timeout 2
  out_has "WARN row with the documented wording" 'fluentd-1 +WARN .*healthy per docker, HTTP not reachable from host'
  out_lacks "never reported OK on docker health alone" 'fluentd-[12] +OK '
  out_has "aggregate stays WARN" 'fluentd \(active-active\) +WARN .*no aggregator verified over HTTP'
  for t in unhealthy starting none; do
    PATH="$sh:$PATH" SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=$dead fluentd-2=$dead" SHIM_HEALTH=$t HC_TCP_TIMEOUT=1 COMPOSE_PROJECT_NAME=vendetta-stack \
      t_run "docker health '$t' is no evidence → FAIL, unhealthy" 2 "$S/healthcheck.sh" --only fluentd --timeout 2
    out_has "FAIL with docker health '$t'" 'fluentd-1 +FAIL .*connection refused'
  done

  # --- docker missing: nothing but the host ports are tried → unchanged FAIL
  nodocker="$(shims_dir hip-nodocker)"
  for t in bash env curl jq awk tr head tail sed grep sort cat date mktemp rm dirname basename uname timeout cut wc stat openssl readlink mkdir chmod mv cp ln touch sleep find xargs; do
    if command -v "$t" >/dev/null 2>&1; then ln -sf "$(command -v "$t")" "$nodocker/$t"; fi
  done
  check_not "fixture: PATH without docker" env PATH="$nodocker" bash -c 'command -v docker'
  PATH="$nodocker" t_run "docker absent → unchanged FAIL" 2 "$S/healthcheck.sh" --only fluentd --timeout 2
  out_has "plain connection refused" 'fluentd-1 +FAIL .*connection refused'
  out_lacks "no docker-based WARN" 'healthy per docker'
  PATH="$sh:$PATH" SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=${lip:-$dead} fluentd-2=${lip:-$dead}" t_run "--no-docker → unchanged FAIL" 2 "$S/healthcheck.sh" --no-docker --only fluentd --timeout 2
  PATH="$sh:$PATH" SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=${lip:-$dead} fluentd-2=${lip:-$dead}" t_run "--transport host never falls back to container IPs" 2 "$S/healthcheck.sh" --transport host --only fluentd --timeout 2

  # --- published port reachable on the host → used as before; the container IP is never even looked up
  hc_fd_spec "$WORK/hip-c.json" 127.0.0.1
  start_mock hip-c "$WORK/hip-c.json"
  pid_c=$MOCK_LAST_PID
  pid_d=""
  if [[ -n "$lip" ]]; then
    hc_fd_spec "$WORK/hip-d.json" "$lip"
    start_mock hip-d "$WORK/hip-d.json"
    pid_d=$MOCK_LAST_PID
  fi
  : >"$shimlog"
  : >"$curllog"
  PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vendetta-stack \
    SHIM_RUNNING="fluentd-1 fluentd-2" SHIM_IPS="fluentd-1=${lip:-$dead} fluentd-2=${lip:-$dead}" \
    t_run "published port reachable → host path, healthy" 0 "$S/healthcheck.sh" --only fluentd --timeout 3
  out_has "both aggregators OK via 127.0.0.1" 'fluentd \(active-active\) +OK .*both aggregators healthy'
  eq "the host mock answered both aggregators" 2 "$(req_count hip-c '.path == "/api/plugins.json"')"
  if [[ -n "$pid_d" ]]; then eq "the container-IP mock was not contacted" 0 "$(req_count hip-d true)"; fi
  check_not "no --resolve on the host path" grep -Fq 'resolve =' "$curllog"
  check_not "container IPs never inspected on the host path" grep -Fq 'IPAddress' "$shimlog"
  stop_mock "$pid_c"
  if [[ -n "$pid_d" ]]; then stop_mock "$pid_d"; fi

  # --- TLS stays verified on the container-IP path: right name passes, wrong certificate name fails, never -k
  if [[ -n "$lip" ]]; then
    : >"$curllog"
    hc_errow_spec "$WORK/hip-e.json" "$lip" "$lip" errow-mcp
    start_mock hip-e "$WORK/hip-e.json"
    PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vendetta-stack \
      SHIM_RUNNING="errow-mcp errow-feedback" SHIM_IPS="errow-mcp=$lip errow-feedback=$lip" \
      t_run "errow-mcp over its container IP with mTLS → healthy" 0 "$S/healthcheck.sh" --only errow --timeout 3
    out_has "errow-mcp OK" 'errow-mcp +OK .*mTLS ok'
    out_has "errow-feedback OK" 'errow-feedback +OK '
    check "TLS verified with the stack CA" grep -Fq "cacert = \"$TREE/pki/ca.crt\"" "$curllog"
    check "SNI/SAN name pinned to the container IP" grep -Fq "resolve = \"errow-mcp:9103:$lip\"" "$curllog"
    check_not "no -k / --insecure in any curl invocation" grep -Eq -- '(^| )(-k|--insecure)( |$)|^insecure' "$curllog"
    stop_mock "$MOCK_LAST_PID"
    hc_errow_spec "$WORK/hip-f.json" "$lip" "$lip" llm-gateway
    start_mock hip-f "$WORK/hip-f.json"
    PATH="$sh:$PATH" SHIM_CURL_LOG="$curllog" SHIM_LOG="$shimlog" COMPOSE_PROJECT_NAME=vendetta-stack \
      SHIM_RUNNING="errow-mcp errow-feedback" SHIM_IPS="errow-mcp=$lip errow-feedback=$lip" \
      t_run "certificate for another name on the container IP → TLS FAIL (soft → degraded)" 1 "$S/healthcheck.sh" --only errow --timeout 3
    out_has "TLS verification failure reported" 'errow-mcp +FAIL .*TLS verification failed'
    check_not "still no -k / --insecure" grep -Eq -- '(^| )(-k|--insecure)( |$)|^insecure' "$curllog"
    stop_mock "$MOCK_LAST_PID"
  fi
  check_not "healthcheck.sh and vs_http never build an insecure curl call" grep -Eq -- 'curl .*(--insecure| -k )|^[[:space:]]*insecure|"insecure' "$S/healthcheck.sh" "$S/lib/common.sh"
}
