# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted jq programs are intentional
# Cases: enroll-agent.sh — native authd over TLS (mock_authd.py), the manager-API fallback (mock_stack.py), an agent-auth shim,
# and the edge-forwarder rendering.

AEA_KEY64=$(printf 'a%.0s' {1..64})

start_authd() { # <name> <password-file> — sets AUTHD_PID, AUTHD_PORT; request log $WORK/<name>.authd.jsonl
  local name=$1
  rm -f -- "$WORK/$name.authd.port" "$WORK/$name.authd.jsonl"
  timeout 600 python3 "$HERE/mock_authd.py" --cert "$TREE/pki/vendetta-manager.crt" --key "$TREE/pki/vendetta-manager.key" \
    --password-file "$2" --port-file "$WORK/$name.authd.port" --log "$WORK/$name.authd.jsonl" >"$WORK/$name.authd.out" 2>&1 &
  AUTHD_PID=$!
  MOCK_PIDS+=("$AUTHD_PID")
  wait_file "$WORK/$name.authd.port"
  AUTHD_PORT="$(<"$WORK/$name.authd.port")"
  : >>"$WORK/$name.authd.jsonl"
}

authd_count() { # <name> <outcome> — requests the mock answered with that outcome
  jq -s --arg o "$2" '[.[] | select(.outcome == $o)] | length' "$WORK/$1.authd.jsonl"
}

# aea_api_spec <out.json> — EA_API_PW (basic-auth password), EA_EXISTING (manager-side agent id or empty), EA_KEY_FORMAT (b64|hex|bad)
aea_api_spec() {
  local key
  case "${EA_KEY_FORMAT:-b64}" in
    b64) key="$(printf '010 api-1 any %s' "$AEA_KEY64" | base64 -w0)" ;;
    hex) key="$AEA_KEY64" ;;
    *) key="not-a-key" ;;
  esac
  jq -n --arg pki "$TREE/pki" --arg pw "${EA_API_PW:-api-pass}" --arg key "$key" --arg existing "${EA_EXISTING:-}" '
    {listeners: [{name: "api", tls: {cert: "\($pki)/vendetta-manager.crt", key: "\($pki)/vendetta-manager.key", ca: "\($pki)/ca.crt", require_client_cert: false},
      routes: {
        "POST /security/user/authenticate": {auth: {basic: "vendetta:\($pw)"}, text: "jwt.token.value"},
        "GET /agents": {auth: {bearer: "jwt.token.value"}, json: {data: {affected_items: (if $existing == "" then [] else [{id: $existing}] end)}}},
        "DELETE /agents": {auth: {bearer: "jwt.token.value"}, json: {data: {affected_items: [$existing]}}},
        "POST /agents/insert": {auth: {bearer: "jwt.token.value"}, json: {data: {id: "010", key: $key}}},
        "PUT /agents/010/group/linux": {auth: {bearer: "jwt.token.value"}, json: {data: {}}}
      }}]}' >"$1"
}

aea_api_start() { # <mock-name> — sets AEA_PID, AEA_PORT
  aea_api_spec "$WORK/$1.json"
  start_mock "$1" "$WORK/$1.json"
  AEA_PID=$MOCK_LAST_PID
  AEA_PORT="$(mock_port "$1" api)"
}

case_enroll_agent_usage() {
  local pwf
  new_tree_pki eau || return 1
  pwf="$WORK/eau.pw"
  printf 'authd-secret' >"$pwf"; chmod 600 "$pwf"
  local base=("$S/enroll-agent.sh" --manager manager.example --agent-name host-1 --skip-forwarder --vendetta-home "$WORK/eau-home")

  t_run "--help" 0 "$S/enroll-agent.sh" --help
  out_has "help documents the exit codes" 'Exit codes: 0 ok'
  t_run "--manager is required" 2 "$S/enroll-agent.sh" --skip-forwarder
  t_run "invalid --manager" 2 "$S/enroll-agent.sh" --manager 'bad host!' --skip-forwarder
  t_run "invalid --authd-port" 2 "${base[@]}" --authd-port 0
  t_run "invalid --agent-name" 2 "${base[@]}" --agent-name 'x y'
  t_run "invalid --group" 2 "${base[@]}" --group 'a/b'
  t_run "invalid --method" 2 "${base[@]}" --method ssh
  t_run "invalid --forward-host" 2 "${base[@]}" --forward-host 'bad host'
  t_run "--auth-cert needs --auth-key" 2 "${base[@]}" --auth-cert "$TREE/pki/errow.crt"
  t_run "--client-cert needs --client-key" 2 "${base[@]}" --client-cert "$TREE/pki/errow.crt"
  t_run "--client-cert and --issue-client-cert conflict" 2 "$S/enroll-agent.sh" --manager m.example --client-cert "$TREE/pki/errow.crt" --client-key "$TREE/pki/errow.key" --issue-client-cert
  t_run "the forwarder needs a client identity" 2 "$S/enroll-agent.sh" --manager m.example --skip-enroll
  out_has "identity options named" '--issue-client-cert'
  t_run "authd without a password source" 2 "${base[@]}" --method authd
  out_has "password options named" '--password-file'
  t_run "api method without the password file" 2 "${base[@]}" --method api --api-password-file "$WORK/none"
  t_run "agent-auth method without the binary" 4 "${base[@]}" --method agent-auth --password-file "$pwf"
  local refused=("${base[@]}" --vendetta-home "$WORK/eau-refused" --method authd --password-file "$pwf")
  CS3_PROFILE=onprem OPENAI_API_KEY=sk-test t_run "FailClosed: cloud LLM key under onprem → 3" 3 "${refused[@]}"
  out_has "FailClosedError" 'FailClosedError'
  CS3_PROFILE=onprem t_run "unverified manager TLS is refused under onprem (3)" 3 "${refused[@]}" --allow-unverified-manager
  CS3_PROFILE=airgap t_run "unverified manager TLS is refused under airgap (3)" 3 "${refused[@]}" --allow-unverified-manager
  check_not "nothing created by policy refusals" test -e "$WORK/eau-refused"
}

case_enroll_agent_dry_run() {
  local pwf home fdir
  new_tree_pki ead || return 1
  pwf="$WORK/ead.pw"; home="$WORK/ead-home"; fdir="$WORK/ead-fwd"
  printf 'authd-secret' >"$pwf"; chmod 600 "$pwf"
  t_run "--dry-run plans enrollment and forwarder without touching anything" 0 "$S/enroll-agent.sh" --manager manager.example --agent-name host-1 \
    --method authd --password-file "$pwf" --vendetta-home "$home" --issue-client-cert --forwarder-dir "$fdir" --buffer-dir "$WORK/ead-buf" --dry-run
  out_has "enrollment planned" 'would enroll via authd against manager\.example'
  out_has "forwarder planned" 'would write .*upstream\.conf'
  out_has "client cert issuance planned" 'would issue a client certificate CN=host-1'
  check_not "no vendetta home" test -e "$home"
  check_not "no forwarder dir" test -e "$fdir"
  out_lacks "password never printed" 'authd-secret'
}

case_enroll_agent_authd() {
  local pwf home n before
  new_tree_pki eaa || return 1
  pwf="$WORK/eaa.pw"; home="$WORK/eaa-home"
  printf 'authd-secret' >"$pwf"; chmod 600 "$pwf"
  start_authd eaa "$pwf"
  local base=("$S/enroll-agent.sh" --manager localhost --authd-port "$AUTHD_PORT" --method authd --password-file "$pwf" --vendetta-home "$home" --skip-forwarder)

  t_run "enroll over authd with a verified manager certificate" 0 "${base[@]}" --agent-name web-01
  out_has "enrolled" 'enrolled as id 001'
  out_has "summary" 'agent: name=web-01 id=001 enrollment=enrolled method=authd'
  out_lacks "password never printed" 'authd-secret'
  out_has "ossec.conf hint" 'ossec\.conf not found'
  mode_is "client.keys mode" 640 "$home/etc/client.keys"
  check "client.keys entry is well formed" grep -Eq '^001 web-01 any [0-9a-f]{64}$' "$home/etc/client.keys"
  out_lacks "key never printed" '[0-9a-f]{64}'

  before="$(tree_hashes "$home")"
  t_run "re-running is idempotent (no second enrollment)" 0 "${base[@]}" --agent-name web-01
  out_has "reused" 'already enrolled as id 001'
  eq "nothing changed" "$before" "$(tree_hashes "$home")"
  eq "the manager saw exactly one enrollment" 1 "$(authd_count eaa enrolled)"

  mkdir -p "$home/etc"
  printf '<ossec_config><client><server><address>0.0.0.0</address><port>1514</port></server></client></ossec_config>\n' >"$home/etc/ossec.conf"
  t_run "a second agent gets its own key; the first is kept" 0 "${base[@]}" --agent-name web-02 --group linux --agent-ip 10.1.2.3
  check "second entry" grep -Eq '^002 web-02 10\.1\.2\.3 [0-9a-f]{64}$' "$home/etc/client.keys"
  check "first entry kept" grep -Eq '^001 web-01 any ' "$home/etc/client.keys"
  eq "group and IP forwarded to authd" "linux 10.1.2.3" "$(jq -r 'select(.name == "web-02") | "\(.group) \(.ip)"' "$WORK/eaa.authd.jsonl")"
  check "ossec.conf now points at the manager" grep -q '<address>localhost</address>' "$home/etc/ossec.conf"
  check "ossec.conf backed up" test -n "$(find "$home/etc" -name 'ossec.conf.bak.*' -print -quit)"
  t_run "ossec.conf already pointing at the manager is left alone" 0 "${base[@]}" --agent-name web-03
  out_has "no rewrite" 'ossec\.conf already points at localhost'

  t_run "--manager as an IP address verifies against the certificate IP SAN" 0 "${base[@]}" --manager 127.0.0.1 --agent-name web-04
  out_has "ip enrolment" 'enrolled as id 004'

  t_run "--force-reenroll against a manager that already knows the name → refused (5)" 5 "${base[@]}" --agent-name web-01 --force-reenroll
  out_has "duplicate explained" 'already holds an agent named web-01'
  check "the local key survives a refused re-enrollment" grep -Eq '^001 web-01 any ' "$home/etc/client.keys"

  printf 'wrong-secret' >"$WORK/eaa.badpw"; chmod 600 "$WORK/eaa.badpw"
  t_run "wrong authd password → refused (5)" 5 "${base[@]}" --agent-name web-05 --password-file "$WORK/eaa.badpw"
  out_has "refusal reported" 'authd refused the enrollment: ERROR: Invalid password'
  out_lacks "wrong password never printed" 'wrong-secret'
  t_run "no password at all against a manager that wants one → refused (5)" 5 "${base[@]}" --agent-name web-05 --no-password
  check_not "no key stored for a refused agent" grep -q web-05 "$home/etc/client.keys"

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/eaa-other.key" -out "$WORK/eaa-other-ca.crt" -subj "/CN=other-ca" -days 2 2>/dev/null
  t_run "manager certificate not issued by the given CA → refused (5)" 5 "${base[@]}" --agent-name web-06 --ca "$WORK/eaa-other-ca.crt"
  out_has "TLS failure explained" 'TLS verification of localhost:[0-9]+ failed'
  t_run "--allow-unverified-manager works in a dev profile" 0 "${base[@]}" --agent-name web-07 --ca "$WORK/eaa-other-ca.crt" --allow-unverified-manager
  out_has "loudly warned" 'verification DISABLED'
  t_run "manager down → exit 5" 5 "${base[@]}" --agent-name web-08 --authd-port 1
  out_has "no usable answer" 'no usable answer from localhost:1'

  n="$(wc -l <"$home/etc/client.keys" | tr -d ' ')"
  eq "client.keys holds web-01..04 and web-07" 5 "$n"
  mode_is "client.keys still 0640" 640 "$home/etc/client.keys"
  stop_mock "$AUTHD_PID"
}

case_enroll_agent_agent_auth() {
  local pwf home sh log
  new_tree_pki eag || return 1
  pwf="$WORK/eag.pw"; home="$WORK/eag-home"; sh="$home/bin"; log="$WORK/eag.argv"
  printf 'authd-secret' >"$pwf"; chmod 600 "$pwf"
  mkdir -p "$sh" "$home/etc"
  write_shim "$sh" agent-auth <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SHIM_LOG"
name=""
while (($#)); do
  case "$1" in -A) name=$2; shift 2 ;; *) shift ;; esac
done
if [[ "${SHIM_FAIL:-0}" == 1 ]]; then echo "agent-auth: connection refused" >&2; exit 1; fi
if [[ "${SHIM_NOKEY:-0}" == 1 ]]; then exit 0; fi
printf '007 %s any %s\n' "$name" "$(printf 'c%.0s' {1..64})" >>"$SHIM_HOME/etc/client.keys"
EOF
  export SHIM_LOG="$log" SHIM_HOME="$home"
  local base=("$S/enroll-agent.sh" --manager manager.example --vendetta-home "$home" --skip-forwarder --password-file "$pwf")

  t_run "auto prefers the agent-auth binary when installed" 0 "${base[@]}" --agent-name ag-1 --group linux
  out_has "method reported" 'method=agent-auth'
  check "the shim's key was adopted" grep -Eq '^007 ag-1 any c{64}$' "$home/etc/client.keys"
  check "CA, group and manager passed on argv" grep -Eq -- '-m manager\.example -p 1515 -A ag-1 -G linux -v .*/pki/ca\.crt' "$log"
  check_not "the password never appears on argv" grep -q 'authd-secret' "$log"
  eq "the password is handed over as a file" 'authd-secret' "$(cat "$home/etc/authd.pass")"
  mode_is "authd.pass mode" 640 "$home/etc/authd.pass"

  SHIM_FAIL=1 t_run "agent-auth failure → manager refused (5)" 5 "${base[@]}" --agent-name ag-2
  out_has "failure reported" 'agent-auth failed \(exit 1\): agent-auth: connection refused'
  SHIM_NOKEY=1 t_run "agent-auth success without a key → failure (1)" 1 "${base[@]}" --agent-name ag-3
  out_has "explained" 'has no entry for ag-3'
  t_run "--no-password skips the password hand-over" 0 "$S/enroll-agent.sh" --manager manager.example --vendetta-home "$home" --skip-forwarder --no-password --agent-name ag-4
  unset SHIM_LOG SHIM_HOME
}

case_enroll_agent_api() {
  local pwf home before
  new_tree_pki eap || return 1
  pwf="$WORK/eap.apipw"; home="$WORK/eap-home"
  printf 'api-pass' >"$pwf"; chmod 600 "$pwf"
  aea_api_start eap
  local base=("$S/enroll-agent.sh" --manager localhost --api-port "$AEA_PORT" --method api --api-password-file "$pwf" --vendetta-home "$home" --skip-forwarder --agent-name api-1)

  t_run "enroll through the manager API (POST /agents/insert)" 0 "${base[@]}"
  out_has "summary" 'agent: name=api-1 id=010 enrollment=enrolled method=api'
  check "key decoded from the API reply" grep -Eq '^010 api-1 any a{64}$' "$home/etc/client.keys"
  eq "one insert" 1 "$(req_count eap '.method == "POST" and .path == "/agents/insert"')"
  eq "every request after login carried the bearer" 0 "$(req_count eap '.path != "/security/user/authenticate" and .auth_ok == false')"
  out_lacks "password never printed" 'api-pass'
  out_lacks "JWT never printed" 'jwt\.token\.value'

  before="$(tree_hashes "$home")"
  t_run "idempotent by name: no API call on re-run" 0 "${base[@]}"
  out_has "reused" 'already enrolled as id 010'
  eq "still one insert" 1 "$(req_count eap '.method == "POST" and .path == "/agents/insert"')"
  eq "nothing changed" "$before" "$(tree_hashes "$home")"

  rm -rf -- "$home"
  t_run "--group is applied with PUT /agents/<id>/group/<g>" 0 "${base[@]}" --group linux
  eq "group call made" 1 "$(req_count eap '.method == "PUT" and .path == "/agents/010/group/linux"')"

  rm -rf -- "$home"
  printf 'bad' >"$WORK/eap.badpw"; chmod 600 "$WORK/eap.badpw"
  t_run "wrong API password → refused (5)" 5 "${base[@]}" --api-password-file "$WORK/eap.badpw"
  out_has "auth failure reported" 'API authentication failed \(HTTP 401\)'
  check_not "no key stored" test -e "$home/etc/client.keys"

  t_run "--method auto without agent-auth or a password file falls back to the API" 0 "$S/enroll-agent.sh" --manager localhost --api-port "$AEA_PORT" \
    --api-password-file "$pwf" --vendetta-home "$home" --skip-forwarder --agent-name api-1
  out_has "api chosen" 'method=api'
  stop_mock "$AEA_PID"

  EA_EXISTING=005 aea_api_start eap2
  rm -rf -- "$home"
  t_run "a name the manager already holds, without a local key → refused (5)" 5 "${base[@]}" --api-port "$AEA_PORT"
  out_has "explained" 'already exists on the manager \(id 005\)'
  eq "nothing inserted" 0 "$(req_count eap2 '.path == "/agents/insert"')"
  t_run "--force-reenroll deletes the stale manager-side agent first" 0 "${base[@]}" --api-port "$AEA_PORT" --force-reenroll
  eq "stale agent deleted" 1 "$(req_count eap2 '.method == "DELETE" and .path == "/agents"')"
  eq "then re-inserted" 1 "$(req_count eap2 '.path == "/agents/insert"')"
  stop_mock "$AEA_PID"

  EA_KEY_FORMAT=hex aea_api_start eap3
  rm -rf -- "$home"
  t_run "a raw 64-hex key from the API is assembled into a client.keys line" 0 "${base[@]}" --api-port "$AEA_PORT"
  check "assembled" grep -Eq '^010 api-1 any a{64}$' "$home/etc/client.keys"
  stop_mock "$AEA_PID"

  EA_KEY_FORMAT=bad aea_api_start eap4
  rm -rf -- "$home"
  t_run "an unrecognised key format is never stored (1)" 1 "${base[@]}" --api-port "$AEA_PORT"
  out_has "explained" 'unrecognised key format'
  check_not "no key file" test -e "$home/etc/client.keys"
  stop_mock "$AEA_PID"
}

case_enroll_agent_forwarder() {
  local fdir buf before sh subj ekus
  new_tree_pki eaf || return 1
  fdir="$WORK/eaf-fwd"; buf="$WORK/eaf-buf"; sh="$(shims_dir eaf)"
  local base=("$S/enroll-agent.sh" --manager manager.example --agent-name edge-1 --skip-enroll --forwarder-dir "$fdir" --buffer-dir "$buf"
    --forward-host fluentd-1:24224 --forward-host fluentd-2 --issue-client-cert)

  t_run "render the edge forwarder with an issued client certificate" 0 "${base[@]}"
  out_has "certificate issued" 'issued client certificate CN=edge-1'
  check "fluent-bit.conf" test -s "$fdir/fluent-bit.conf"
  check "upstream.conf" test -s "$fdir/upstream.conf"
  mode_is "client key mode" 600 "$fdir/pki/client.key"
  mode_is "pki dir mode" 700 "$fdir/pki"
  check "client cert verifies against the stack CA" openssl verify -CAfile "$TREE/pki/ca.crt" "$fdir/pki/client.crt"
  # RFC2253 keeps the format stable across OpenSSL releases (the default spacing around "=" has changed)
  subj="$(openssl x509 -in "$fdir/pki/client.crt" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  eq "client cert subject" "CN=edge-1,O=Vendetta Stack" "$subj"
  ekus="$(openssl x509 -in "$fdir/pki/client.crt" -noout -ext extendedKeyUsage)"
  check "clientAuth EKU" grep -q 'TLS Web Client Authentication' <<<"$ekus"
  eq "client key matches the cert" "$(openssl x509 -in "$fdir/pki/client.crt" -noout -pubkey)" "$(openssl pkey -in "$fdir/pki/client.key" -pubout)"
  eq "two upstream nodes" 2 "$(grep -c '^\[NODE\]' "$fdir/upstream.conf")"
  check "TLS verification is on for every node" test "$(grep -c 'tls.verify on' "$fdir/upstream.conf")" -eq 2
  check "second node defaults to 24224" grep -Eq '^    Port       24224$' "$fdir/upstream.conf"
  check "tls.vhost pins the server name" grep -q 'tls.vhost  fluentd-2' "$fdir/upstream.conf"
  check "buffering is filesystem-backed" grep -q 'storage.type              filesystem' "$fdir/fluent-bit.conf"
  check "journal input present" grep -q 'Name                      systemd' "$fdir/fluent-bit.conf"
  check "events are stamped with the agent" grep -q 'Record                    agent_name edge-1' "$fdir/fluent-bit.conf"
  check "unenrolled id when enrollment was skipped" grep -q 'agent_id unenrolled' "$fdir/fluent-bit.conf"
  check_not "no private key text inside the configs" grep -rq 'PRIVATE KEY' "$fdir/fluent-bit.conf" "$fdir/upstream.conf"

  before="$(tree_hashes "$fdir")"
  t_run "re-running changes nothing" 0 "${base[@]}"
  out_has "certificate kept" 'still valid — kept'
  out_has "configs unchanged" 'fluent-bit\.conf unchanged'
  eq "no file changed" "$before" "$(tree_hashes "$fdir")"

  t_run "--no-journal re-renders without the journal input" 0 "${base[@]}" --no-journal
  check_not "journal input removed" grep -q 'host_journal' "$fdir/fluent-bit.conf"

  EDGE_FORWARD_HOSTS=agg-a.example:2424,agg-b.example t_run "default aggregators come from EDGE_FORWARD_HOSTS" 0 "$S/enroll-agent.sh" --manager m.example --agent-name edge-1 \
    --skip-enroll --forwarder-dir "$fdir" --buffer-dir "$buf" --issue-client-cert
  check "env host with a custom port" grep -Eq '^    Port       2424$' "$fdir/upstream.conf"
  check "env host with the default port" grep -q 'Host       agg-b.example' "$fdir/upstream.conf"

  t_run "an existing client identity is installed (key 0600)" 0 "$S/enroll-agent.sh" --manager m.example --agent-name edge-1 --skip-enroll \
    --forwarder-dir "$WORK/eaf-fwd2" --buffer-dir "$buf" --client-cert "$TREE/pki/errow.crt" --client-key "$TREE/pki/errow.key"
  mode_is "installed key mode" 600 "$WORK/eaf-fwd2/pki/client.key"
  check "installed cert is the supplied one" cmp -s "$TREE/pki/errow.crt" "$WORK/eaf-fwd2/pki/client.crt"
  t_run "a key that does not match the certificate is refused (2)" 2 "$S/enroll-agent.sh" --manager m.example --agent-name edge-1 --skip-enroll \
    --forwarder-dir "$WORK/eaf-fwd3" --buffer-dir "$buf" --client-cert "$TREE/pki/errow.crt" --client-key "$TREE/pki/errow-mcp.key"
  out_has "mismatch named" 'does not match'

  t_run "--install-systemd without a Fluent Bit binary → prerequisite (4)" 4 "${base[@]}" --install-systemd
  write_shim "$sh" fb <<'EOF'
#!/usr/bin/env bash
if [[ "${FB_FAIL:-0}" == 1 ]]; then echo "[error] invalid plugin" >&2; exit 1; fi
[[ "$1" == --dry-run && "$2" == -c && -s "$3" ]]
EOF
  t_run "the rendered config is syntax-checked with Fluent Bit --dry-run" 0 "${base[@]}" --fluent-bit-bin "$sh/fb"
  out_has "accepted" 'Fluent Bit accepted the rendered configuration'
  FB_FAIL=1 t_run "a rejected config fails the run (1)" 1 "${base[@]}" --fluent-bit-bin "$sh/fb"
  out_has "rejection reported" 'rejected the rendered configuration: \[error\] invalid plugin'
}

case_enroll_agent_combined() {
  local pwf home fdir
  new_tree_pki eac || return 1
  pwf="$WORK/eac.pw"; home="$WORK/eac-home"; fdir="$WORK/eac-fwd"
  printf 'authd-secret' >"$pwf"; chmod 600 "$pwf"
  start_authd eac "$pwf"
  t_run "enroll and configure the forwarder in one run" 0 "$S/enroll-agent.sh" --manager localhost --authd-port "$AUTHD_PORT" --agent-name host-9 \
    --method authd --password-file "$pwf" --vendetta-home "$home" --forwarder-dir "$fdir" --buffer-dir "$WORK/eac-buf" --issue-client-cert
  out_has "summary" "agent: name=host-9 id=001 enrollment=enrolled method=authd forwarder=$fdir"
  check "the forwarder config carries the enrolled agent id" grep -q 'Record                    agent_id 001' "$fdir/fluent-bit.conf"
  out_has "next steps printed" 'next steps:'
  stop_mock "$AUTHD_PID"
}
