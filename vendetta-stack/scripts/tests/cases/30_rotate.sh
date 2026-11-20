# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted jq/awk/sed programs and literal $ patterns are intentional
# Cases: rotate-certs.sh — dry-run, re-issue + archive, selective/expiring rotation, rollback, compose reload order,
# CA rotation phases, Kubernetes mode.

fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }

compose_shim() { # <shim-dir> <log-file> — fake docker with a Compose v2 front end that records every action
  write_shim "$1" docker <<EOF
#!/usr/bin/env bash
LOG="$2"
if [[ "\${1:-}" == inspect ]]; then
  # docker inspect -f <fmt> <cid>
  case "\${4:-}" in
    cid-\${SHIM_UNHEALTHY:-none}) echo unhealthy ;;
    *) echo healthy ;;
  esac
  exit 0
fi
[[ "\${1:-}" == compose ]] || { echo "docker shim: unsupported: \$*" >&2; exit 1; }
shift
if [[ "\${1:-}" == version ]]; then echo 2.29.1; exit 0; fi
while (( \$# )); do
  case "\$1" in
    -p|--project-directory|-f|--env-file) shift 2 ;;
    *) break ;;
  esac
done
cmd=\${1:-}; shift || true
case "\$cmd" in
  ps)
    if [[ "\${1:-}" == "--services" ]]; then printf '%s\n' \${SHIM_RUNNING:-opensearch prometheus fluentd-1 fluentd-2 llm-gateway ollama-lb errow-mcp}; exit 0; fi
    if [[ "\${1:-}" == "-q" ]]; then echo "cid-\$2"; exit 0; fi ;;
  kill|restart|up) echo "\$cmd \$*" >>"\$LOG" ;;
  *) echo "docker shim: unsupported compose command: \$cmd" >&2; exit 1 ;;
esac
EOF
}

case_rotate_dry_run_and_issue() {
  local before after name archive
  new_tree_pki rot || return 1
  before="$(tree_hashes "$TREE/pki")"
  t_run "rotate-certs --dry-run" 0 "$S/rotate-certs.sh" --dry-run --no-reload
  after="$(tree_hashes "$TREE/pki")"
  eq "dry-run changes nothing in pki/" "$before" "$after"
  out_has "dry-run lists the certificates it would issue" 'issue opensearch-admin\.crt'
  check_not "dry-run creates no archive" test -d "$TREE/pki-archive/$(date +%Y)"

  t_run "rotate-certs --only-expiring with nothing expiring" 0 "$S/rotate-certs.sh" --only-expiring --no-reload
  out_has "nothing to rotate" 'nothing to rotate'
  eq "no files changed" "$before" "$(tree_hashes "$TREE/pki")"

  local old_errow old_prom old_admin old_ca
  old_errow="$(fp "$TREE/pki/errow.crt")"
  old_prom="$(fp "$TREE/pki/prometheus.crt")"
  old_admin="$(fp "$TREE/pki/opensearch-admin.crt")"
  old_ca="$(fp "$TREE/pki/ca.crt")"
  t_run "rotate only errow + prometheus" 0 "$S/rotate-certs.sh" --services errow,prometheus --no-reload
  check "errow.crt was re-issued" test "$old_errow" != "$(fp "$TREE/pki/errow.crt")"
  check "prometheus.crt was re-issued" test "$old_prom" != "$(fp "$TREE/pki/prometheus.crt")"
  eq "opensearch-admin.crt untouched" "$old_admin" "$(fp "$TREE/pki/opensearch-admin.crt")"
  eq "CA untouched" "$old_ca" "$(fp "$TREE/pki/ca.crt")"
  check "new errow.crt verifies against the CA" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/errow.crt"
  mode_is "new errow.key is 0600" 600 "$TREE/pki/errow.key"
  archive="$(find "$TREE/pki-archive" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  check "previous set archived outside pki/" test -s "$archive/errow.crt"
  eq "archived errow.crt is the previous certificate" "$old_errow" "$(fp "$archive/errow.crt")"
  mode_is "archive dir is 0700" 700 "$archive"
  mode_is "pki-archive root is 0700" 700 "$TREE/pki-archive"
  check_not "pki/ holds no archive directory" test -e "$TREE/pki/archive"
  eq "pki/ contains no subdirectory at all (OpenSearch cannot read an 0700 one)" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  out_has "verification table printed" 'CERTIFICATE +DAYS'

  t_run "rotate every certificate" 0 "$S/rotate-certs.sh" --no-reload
  for name in opensearch fluentd-1 llm-gateway ollama-lb opensearch-admin; do
    check "$name.crt verifies after a full rotation" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/$name.crt"
  done
  t_run "unknown certificate name is a usage error" 2 "$S/rotate-certs.sh" --services nonsense --no-reload
  t_run "--ca-phase without --rotate-ca is a usage error" 2 "$S/rotate-certs.sh" --ca-phase overlap
  t_run "--rotate-ca cannot be combined with --services" 2 "$S/rotate-certs.sh" --rotate-ca --services errow
}

case_rotate_rollback() {
  local before after
  new_tree_pki rot-rb || return 1
  before="$(tree_hashes "$TREE/pki")"
  t_run "re-issue with a validity inside the renewal window fails verification" 1 "$S/rotate-certs.sh" --pki-days 10 --no-reload
  out_has "rollback announced" 'restoring previous files'
  after="$(tree_hashes "$TREE/pki")"
  eq "the previous certificate set is restored exactly" "$before" "$after"
  check_not "the failed run left no archive inside pki/" test -e "$TREE/pki/archive"
  check "the failed run's archive is under pki-archive/" test -n "$(find "$TREE/pki-archive" -mindepth 2 -name errow.crt)"
}

case_rotate_legacy_archive() {
  local arch
  new_tree_pki rot-legacy || return 1
  mkdir -p "$TREE/pki/archive/20250101T000000Z"
  cp -p "$TREE/pki/errow.crt" "$TREE/pki/archive/20250101T000000Z/errow.crt"
  chmod 0700 "$TREE/pki/archive/20250101T000000Z" "$TREE/pki/archive"
  t_run "dry-run reports the legacy archive move" 0 "$S/rotate-certs.sh" --dry-run --no-reload
  out_has "dry-run says what it would move" 'would move pki/archive'
  check "dry-run moved nothing" test -d "$TREE/pki/archive/20250101T000000Z"
  t_run "rotation moves a legacy pki/archive out of the mounted tree" 0 "$S/rotate-certs.sh" --services errow --no-reload
  check_not "pki/archive is gone" test -e "$TREE/pki/archive"
  check "the legacy set is kept under pki-archive/" test -s "$TREE/pki-archive/20250101T000000Z/errow.crt"
  arch="$(find "$TREE/pki-archive" -mindepth 1 -maxdepth 1 -type d -not -name 20250101T000000Z | head -n 1)"
  check "this rotation archived the previous set next to it" test -s "$arch/errow.crt"
  eq "pki/ contains no subdirectory" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  PKI_ARCHIVE_DIR="$TREE/pki/arch" t_run "PKI_ARCHIVE_DIR inside pki/ is refused" 2 "$S/rotate-certs.sh" --services errow --no-reload
  check_not "nothing created inside pki/" test -e "$TREE/pki/arch"
}

case_rotate_compose_reload() {
  local sh log cid_order
  new_tree_pki rot-dc || return 1
  sh="$(shims_dir rot-dc)"
  log="$WORK/rot-dc.log"
  : >"$log"
  compose_shim "$sh" "$log"
  cat >"$WORK/rot-dc.os.json" <<EOF
{"listeners": [{"name": "os", "tls": {"cert": "$TREE/pki/opensearch.crt", "key": "$TREE/pki/opensearch.key", "ca": "$TREE/pki/ca.crt", "require_client_cert": true},
  "routes": {"PUT /_plugins/_security/api/ssl/*": {"status": 200, "json": {"status": "OK"}}}}]}
EOF
  start_mock rot-dc-os "$WORK/rot-dc.os.json"
  PATH="$sh:$PATH" t_run "rotation with compose reload" 0 "$S/rotate-certs.sh" --services opensearch,fluentd-1,fluentd-2,llm-gateway,prometheus --wait 4 \
    --opensearch-url "https://localhost:$(mock_port rot-dc-os os)"
  eq "OpenSearch certificates hot-reloaded over the admin API (transport + http)" 2 "$(req_count rot-dc-os '.method == "PUT" and .auth_ok')"
  check "prometheus got HUP" grep -qx 'kill -s HUP prometheus' "$log"
  check "llm-gateway restarted" grep -qx 'restart llm-gateway' "$log"
  check "ollama-lb HUP follows a gateway restart (shared network namespace)" grep -qx 'kill -s HUP ollama-lb' "$log"
  check_not "services that were not rotated are left alone" grep -q 'errow-mcp' "$log"
  cid_order="$(grep -nE 'restart fluentd-[12]' "$log" | cut -d' ' -f2 | tr '\n' ' ')"
  eq "fluentd-2 is restarted before fluentd-1" "fluentd-2 fluentd-1 " "$cid_order"

  : >"$log"
  SHIM_UNHEALTHY=fluentd-1 PATH="$sh:$PATH" t_run "unhealthy service after the reload → exit 5" 5 "$S/rotate-certs.sh" --services fluentd-1 --wait 0
  out_has "unhealthy service named" 'fluentd-1: not healthy after reload'
  check "certificate was still rotated and verified" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/fluentd-1.crt"

  : >"$log"
  SHIM_RUNNING="prometheus" PATH="$sh:$PATH" t_run "services that are not running are skipped" 0 "$S/rotate-certs.sh" --services errow --wait 4
  out_has "skip reported" 'errow: not running'
  check_not "no action was taken" test -s "$log"
  PATH="$sh:$PATH" t_run "dry-run prints reload actions without running them" 0 "$S/rotate-certs.sh" --dry-run --services fluentd-1
  out_has "dry-run shows the planned restart" 'restart fluentd-1'
  check_not "dry-run executed nothing" test -s "$log"
}

case_rotate_ca_phases() {
  local before_leaf
  new_tree_pki rot-ca || return 1
  before_leaf="$(fp "$TREE/pki/errow.crt")"
  t_run "CA rotation dry-run" 0 "$S/rotate-certs.sh" --rotate-ca --dry-run --no-reload
  check_not "dry-run leaves no rotation state" test -e "$TREE/pki/.rotation-state"

  t_run "--ca-phase finalize cannot be the first phase" 3 "$S/rotate-certs.sh" --rotate-ca --ca-phase finalize --no-reload
  t_run "phase 1: overlap (dual-trust bundle)" 0 "$S/rotate-certs.sh" --rotate-ca --ca-phase overlap --no-reload
  eq "ca.crt now holds two CA certificates" 2 "$(grep -c 'BEGIN CERTIFICATE' "$TREE/pki/ca.crt")"
  eq "leaf certificates are unchanged in the overlap phase" "$before_leaf" "$(fp "$TREE/pki/errow.crt")"
  check "old leaf still verifies against the dual-trust bundle" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/errow.crt"
  check "rotation state recorded" grep -qx 'phase=overlap' "$TREE/pki/.rotation-state"
  t_run "phases cannot be skipped" 3 "$S/rotate-certs.sh" --rotate-ca --ca-phase finalize --no-reload

  t_run "phase 2: reissue under the new CA" 0 "$S/rotate-certs.sh" --rotate-ca --ca-phase reissue --no-reload
  check "errow.crt re-issued" test "$before_leaf" != "$(fp "$TREE/pki/errow.crt")"
  check "new leaf verifies against the dual-trust bundle" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/errow.crt"
  check "new leaf is signed by the NEW CA only" openssl verify -CAfile "$TREE/pki/ca-signer.crt" "$TREE/pki/errow.crt"

  t_run "phase 3: finalize (drop the old CA)" 0 "$S/rotate-certs.sh" --rotate-ca --ca-phase finalize --no-reload
  eq "ca.crt holds the new CA only" 1 "$(grep -c 'BEGIN CERTIFICATE' "$TREE/pki/ca.crt")"
  check_not "rotation state removed" test -e "$TREE/pki/.rotation-state"
  check "every leaf verifies against the final CA" bash -c 'for c in "$1"/*.crt; do case "$c" in */ca.crt|*/ca-signer.crt) continue ;; esac; openssl verify -CAfile "$1/ca.crt" "$c" >/dev/null || exit 1; done' _ "$TREE/pki"
  check "the archive keeps the old CA" bash -c 'grep -l "BEGIN CERTIFICATE" "$1"/*/ca.crt >/dev/null' _ "$TREE/pki-archive"
  check "the old CA's signer/state files are archived too" bash -c 'ls "$1"/*/.rotation-state "$1"/*/ca-signer.crt >/dev/null' _ "$TREE/pki-archive"
  eq "pki/ contains no subdirectory after a full CA rotation" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  check_not "no ca-next.* / ca-signer.crt / .rotation-state is left behind in pki/" bash -c 'ls "$1"/ca-next.* "$1"/ca-signer.crt "$1"/.rotation-state >/dev/null 2>&1' _ "$TREE/pki"
  t_run "bootstrap --check is green after the rotation" 0 "$S/bootstrap.sh" --skip-preflight --check
}

case_rotate_kubernetes() {
  local sh log
  new_tree_pki rot-k8s || return 1
  sh="$(shims_dir rot-k8s)"
  log="$WORK/rot-k8s.log"
  : >"$log"
  write_shim "$sh" kubectl <<EOF
#!/usr/bin/env bash
LOG="$log"
case "\$*" in
  *"get statefulset"*) echo statefulset.apps/opensearch ;;
  *"get deployment"*) echo deployment.apps/llm-gateway ;;
  *"get daemonset"*) ;;
  *"get certificates"*) echo '{"items":[]}' ;;
  *"rollout restart"*|*"rollout status"*) echo "\$*" >>"\$LOG" ;;
  *) echo "kubectl shim: unsupported: \$*" >&2; exit 1 ;;
esac
EOF
  write_shim "$sh" cmctl <<EOF
#!/usr/bin/env bash
echo "cmctl \$*" >>"$log"
EOF
  PATH="$sh:$PATH" t_run "--kubernetes renews and rolls out" 0 "$S/rotate-certs.sh" --kubernetes --namespace vs-test
  check "cert-manager renewal requested for the namespace" grep -qx 'cmctl renew --namespace vs-test --all' "$log"
  check "StatefulSet restarted" grep -q 'rollout restart statefulset.apps/opensearch' "$log"
  check "Deployment restarted" grep -q 'rollout restart deployment.apps/llm-gateway' "$log"
  : >"$log"
  PATH="$sh:$PATH" t_run "--kubernetes --dry-run restarts nothing" 0 "$S/rotate-certs.sh" --kubernetes --dry-run
  check_not "dry-run ran no rollout" test -s "$log"
  rm -f -- "$sh/cmctl"
  PATH="$sh:$(plain_path_dir):/usr/bin:/bin" t_run "--kubernetes without cmctl is a prerequisite error" 4 "$S/rotate-certs.sh" --kubernetes
}
