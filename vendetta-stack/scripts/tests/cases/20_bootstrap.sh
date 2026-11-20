# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted jq/awk/sed programs and literal $ patterns are intentional
# Cases: bootstrap.sh — secrets, PKI (openssl verify, SANs, EKU, idempotency), --check, --dry-run, preflight, FailClosed, .env.

PKI_ALL=(opensearch fluentd-1 fluentd-2 fluent-bit llm-gateway ollama-lb ollama-1 mock-ollama errow-mcp errow errow-feedback prometheus vendetta-manager opensearch-dashboards opensearch-admin)
SECRET_FILES=(opensearch_admin_password llm_gateway_token errow_api_token grafana_admin_password feedback_webhook_token vendetta_api_password cs3_approval_token)

cert_text() { openssl x509 -in "$1" -noout -text 2>/dev/null; }

san_ok() { # <crt> <dns-name> — SAN has the name, localhost and 127.0.0.1
  local san
  san="$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null)"
  [[ "$san" == *"DNS:$2"* && "$san" == *"DNS:localhost"* && "$san" == *"IP Address:127.0.0.1"* ]]
}

eku_ok() {
  local eku
  eku="$(openssl x509 -in "$1" -noout -ext extendedKeyUsage 2>/dev/null)"
  [[ "$eku" == *"TLS Web Server Authentication"* && "$eku" == *"TLS Web Client Authentication"* ]]
}

case_bootstrap_dry_run_and_check() {
  new_tree bs-dry
  t_run "bootstrap --dry-run (fresh tree)" 0 "$S/bootstrap.sh" --skip-preflight --dry-run
  check_not "dry-run created no secrets/" test -e "$TREE/secrets"
  check_not "dry-run created no pki/" test -e "$TREE/pki"
  check_not "dry-run created no .env" test -e "$TREE/.env"
  out_has "dry-run reports the secrets it would create" 'NEW +secret opensearch_admin_password'
  t_run "bootstrap --check on an empty tree reports problems" 5 "$S/bootstrap.sh" --skip-preflight --check
  check_not "--check wrote nothing" test -e "$TREE/secrets"
}

case_bootstrap_secrets_and_pki() {
  local f svc pw before after
  new_tree bs
  t_run "bootstrap (openssl mode)" 0 "$S/bootstrap.sh" --skip-preflight
  out_has "no .env.example yet is handled gracefully" 'SKIP +\.env'
  mode_is "secrets/ directory is 0700" 700 "$TREE/secrets"
  for f in "${SECRET_FILES[@]}"; do
    check "secret $f exists and is not empty" test -s "$TREE/secrets/$f"
    mode_is "secret $f is 0600" 600 "$TREE/secrets/$f"
    check "secret $f has no trailing newline" test -n "$(tail -c1 "$TREE/secrets/$f")"
  done
  pw="$(<"$TREE/secrets/opensearch_admin_password")"
  check "opensearch_admin_password is ≥16 chars with upper/lower/digit/special" \
    bash -c '[[ ${#1} -ge 16 && "$1" =~ [A-Z] && "$1" =~ [a-z] && "$1" =~ [0-9] && "$1" =~ [^A-Za-z0-9] ]]' _ "$pw"
  check "tokens are ≥32 chars" test "$(wc -c <"$TREE/secrets/llm_gateway_token")" -ge 32

  check "ca.crt exists" test -s "$TREE/pki/ca.crt"
  mode_is "ca.key is 0600" 600 "$TREE/pki/ca.key"
  mode_is "pki-archive/ (PKI_ARCHIVE_DIR) is 0700" 700 "$TREE/pki-archive"
  check_not "pki/ has no archive directory (compose mounts pki/ into OpenSearch)" test -e "$TREE/pki/archive"
  eq "pki/ contains no subdirectory at all" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  check "CA is a CA (basicConstraints CA:TRUE)" grep -q 'CA:TRUE' < <(cert_text "$TREE/pki/ca.crt")
  check "CA key is ECDSA P-384 by default" grep -q 'secp384r1' < <(cert_text "$TREE/pki/ca.crt")
  for svc in "${PKI_ALL[@]}"; do
    check "pki/$svc.{crt,key,pem} exist" bash -c 'for e in crt key pem; do test -s "$1/$2.$e" || exit 1; done' _ "$TREE/pki" "$svc"
    check "openssl verify $svc.crt against the private CA" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/$svc.crt"
    check "$svc.crt valid as TLS server" openssl verify -CAfile "$TREE/pki/ca.crt" -purpose sslserver "$TREE/pki/$svc.crt"
    check "$svc.crt valid as TLS client" openssl verify -CAfile "$TREE/pki/ca.crt" -purpose sslclient "$TREE/pki/$svc.crt"
    check "$svc.crt EKU serverAuth+clientAuth" eku_ok "$TREE/pki/$svc.crt"
    mode_is "$svc.key is 0600" 600 "$TREE/pki/$svc.key"
    check "$svc.key is PKCS#8" grep -q 'BEGIN PRIVATE KEY' "$TREE/pki/$svc.key"
    check "$svc.pem bundles certificate and key" bash -c 'grep -q "BEGIN CERTIFICATE" "$1" && grep -q "PRIVATE KEY" "$1"' _ "$TREE/pki/$svc.pem"
    check "$svc.crt matches its key" bash -c 'a="$(openssl x509 -in "$1" -noout -pubkey | sha256sum)"; b="$(openssl pkey -in "$2" -pubout | sha256sum)"; [[ "$a" == "$b" ]]' _ "$TREE/pki/$svc.crt" "$TREE/pki/$svc.key"
    if [[ "$svc" != opensearch-admin ]]; then check "$svc.crt SAN has $svc, localhost, 127.0.0.1" san_ok "$TREE/pki/$svc.crt" "$svc"; fi
  done
  check "ollama-1.crt also covers ollama-workers (LB DNS discovery) and ollama-1-proxy" \
    bash -c 'o="$(openssl x509 -in "$1" -noout -ext subjectAltName)"; [[ "$o" == *DNS:ollama-workers* && "$o" == *DNS:ollama-1-proxy* ]]' _ "$TREE/pki/ollama-1.crt"
  check "opensearch-admin subject is CN=opensearch-admin,O=Vendetta Stack" \
    bash -c 'openssl x509 -in "$1" -noout -subject -nameopt compat | grep -q "CN=opensearch-admin" ' _ "$TREE/pki/opensearch-admin.crt"
  check "opensearch node subject has CN=opensearch" bash -c 'openssl x509 -in "$1" -noout -subject -nameopt compat | grep -q "CN=opensearch"' _ "$TREE/pki/opensearch.crt"
  check "leaf validity is 397 days by default" bash -c 'openssl x509 -in "$1" -noout -checkend $((396*86400)) && ! openssl x509 -in "$1" -noout -checkend $((398*86400))' _ "$TREE/pki/errow.crt"

  t_run "bootstrap --check on a complete tree" 0 "$S/bootstrap.sh" --skip-preflight --check
  out_lacks "--check finds nothing failing" '^FAIL'

  before="$(tree_hashes "$TREE/secrets" "$TREE/pki")"
  t_run "bootstrap re-run (idempotent)" 0 "$S/bootstrap.sh" --skip-preflight
  after="$(tree_hashes "$TREE/secrets" "$TREE/pki")"
  eq "re-run changes no secret and no certificate" "$before" "$after"
  out_has "re-run keeps existing secrets" 'KEEP +secret opensearch_admin_password'
  out_has "re-run keeps valid certificates" 'KEEP +pki/errow'

  rm -f -- "$TREE/pki/errow.crt" "$TREE/pki/errow.key" "$TREE/pki/errow.pem"
  before="$(tree_hashes "$TREE/pki" | grep -v ' \./errow\.')"
  t_run "bootstrap re-issues only the missing certificate" 0 "$S/bootstrap.sh" --skip-preflight
  after="$(tree_hashes "$TREE/pki" | grep -v ' \./errow\.')"
  eq "other certificates untouched" "$before" "$after"
  check "errow.crt re-created and valid" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/errow.crt"

  chmod 0644 "$TREE/secrets/llm_gateway_token"
  t_run "--check flags a world-readable secret" 5 "$S/bootstrap.sh" --skip-preflight --check
  out_has "--check names the loose secret" 'FAIL +secret llm_gateway_token'
}

case_bootstrap_approval_dir() {
  local h
  new_tree bs-appr
  t_run "--dry-run plans the approval dir" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --dry-run
  out_has "dry-run reports the approval dir as NEW" 'NEW +approval dir +would be created \(mode 0700\)'
  check_not "dry-run created nothing" test -e "$TREE/secrets"
  t_run "--check on a tree without secrets/approval fails" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "--check explains the root-owned auto-create" 'FAIL +approval dir .*root-owned'
  t_run "bootstrap creates secrets/approval" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  check "secrets/approval is a directory" test -d "$TREE/secrets/approval"
  mode_is "secrets/approval is 0700" 700 "$TREE/secrets/approval"
  out_has "approval dir reported NEW" 'NEW +approval dir +created \(mode 0700\)'
  check_not "feedback_approval_key is never generated" test -e "$TREE/secrets/approval/feedback_approval_key"
  check_not "feedback_approval_key is not a bootstrap-managed secret" bash -c 'source "$1/lib/common.sh"; printf "%s\n" "${VS_SECRET_NAMES[@]}" | grep -qx feedback_approval_key' _ "$S"
  out_has "NOTE row: the key is opt-in and operator-generated" 'NOTE +feedback_approval_key +not generated: live feedback is opt-in; the operator creates it per errow/feedback-loop/APPROVALS\.md'
  t_run "--check passes once the directory exists" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "--check still prints the NOTE row" 'NOTE +feedback_approval_key'

  printf 'operator-generated-key' >"$TREE/secrets/approval/feedback_approval_key"
  chmod 0600 "$TREE/secrets/approval/feedback_approval_key"
  h="$(tree_hashes "$TREE/secrets")"
  t_run "re-run with an operator key present" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  eq "the operator's key and all secrets are untouched" "$h" "$(tree_hashes "$TREE/secrets")"
  out_has "re-run keeps the approval dir" 'KEEP +approval dir'
  out_has "re-run keeps the key" 'KEEP +feedback_approval_key +present — never touched'
  out_lacks "no NOTE when the key exists" 'NOTE +feedback_approval_key'
  chmod 0644 "$TREE/secrets/approval/feedback_approval_key"
  t_run "--check warns about a loose key mode" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "loose key mode named" 'WARN +feedback_approval_key +mode 644'
  chmod 0755 "$TREE/secrets/approval"
  t_run "--check fails on a loose approval dir mode" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "loose dir mode named" 'FAIL +approval dir +mode 755 is looser than 0700'
  t_run "bootstrap tightens a loose approval dir" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  mode_is "approval dir back to 0700" 700 "$TREE/secrets/approval"

  rm -f -- "$TREE/secrets/approval/feedback_approval_key"
  ERROW_FEEDBACK_LIVE=true t_run "ERROW_FEEDBACK_LIVE=true without the key: --check fails" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "names APPROVALS.md" 'FAIL +feedback_approval_key +ERROW_FEEDBACK_LIVE=true but the key is missing.*APPROVALS\.md'
  ERROW_FEEDBACK_LIVE=true t_run "ERROW_FEEDBACK_LIVE=true without the key: bootstrap only warns" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  out_has "WARN row" 'WARN +feedback_approval_key'
  check_not "still no generated key" test -e "$TREE/secrets/approval/feedback_approval_key"

  new_tree bs-appr-g
  t_run "--key-group makes the approval dir 0750" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --key-group "$(id -g)"
  mode_is "approval dir 0750 with --key-group" 750 "$TREE/secrets/approval"
  new_tree bs-appr-d
  t_run "--dev-readable-secrets makes the approval dir 0755" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --dev-readable-secrets
  mode_is "approval dir 0755 with --dev-readable-secrets" 755 "$TREE/secrets/approval"
  new_tree bs-appr-o
  ERROW_FEEDBACK_APPROVAL_DIR=./secrets/alt-approval t_run "ERROW_FEEDBACK_APPROVAL_DIR is honoured" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  mode_is "alternative approval dir is 0700" 700 "$TREE/secrets/alt-approval"
  check_not "the default location is not created" test -e "$TREE/secrets/approval"
  new_tree bs-appr-n
  t_run "--no-secrets skips the approval dir" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets
  check_not "no approval dir with --no-secrets" test -e "$TREE/secrets/approval"
}

case_bootstrap_renewal_window() {
  local fp1 fp2 days
  new_tree bs-renew
  PKI_DAYS=10 t_run "bootstrap with PKI_DAYS=10" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  fp1="$(openssl x509 -in "$TREE/pki/errow.crt" -noout -fingerprint -sha256)"
  t_run "--check warns about certificates inside the 30-day window" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  out_has "--check says days left" 'WARN +pki/errow'
  t_run "bootstrap re-issues certificates with <30 days left" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  fp2="$(openssl x509 -in "$TREE/pki/errow.crt" -noout -fingerprint -sha256)"
  check "errow.crt was re-issued" test "$fp1" != "$fp2"
  check "the previous errow set was archived under pki-archive/" test -n "$(find "$TREE/pki-archive" -mindepth 2 -name errow.crt)"
  check_not "…not under pki/" test -e "$TREE/pki/archive"
  eq "pki/ still contains no subdirectory" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  notafter="$(openssl x509 -in "$TREE/pki/errow.crt" -noout -enddate | cut -d= -f2)"
  notafter_epoch="$({ date -u -d "$notafter" +%s 2>/dev/null || date -j -u -f '%b %d %T %Y %Z' "$notafter" +%s; } 2>/dev/null)"
  days="$(( (notafter_epoch - $(date +%s)) / 86400 ))"
  check "re-issued certificate has ~397 days" test "$days" -ge 390
}

case_bootstrap_legacy_pki_archive() {
  local before after
  new_tree bs-legacy
  t_run "bootstrap" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  # a stack bootstrapped before the pki-archive fix: OpenSearch cannot read these 0700 directories inside the mounted pki/
  mkdir -p "$TREE/pki/archive/20250101T000000Z" "$TREE/pki/.mkcert"
  cp -p "$TREE/pki/errow.crt" "$TREE/pki/archive/20250101T000000Z/errow.crt"
  printf 'k' >"$TREE/pki/.mkcert/rootCA-key.pem"
  chmod 0700 "$TREE/pki/archive/20250101T000000Z" "$TREE/pki/archive" "$TREE/pki/.mkcert"
  t_run "--check flags the legacy pki/archive layout" 5 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  out_has "names pki/archive with the fix hint" 'FAIL +pki/archive +legacy layout: move it to pki-archive/'
  out_has "names the legacy mkcert store too" 'FAIL +pki/\.mkcert +legacy layout'
  check "--check moved nothing" test -d "$TREE/pki/archive/20250101T000000Z"

  mkdir -p "$TREE/pki/other"
  chmod 0700 "$TREE/pki/other"
  t_run "--check flags any unreadable subdirectory" 5 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  out_has "names the subdirectory" 'FAIL +pki/other/ +subdirectory with mode 700'
  rmdir "$TREE/pki/other"

  t_run "--dry-run reports the migration" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets --dry-run
  out_has "dry-run says what it would move" 'would move pki/archive'
  check "dry-run moved nothing" test -d "$TREE/pki/archive/20250101T000000Z"

  t_run "bootstrap migrates the legacy archive out of pki/" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  check_not "pki/archive is gone" test -e "$TREE/pki/archive"
  check_not "pki/.mkcert is gone" test -e "$TREE/pki/.mkcert"
  check "archived set kept under pki-archive/" test -s "$TREE/pki-archive/20250101T000000Z/errow.crt"
  check "mkcert CA store kept under pki-archive/" test -s "$TREE/pki-archive/mkcert-caroot/rootCA-key.pem"
  mode_is "migrated timestamp dir stays 0700" 700 "$TREE/pki-archive/20250101T000000Z"
  mode_is "pki-archive/ is 0700" 700 "$TREE/pki-archive"
  eq "pki/ contains no subdirectory" 0 "$(find "$TREE/pki" -mindepth 1 -type d | wc -l | tr -d ' ')"
  t_run "--check is green after the migration" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  out_has "--check reports the archive outside pki/" 'OK +pki-archive +outside pki/'
  before="$(tree_hashes "$TREE/pki" "$TREE/pki-archive")"
  t_run "re-run is idempotent" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  after="$(tree_hashes "$TREE/pki" "$TREE/pki-archive")"
  eq "nothing changed" "$before" "$after"

  chmod 0755 "$TREE/pki-archive"
  t_run "--check flags a loose pki-archive mode" 5 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  out_has "names the mode problem" 'FAIL +pki-archive +mode 755 is looser than 0700'
  chmod 0700 "$TREE/pki-archive"
  PKI_ARCHIVE_DIR="$TREE/pki/arch" t_run "PKI_ARCHIVE_DIR inside pki/ is refused" 2 "$S/bootstrap.sh" --skip-preflight --no-secrets
  out_has "explains why" 'must be outside'
  PKI_ARCHIVE_DIR="$TREE/pki/arch" t_run "--check flags PKI_ARCHIVE_DIR inside pki/" 5 "$S/bootstrap.sh" --skip-preflight --no-secrets --check
  check_not "nothing was created inside pki/" test -e "$TREE/pki/arch"
  PKI_ARCHIVE_DIR="$WORK/custom-pki-archive" t_run "a PKI_ARCHIVE_DIR override outside the stack is honored" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets
  mode_is "custom archive dir is 0700" 700 "$WORK/custom-pki-archive"
}

case_bootstrap_modes_and_options() {
  new_tree bs-opt
  t_run "bootstrap --dev-readable-keys" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets --dev-readable-keys
  mode_is "keys are 0644 with --dev-readable-keys" 644 "$TREE/pki/llm-gateway.key"
  mode_is "ca.key stays 0600 even with --dev-readable-keys" 600 "$TREE/pki/ca.key"
  new_tree bs-rsa
  t_run "bootstrap --pki-algo rsa" 0 "$S/bootstrap.sh" --skip-preflight --no-secrets --pki-algo rsa --extra-services extra-svc
  check "RSA CA is 4096 bit" grep -q 'Public-Key: (4096 bit)' < <(cert_text "$TREE/pki/ca.crt")
  check "extra service certificate issued and valid" openssl verify -CAfile "$TREE/pki/ca.crt" "$TREE/pki/extra-svc.crt"
  new_tree bs-step
  t_run "--pki step-ca without the step CLI is a prerequisite error" 4 "$S/bootstrap.sh" --skip-preflight --no-secrets --pki step-ca --step-ca-url https://ca.example.invalid:9000
  check_not "nothing issued by the failed step-ca run" test -s "$TREE/pki/errow.crt"
  t_run "bad --pki mode is a usage error" 2 "$S/bootstrap.sh" --skip-preflight --pki nonsense
  PKI_DAYS=9999 t_run "absurd PKI_DAYS is a usage error" 2 "$S/bootstrap.sh" --skip-preflight --no-secrets
}

case_bootstrap_failclosed() {
  new_tree bs-fc
  CS3_PROFILE=airgap OPENAI_API_KEY=sk-test-not-a-secret t_run "airgap + cloud LLM key → FailClosedError" 3 "$S/bootstrap.sh" --skip-preflight --check
  out_has "message names FailClosedError" 'FailClosedError'
  out_lacks "the key value is never printed" 'sk-test-not-a-secret'
  CS3_PROFILE=onprem ANTHROPIC_API_KEY=x-test t_run "onprem + cloud key → exit 3 (also without --check)" 3 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets
  check_not "FailClosed stops before generating anything" test -e "$TREE/secrets"
  CS3_PROFILE=airgap t_run "airgap without cloud keys passes the FailClosed step" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets
}

case_bootstrap_preflight() {
  local sh mm want
  new_tree bs-pre
  sh="$(shims_dir bs-pre)"
  write_shim "$sh" docker <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "version --format {{.Server.Version}}") echo "${SHIM_DOCKER_VERSION:-29.1.3}" ;;
  "compose version --short") echo "${SHIM_COMPOSE_VERSION:-2.29.1}" ;;
  ps*) ;;
  *) echo "docker shim: unsupported: $*" >&2; exit 1 ;;
esac
EOF
  # a host with the standalone v2 binary must not rescue the Compose-v1 case
  write_shim "$sh" docker-compose <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  mm=""
  [[ -r /proc/sys/vm/max_map_count ]] && mm="$(</proc/sys/vm/max_map_count)"   # absent on macOS: the row WARNs
  want=0
  if [[ -n "$mm" ]] && ((mm < 262144)); then want=4; fi
  PATH="$sh:$PATH" MIN_DISK_GB=1 MIN_RAM_MB=256 t_run "preflight with docker 29 + compose v2 (rc depends on this host's vm.max_map_count=$mm)" "$want" \
    "$S/bootstrap.sh" --dry-run --ports 59999 --no-secrets --no-pki
  out_has "docker engine version reported" 'OK +docker +engine 29\.1\.3'
  out_has "compose v2 detected" 'OK +docker compose +v2\.29\.1'
  out_has "vm.max_map_count row present" 'vm\.max_map_count'
  SHIM_DOCKER_VERSION=20.10.7 PATH="$sh:$PATH" MIN_DISK_GB=1 MIN_RAM_MB=256 t_run "docker < 24 fails preflight" 4 "$S/bootstrap.sh" --dry-run --ports 59999 --no-secrets --no-pki
  out_has "old engine named in the failure" 'FAIL +docker +engine 20\.10\.7 < 24'
  SHIM_COMPOSE_VERSION=1.29.2 PATH="$sh:$PATH" MIN_DISK_GB=1 MIN_RAM_MB=256 t_run "compose v1 fails preflight" 4 "$S/bootstrap.sh" --dry-run --ports 59999 --no-secrets --no-pki
  out_has "compose v2 required" 'FAIL +docker compose'
  PATH="$sh:$PATH" MIN_DISK_GB=999999 t_run "insufficient disk fails preflight" 4 "$S/bootstrap.sh" --dry-run --ports 59999 --no-secrets --no-pki
  out_has "disk failure reported" 'FAIL +disk'
}

case_bootstrap_env() {
  new_tree bs-env
  printf '%s\n' '# example' 'CS3_PROFILE=onprem' 'OPENSEARCH_PASSWORD_FILE=./secrets/opensearch_admin_password' 'GRAFANA_PORT=3000' >"$TREE/.env.example"
  t_run "bootstrap renders .env from .env.example" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets --set GRAFANA_PORT=3300
  check ".env created" test -s "$TREE/.env"
  mode_is ".env is 0600" 600 "$TREE/.env"
  check ".env carries the --set override" grep -qx 'GRAFANA_PORT=3300' "$TREE/.env"
  check ".env keeps the example comments" grep -qx '# example' "$TREE/.env"
  printf '%s\n' 'CS3_PROFILE=cloud' >"$TREE/.env"
  t_run "existing .env is not overwritten" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets
  eq ".env content untouched" 'CS3_PROFILE=cloud' "$(<"$TREE/.env")"
  rm -f -- "$TREE/.env"
  t_run "--set refuses secret-looking keys" 2 "$S/bootstrap.sh" --skip-preflight --no-pki --no-secrets --set GRAFANA_ADMIN_PASSWORD=hunter2
  out_lacks "refused value never echoed" 'hunter2'
}

# Per-approver keys + ERROW_FEEDBACK_APPROVAL_THRESHOLD decide whether approvals are dual-control (approval.py).
case_bootstrap_approval_keys() {
  local d
  new_tree bs-akeys
  t_run "bootstrap creates the approval dir" 0 "$S/bootstrap.sh" --skip-preflight --no-pki
  d="$TREE/secrets/approval"

  printf 'operator-shared-key-0123456789abcdef\n' >"$d/feedback_approval_key"
  chmod 0600 "$d/feedback_approval_key"
  t_run "--check warns when only the shared key exists" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the shared key alone is flagged as no dual control" 'WARN +approval threshold +threshold 2 but only the shared key exists'

  mkdir "$d/keys"
  chmod 0700 "$d/keys"
  printf 'alice-key-0123456789abcdef0123456789\n' >"$d/keys/alice.key"
  chmod 0600 "$d/keys/alice.key"
  t_run "--check passes with one per-approver key (shared key counts as the second authority)" 0 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the key set is reported" 'OK +approval threshold +2 of 2'
  out_lacks "no dual-control warning once a per-approver key exists" 'WARN +approval threshold'

  chmod 0644 "$d/keys/alice.key"
  t_run "--check fails on a loose per-approver key" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the loose key is named" 'FAIL +approval keys +per-approver key\(s\) looser than 0600: alice.key'
  chmod 0600 "$d/keys/alice.key"

  printf 'short\n' >"$d/keys/alice.key"
  t_run "--check fails on a short per-approver key" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the short key is named" 'FAIL +approval keys +per-approver key\(s\) shorter than 32 characters: alice.key'
  printf 'alice-key-0123456789abcdef0123456789\n' >"$d/keys/alice.key"

  rm -f -- "$d/feedback_approval_key"
  t_run "--check fails when the threshold cannot be met while live" 5 \
    env ERROW_FEEDBACK_APPROVAL_THRESHOLD=2 ERROW_FEEDBACK_LIVE=true "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the shortfall is named" 'FAIL +approval threshold +threshold 2 but only 1 approver'
  t_run "…and only warns while live feedback is off" 0 env ERROW_FEEDBACK_APPROVAL_THRESHOLD=2 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "WARN when live is off" 'WARN +approval threshold'

  t_run "--check fails on a non-numeric threshold" 5 env ERROW_FEEDBACK_APPROVAL_THRESHOLD=nope "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the bad threshold is named" 'FAIL +approval threshold +ERROW_FEEDBACK_APPROVAL_THRESHOLD must be a positive integer'

  rm -rf -- "$d/keys"
  printf 'not a dir\n' >"$d/keys"
  t_run "--check fails when keys/ is a file" 5 "$S/bootstrap.sh" --skip-preflight --no-pki --check
  out_has "the file is named" 'FAIL +approval keys +secrets/approval/keys exists and is not a directory'
}
