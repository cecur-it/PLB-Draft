# shellcheck shell=bash
# shellcheck disable=SC2034  # configuration globals are consumed by the scripts that source this library
#
# scripts/lib/pki.sh — private CA + service-certificate helpers shared by bootstrap.sh, rotate-certs.sh,
# enroll-agent.sh (agent client certificates) and healthcheck.sh (expiry/SAN validation).
#
# Traces: PROMPT §3 Phase 3 scripts/bootstrap.sh (PKI), scripts/rotate-certs.sh; CONTRACT §2 (PKI file names),
#         §8.6 (<svc>.pem for HAProxy), CS3 deployment/operations/{certificate-rotation,mtls-certificate-pinning}.md
#         (ECDSA P-256/P-384 or RSA 3072, SHA-256+, serverAuth+clientAuth, 30-day renew window).
#
# Modes (PKI_MODE): openssl (default; private CA kept in $PKI_DIR/ca.key), step-ca (certificates requested
# from a running smallstep CA), mkcert (local smoke only). Every mode produces the same file set:
#   ca.crt  ca.key  <svc>.crt  <svc>.key  <svc>.pem (cert+key for HAProxy)
# Keys are PKCS#8 ("BEGIN PRIVATE KEY") — required by the OpenSearch security plugin — whatever the mode.
#
# Requires lib/common.sh to be sourced first.

PKI_MODE="${PKI_MODE:-openssl}"
PKI_ALGO="${PKI_ALGO:-ec}"                 # ec = ECDSA P-384 (CA and leaves); rsa = RSA 4096 CA / 3072 leaves
PKI_DAYS="${PKI_DAYS:-397}"                # leaf validity
PKI_CA_DAYS="${PKI_CA_DAYS:-3650}"         # CA validity (openssl mode)
PKI_RENEW_DAYS="${PKI_RENEW_DAYS:-30}"     # a certificate with fewer days left is re-issued / flagged
PKI_ORG="${PKI_ORG:-Vendetta Stack}"
PKI_CA_CN="${PKI_CA_CN:-Vendetta Stack Private CA}"
PKI_CA_PASSPHRASE_FILE="${PKI_CA_PASSPHRASE_FILE:-}"
PKI_DEV_READABLE_KEYS="${PKI_DEV_READABLE_KEYS:-0}"
PKI_KEY_GROUP="${PKI_KEY_GROUP:-}"
PKI_STEP_URL="${PKI_STEP_URL:-}"
PKI_STEP_ROOT="${PKI_STEP_ROOT:-}"
PKI_STEP_FINGERPRINT="${PKI_STEP_FINGERPRINT:-}"
PKI_STEP_PROVISIONER="${PKI_STEP_PROVISIONER:-}"
PKI_STEP_PASSWORD_FILE="${PKI_STEP_PASSWORD_FILE:-}"
PKI_EXTRA_SERVICES="${PKI_EXTRA_SERVICES:-}"   # comma-separated extra service names

# CONTRACT §2 / §8.6 service list; vendetta-manager (authd 1515 TLS) and opensearch-dashboards are additions.
readonly PKI_SERVICES=(opensearch fluentd-1 fluentd-2 fluent-bit llm-gateway ollama-lb ollama-1 mock-ollama errow-mcp errow errow-feedback prometheus)
readonly PKI_DEFAULT_EXTRAS=(vendetta-manager opensearch-dashboards)
readonly PKI_ADMIN_SERVICE=opensearch-admin

PKI_WORK=""
PKI_REASON=""
PKI_DAYS_LEFT=0
PKI_ISSUED=()
PKI_SKIPPED=()

pki_validate_config() {
  case "$PKI_MODE" in openssl|step-ca|mkcert) ;; *) die "$EX_USAGE" "PKI mode must be openssl, step-ca or mkcert (got '$PKI_MODE')" ;; esac
  case "$PKI_ALGO" in ec|rsa) ;; *) die "$EX_USAGE" "PKI algorithm must be ec or rsa (got '$PKI_ALGO')" ;; esac
  if ! vs_is_uint "$PKI_DAYS" || ((PKI_DAYS < 1 || PKI_DAYS > 825)); then die "$EX_USAGE" "PKI_DAYS must be 1..825 (got '$PKI_DAYS')"; fi
  vs_is_uint "$PKI_RENEW_DAYS" || die "$EX_USAGE" "PKI_RENEW_DAYS must be a number"
  [[ "$PKI_ORG" =~ ^[A-Za-z0-9\ ._-]{1,64}$ ]] || die "$EX_USAGE" "PKI_ORG may only contain letters, digits, space . _ -"
  if [[ -n "$PKI_CA_PASSPHRASE_FILE" ]]; then
    [[ -s "$PKI_CA_PASSPHRASE_FILE" ]] || die "$EX_USAGE" "CA passphrase file missing or empty: $PKI_CA_PASSPHRASE_FILE"
  fi
  if [[ "$PKI_MODE" == step-ca ]]; then
    vs_have step || die "$EX_PREREQ" "--pki step-ca needs the 'step' CLI on PATH"
    [[ "$PKI_STEP_URL" =~ ^https:// ]] || die "$EX_USAGE" "--step-ca-url must be an https:// URL"
    [[ -n "$PKI_STEP_ROOT" || -n "$PKI_STEP_FINGERPRINT" || -s "$PKI_DIR/ca.crt" ]] \
      || die "$EX_USAGE" "step-ca mode needs --step-ca-root FILE or --step-ca-fingerprint SHA256 (or an existing pki/ca.crt)"
    [[ -n "$PKI_STEP_PROVISIONER" && -n "$PKI_STEP_PASSWORD_FILE" ]] \
      || die "$EX_USAGE" "step-ca mode needs --step-provisioner NAME and --step-password-file FILE"
    [[ -s "$PKI_STEP_PASSWORD_FILE" ]] || die "$EX_USAGE" "step provisioner password file missing or empty"
  fi
  if [[ "$PKI_MODE" == mkcert ]]; then vs_have mkcert || die "$EX_PREREQ" "--pki mkcert needs the 'mkcert' CLI on PATH"; fi
}

pki_all_services() {
  local s extra=()
  printf '%s\n' "${PKI_SERVICES[@]}" "${PKI_DEFAULT_EXTRAS[@]}"
  if [[ -n "$PKI_EXTRA_SERVICES" ]]; then
    IFS=, read -r -a extra <<<"$PKI_EXTRA_SERVICES"
    for s in "${extra[@]}"; do
      vs_valid_name "$s" || die "$EX_USAGE" "invalid extra PKI service name: $s"
      printf '%s\n' "$s"
    done
  fi
}

# pki_service_sans <svc> — expected SAN entries (DNS:…/IP:…), one per line, sorted.
pki_service_sans() {
  local svc=$1 dns=("$1")
  case "$svc" in
    ollama-1) dns+=(ollama-1-proxy ollama-workers) ;;
    mock-ollama) dns+=(mock-ollama-proxy ollama-1 ollama-workers) ;;
  esac
  dns+=(localhost)
  { printf 'DNS:%s\n' "${dns[@]}"; printf 'IP:127.0.0.1\n'; } | LC_ALL=C sort -u
}

pki_workdir() {
  if [[ -z "$PKI_WORK" ]]; then vs_mkwork pki; PKI_WORK=$VS_WORK; fi
}

pki_genkey() { # <out> <ca|leaf> [passphrase-file]
  local out=$1 kind=$2 pass=${3:-} enc=() bits=3072
  if [[ -n "$pass" ]]; then enc=(-aes-256-cbc -pass "file:$pass"); fi
  if [[ "$kind" == ca ]]; then bits=4096; fi
  (
    umask 077
    case "$PKI_ALGO" in
      ec) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve "${enc[@]}" -out "$out" 2>/dev/null ;;
      rsa) openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" "${enc[@]}" -out "$out" 2>/dev/null ;;
    esac
  )
  chmod 0600 "$out"
}

pki_ca_passin() { # fills PKI_PASSIN for the signing key
  PKI_PASSIN=()
  if [[ -n "$PKI_CA_PASSPHRASE_FILE" ]]; then PKI_PASSIN=(-passin "file:$PKI_CA_PASSPHRASE_FILE"); fi
}

# pki_new_ca <key-out> <crt-out> — fresh CA key pair + self-signed CA certificate.
pki_new_ca() {
  local key=$1 crt=$2 cnf
  pki_workdir
  cnf="$PKI_WORK/ca.cnf"
  cat >"$cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
O = $PKI_ORG
CN = $PKI_CA_CN
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
  pki_genkey "$key.new" ca "$PKI_CA_PASSPHRASE_FILE"
  pki_ca_passin
  openssl req -x509 -new -key "$key.new" "${PKI_PASSIN[@]}" -sha384 -days "$PKI_CA_DAYS" -config "$cnf" -extensions v3_ca -out "$crt.new"
  mv -f "$key.new" "$key"
  mv -f "$crt.new" "$crt"
  chmod 0600 "$key"
  chmod 0644 "$crt"
}

# pki_signer_cert — certificate matching ca.key (ca-signer.crt during a CA rotation, else ca.crt).
pki_signer_cert() {
  if [[ -s "$PKI_DIR/ca-signer.crt" ]]; then printf '%s' "$PKI_DIR/ca-signer.crt"; else printf '%s' "$PKI_DIR/ca.crt"; fi
}

pki_cert_days_left() { # <crt> → whole days remaining (negative when expired), -9999 when unreadable
  local end epoch now
  end="$(openssl x509 -noout -enddate -in "$1" 2>/dev/null)" || { printf '%s' -9999; return 0; }
  epoch="$(vs_date_to_epoch "${end#notAfter=}")" || { printf '%s' -9999; return 0; }
  [[ "$epoch" =~ ^[0-9]+$ ]] || { printf '%s' -9999; return 0; }
  now="$(date -u +%s)"
  printf '%d' $(((epoch - now) / 86400))
}

pki_cert_sans() { # <crt> → sorted SAN entries in DNS:/IP: form
  openssl x509 -noout -ext subjectAltName -in "$1" 2>/dev/null | sed -n '2,$p' | tr ',' '\n' \
    | sed -e 's/^[[:space:]]*//' -e 's/^IP Address:/IP:/' -e '/^$/d' | LC_ALL=C sort -u
}

pki_cert_fingerprint() { openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2; }
pki_cert_subject() { openssl x509 -noout -subject -nameopt RFC2253 -in "$1" | sed 's/^subject=//'; }
pki_cert_not_after() { openssl x509 -noout -enddate -in "$1" | cut -d= -f2; }

pki_key_matches() { # <crt> <key>
  local a b
  a="$(openssl x509 -noout -pubkey -in "$1" 2>/dev/null | openssl sha256 2>/dev/null)" || return 1
  b="$(openssl pkey -pubout -in "$2" 2>/dev/null | openssl sha256 2>/dev/null)" || return 1
  [[ -n "$a" && "$a" == "$b" ]]
}

pki_key_mode() {
  if [[ "$PKI_DEV_READABLE_KEYS" == 1 ]]; then printf '0644'
  elif [[ -n "$PKI_KEY_GROUP" ]]; then printf '0640'
  else printf '0600'
  fi
}

pki_set_key_perms() { # <file>
  chmod "$(pki_key_mode)" "$1"
  if [[ -n "$PKI_KEY_GROUP" ]]; then chgrp "$PKI_KEY_GROUP" "$1" 2>/dev/null || log_warn "cannot chgrp $1 to $PKI_KEY_GROUP (need root or group membership)"; fi
}

# pki_cert_check <svc> — 0 when the service's certificate set is complete and healthy; otherwise sets PKI_REASON.
pki_cert_check() {
  local svc=$1 crt="$PKI_DIR/$1.crt" key="$PKI_DIR/$1.key" pem="$PKI_DIR/$1.pem" ekus
  PKI_REASON=""
  [[ -s "$crt" && -s "$key" ]] || { PKI_REASON="missing certificate or key"; return 1; }
  [[ -s "$PKI_DIR/ca.crt" ]] || { PKI_REASON="missing ca.crt"; return 1; }
  pki_key_matches "$crt" "$key" || { PKI_REASON="key does not match certificate"; return 1; }
  PKI_DAYS_LEFT="$(pki_cert_days_left "$crt")"
  if ((PKI_DAYS_LEFT < PKI_RENEW_DAYS)); then PKI_REASON="${PKI_DAYS_LEFT}d left (< ${PKI_RENEW_DAYS}d)"; return 1; fi
  openssl verify -CAfile "$PKI_DIR/ca.crt" "$crt" >/dev/null 2>&1 || { PKI_REASON="not signed by the current CA bundle"; return 1; }
  ekus="$(openssl x509 -noout -ext extendedKeyUsage -in "$crt" 2>/dev/null || true)"
  [[ "$ekus" == *"TLS Web Server Authentication"* && "$ekus" == *"TLS Web Client Authentication"* ]] \
    || { PKI_REASON="EKU must include serverAuth and clientAuth"; return 1; }
  if [[ "$svc" != "$PKI_ADMIN_SERVICE" && "$(pki_cert_sans "$crt")" != "$(pki_service_sans "$svc")" ]]; then
    PKI_REASON="SAN set differs from the expected DNS/IP list"; return 1
  fi
  [[ -s "$pem" ]] || { PKI_REASON="missing $svc.pem"; return 1; }
  return 0
}

pki_write_pem() { # <svc> — cert + key for HAProxy
  local svc=$1
  { cat "$PKI_DIR/$svc.crt"; cat "$PKI_DIR/$svc.key"; } | vs_atomic_write "$PKI_DIR/$svc.pem" 0600
  pki_set_key_perms "$PKI_DIR/$svc.pem"
}

# pki_issue_leaf <cn> <crt-out> <key-out> <eku-csv> <san-entry>... — sign a leaf with the CA (or via step-ca / mkcert).
pki_issue_leaf() {
  local cn=$1 crt=$2 key=$3 eku=$4 ku san cnf ext d=0 n=0
  shift 4
  pki_workdir
  case "$PKI_MODE" in
    openssl)
      [[ -s "$PKI_DIR/ca.key" ]] || die "$EX_PREREQ" "pki/ca.key missing — cannot sign (use step-ca mode or restore the CA key)"
      ku=digitalSignature; if [[ "$PKI_ALGO" == rsa ]]; then ku=digitalSignature,keyEncipherment; fi
      cnf="$PKI_WORK/req.cnf"; ext="$PKI_WORK/ext.cnf"
      printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nO = %s\nCN = %s\n' "$PKI_ORG" "$cn" >"$cnf"
      {
        printf 'basicConstraints = critical,CA:FALSE\nkeyUsage = critical,%s\nextendedKeyUsage = %s\n' "$ku" "$eku"
        printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n'
        if (($#)); then
          printf 'subjectAltName = @alt\n[alt]\n'
          for san in "$@"; do
            case "$san" in
              DNS:*) d=$((d + 1)); printf 'DNS.%d = %s\n' "$d" "${san#DNS:}" ;;
              IP:*) n=$((n + 1)); printf 'IP.%d = %s\n' "$n" "${san#IP:}" ;;
              *) die "$EX_USAGE" "unsupported SAN entry: $san" ;;
            esac
          done
        fi
      } >"$ext"
      pki_genkey "$key.new" leaf
      openssl req -new -key "$key.new" -config "$cnf" -out "$PKI_WORK/leaf.csr"
      pki_ca_passin
      openssl x509 -req -in "$PKI_WORK/leaf.csr" -CA "$(pki_signer_cert)" -CAkey "$PKI_DIR/ca.key" "${PKI_PASSIN[@]}" \
        -set_serial "0x$(openssl rand -hex 16)" -days "$PKI_DAYS" -sha384 -extfile "$ext" -out "$crt.new" 2>/dev/null
      ;;
    step-ca)
      local sanargs=()
      for san in "$@"; do sanargs+=(--san "${san#*:}"); done
      step ca certificate "$cn" "$crt.new" "$key.new" --ca-url "$PKI_STEP_URL" --root "$PKI_DIR/ca.crt" \
        --provisioner "$PKI_STEP_PROVISIONER" --provisioner-password-file "$PKI_STEP_PASSWORD_FILE" \
        --kty EC --curve P-384 --not-after "$((PKI_DAYS * 24))h" --force "${sanargs[@]}"
      ;;
    mkcert)
      local names=()
      for san in "$@"; do names+=("${san#*:}"); done
      if [[ ${#names[@]} -eq 0 ]]; then names=("$cn"); fi
      CAROOT="$(pki_mkcert_caroot)" mkcert -ecdsa -client -cert-file "$crt.new" -key-file "$key.new" "${names[@]}" >/dev/null
      ;;
  esac
  # normalise every mode to a PKCS#8 key (OpenSearch security plugin requirement)
  (umask 077; openssl pkey -in "$key.new" -out "$key.p8" 2>/dev/null)
  mv -f "$key.p8" "$key.new"
  mv -f "$key.new" "$key"
  mv -f "$crt.new" "$crt"
  chmod 0644 "$crt"
}

pki_ensure_ca() { # creates the CA when missing (openssl/mkcert) or fetches the root (step-ca)
  case "$PKI_MODE" in
    openssl)
      if [[ -s "$PKI_DIR/ca.crt" && -s "$PKI_DIR/ca.key" ]]; then
        if ! openssl x509 -noout -checkend $((90 * 86400)) -in "$PKI_DIR/ca.crt" >/dev/null 2>&1; then
          log_warn "CA certificate expires within 90 days — plan 'rotate-certs.sh --rotate-ca'"
        fi
        return 0
      fi
      if [[ -s "$PKI_DIR/ca.crt" || -s "$PKI_DIR/ca.key" ]]; then
        die "$EX_FAIL" "pki/ca.crt and pki/ca.key must exist together (found only one); refusing to overwrite — restore or remove both"
      fi
      log_info "creating private CA ($PKI_ALGO, ${PKI_CA_DAYS}d): $PKI_DIR/ca.crt"
      pki_new_ca "$PKI_DIR/ca.key" "$PKI_DIR/ca.crt"
      ;;
    step-ca)
      if [[ -s "$PKI_DIR/ca.crt" ]]; then return 0; fi
      if [[ -n "$PKI_STEP_ROOT" ]]; then
        install -m 0644 "$PKI_STEP_ROOT" "$PKI_DIR/ca.crt"
      else
        step ca root "$PKI_DIR/ca.crt" --ca-url "$PKI_STEP_URL" --fingerprint "$PKI_STEP_FINGERPRINT" --force
      fi
      ;;
    mkcert)
      if [[ -s "$PKI_DIR/ca.crt" ]]; then return 0; fi
      local caroot
      caroot="$(pki_mkcert_caroot)"
      pki_ensure_archive_root
      install -d -m 0700 "$caroot"
      CAROOT="$caroot" mkcert -ecdsa -client -cert-file "$caroot/seed.crt" -key-file "$caroot/seed.key" localhost >/dev/null 2>&1
      rm -f "$caroot/seed.crt" "$caroot/seed.key"
      install -m 0644 "$caroot/rootCA.pem" "$PKI_DIR/ca.crt"
      install -m 0600 "$caroot/rootCA-key.pem" "$PKI_DIR/ca.key"
      ;;
  esac
}

# pki_mkcert_caroot — mkcert's CA key store; kept with the archives, never inside the mounted pki/ tree.
pki_mkcert_caroot() { printf '%s' "${PKI_MKCERT_CAROOT:-$PKI_ARCHIVE_DIR/mkcert-caroot}"; }

# pki_ensure_archive_root — create $PKI_ARCHIVE_DIR (0700), refusing a location inside the mounted pki/ tree.
pki_ensure_archive_root() {
  case "$PKI_ARCHIVE_DIR/" in
    "$PKI_DIR"/*) die "$EX_USAGE" "PKI_ARCHIVE_DIR ($PKI_ARCHIVE_DIR) must be outside $PKI_DIR: compose mounts pki/ into OpenSearch, which cannot read a 0700 subdirectory" ;;
    *) ;;
  esac
  (umask 077; mkdir -p "$PKI_ARCHIVE_DIR")
  chmod 0700 "$PKI_ARCHIVE_DIR"
}

# pki_archive_set <timestamp> <name>... — copy the current files of the named certificate sets into $PKI_ARCHIVE_DIR/<ts>/.
pki_archive_set() {
  local ts=$1 dir n f copied=0
  shift
  dir="$PKI_ARCHIVE_DIR/$ts"
  pki_ensure_archive_root
  (umask 077; mkdir -p "$dir")
  chmod 0700 "$dir"
  for n in "$@"; do
    for f in "$PKI_DIR/$n.crt" "$PKI_DIR/$n.key" "$PKI_DIR/$n.pem"; do
      if [[ -f "$f" ]]; then cp -p "$f" "$dir/"; copied=1; fi
    done
  done
  if ((copied)); then log_info "previous set archived under ${dir#"$STACK_DIR"/}"; fi
}

# pki_migrate_legacy_archive — releases before the pki-archive fix kept pki/archive/ (and mkcert's pki/.mkcert/) inside the
# tree that compose mounts into OpenSearch, which then fails to boot. Move their contents out; idempotent, honors --dry-run.
pki_migrate_legacy_archive() {
  local legacy dest e
  for legacy in "$PKI_DIR/archive" "$PKI_DIR/.mkcert"; do
    [[ -d "$legacy" ]] || continue
    if [[ "$legacy" == "$PKI_DIR/archive" ]]; then dest="$PKI_ARCHIVE_DIR"; else dest="$(pki_mkcert_caroot)"; fi
    if ((VS_DRY_RUN)); then log_dry "would move ${legacy#"$STACK_DIR"/} → ${dest#"$STACK_DIR"/}"; continue; fi
    pki_ensure_archive_root
    install -d -m 0700 "$dest"
    for e in "$legacy"/* "$legacy"/.[!.]*; do
      [[ -e "$e" ]] || continue
      if [[ -e "$dest/$(basename "$e")" ]]; then
        die "$EX_FAIL" "cannot migrate ${e#"$STACK_DIR"/}: $dest/$(basename "$e") already exists — merge the two directories by hand, then remove ${legacy#"$STACK_DIR"/}"
      fi
      mv -- "$e" "$dest/"
    done
    rmdir "$legacy"
    log_ok "moved legacy ${legacy#"$STACK_DIR"/} → ${dest#"$STACK_DIR"/} (OpenSearch cannot read subdirectories of pki/)"
  done
}

# pki_issue_service <svc> — issue (or re-issue) one service certificate set and its .pem
pki_issue_service() {
  local svc=$1 sans=() cn=$1 line
  while IFS= read -r line; do sans+=("$line"); done < <(pki_service_sans "$svc")
  if [[ "$svc" == "$PKI_ADMIN_SERVICE" ]]; then sans=("DNS:$svc" "DNS:localhost" "IP:127.0.0.1"); fi
  pki_issue_leaf "$cn" "$PKI_DIR/$svc.crt" "$PKI_DIR/$svc.key" "serverAuth,clientAuth" "${sans[@]}"
  pki_set_key_perms "$PKI_DIR/$svc.key"
  pki_write_pem "$svc"
}

# pki_ensure_services <force:0|1> — idempotent: skip healthy sets (force=0), (re)issue the others. Fills PKI_ISSUED / PKI_SKIPPED.
pki_ensure_services() {
  local force=$1 svc ts
  PKI_ISSUED=(); PKI_SKIPPED=()
  ts="$(vs_ts)"
  while IFS= read -r svc; do
    if ((force == 0)) && pki_cert_check "$svc"; then
      PKI_SKIPPED+=("$svc")
      log_debug "$svc: valid, ${PKI_DAYS_LEFT}d left — skipped"
      continue
    fi
    if ((VS_DRY_RUN)); then
      log_dry "would issue $svc.crt/.key/.pem (${PKI_REASON:-forced})"
      PKI_ISSUED+=("$svc")
      continue
    fi
    if [[ -f "$PKI_DIR/$svc.crt" ]]; then pki_archive_set "$ts" "$svc"; fi
    log_info "issuing $svc (${PKI_REASON:-forced})"
    pki_issue_service "$svc"
    PKI_ISSUED+=("$svc")
  done < <({ pki_all_services; printf '%s\n' "$PKI_ADMIN_SERVICE"; })
}

# pki_apply_modes — enforce modes on an existing PKI directory (idempotent).
pki_apply_modes() {
  local f
  chmod 0755 "$PKI_DIR"
  [[ ! -f "$PKI_DIR/ca.crt" ]] || chmod 0644 "$PKI_DIR/ca.crt"
  [[ ! -f "$PKI_DIR/ca.key" ]] || chmod 0600 "$PKI_DIR/ca.key"
  for f in "$PKI_DIR"/*.crt; do [[ ! -f "$f" ]] || chmod 0644 "$f"; done
  for f in "$PKI_DIR"/*.key "$PKI_DIR"/*.pem; do
    [[ -f "$f" ]] || continue
    if [[ "$f" == "$PKI_DIR/ca.key" ]]; then continue; fi
    pki_set_key_perms "$f"
  done
}
