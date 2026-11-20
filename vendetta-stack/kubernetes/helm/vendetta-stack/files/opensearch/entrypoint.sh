#!/usr/bin/env bash
# vendetta-stack OpenSearch entrypoint wrapper (CONTRACT s2: secrets from files).
# Renders the security plugin configuration for the FIRST start of a cluster:
#   - internal_users.yml with a single `admin` user whose bcrypt hash is
#     computed from the password file (never an inline / demo password);
#   - copies the static security/*.yml files from the mounted opensearch/ dir.
# Then hands over to the stock image entrypoint with the demo installer off.
#
# Env: OPENSEARCH_PASSWORD_FILE  default /run/secrets/opensearch_admin_password
#      OPENSEARCH_SECURITY_SRC   default /opensearch/security
#      NODE_NAME                 default $HOSTNAME
set -euo pipefail
IFS=$'\n\t'

OS_HOME=/usr/share/opensearch
PASSWORD_FILE="${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}"
SECURITY_SRC="${OPENSEARCH_SECURITY_SRC:-/opensearch/security}"
SECURITY_DST="${OS_HOME}/config/opensearch-security"
CERT_DIR="${OS_HOME}/config/certs"

die() { printf 'opensearch-entrypoint: %s\n' "$*" >&2; exit 1; }

[[ -r "$PASSWORD_FILE" ]] || die "admin password file not readable: ${PASSWORD_FILE}"
[[ -d "$SECURITY_SRC" ]] || die "security config directory missing: ${SECURITY_SRC}"
for f in opensearch.crt opensearch.key ca.crt; do
  [[ -r "${CERT_DIR}/${f}" ]] || die "TLS material not readable: ${CERT_DIR}/${f} (mount the stack pki/ dir there)"
done
grep -q 'BEGIN PRIVATE KEY' "${CERT_DIR}/opensearch.key" \
  || die "${CERT_DIR}/opensearch.key must be an unencrypted PKCS#8 key (BEGIN PRIVATE KEY)"

OSPW="$(tr -d '\r\n' <"$PASSWORD_FILE")"
[[ ${#OSPW} -ge 12 ]] || die "admin password must be at least 12 characters"
export OSPW
ADMIN_HASH="$("${OS_HOME}/plugins/opensearch-security/tools/hash.sh" -env OSPW | tail -n 1)"
unset OSPW
[[ "$ADMIN_HASH" == \$2* ]] || die "could not compute the bcrypt hash of the admin password"

mkdir -p "$SECURITY_DST"
for f in "$SECURITY_SRC"/*.yml; do
  [[ -e "$f" ]] || continue
  [[ "$(basename "$f")" == internal_users.yml ]] && continue
  cp -f "$f" "$SECURITY_DST/"
done

umask 077
{
  printf -- '---\n'
  printf '_meta:\n  type: "internalusers"\n  config_version: 2\n\n'
  printf 'admin:\n'
  printf '  hash: "%s"\n' "$ADMIN_HASH"
  printf '  reserved: true\n'
  printf '  backend_roles:\n    - "admin"\n'
  printf '  description: "vendetta-stack administrator"\n'
} >"${SECURITY_DST}/internal_users.yml"

export NODE_NAME="${NODE_NAME:-$(hostname)}"
export DISABLE_INSTALL_DEMO_CONFIG=true
export DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true

exec "${OS_HOME}/opensearch-docker-entrypoint.sh" opensearch "$@"
