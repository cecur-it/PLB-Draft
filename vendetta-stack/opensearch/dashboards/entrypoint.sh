#!/usr/bin/env bash
# Start OpenSearch Dashboards with its credentials in the Dashboards keystore.
#
# Reads the admin password from OPENSEARCH_PASSWORD_FILE (default
# /run/secrets/opensearch_admin_password), stores it as opensearch.password,
# derives a stable 64-char opensearch_security.cookie.password from it (so every
# Dashboards replica sharing the secret shares the cookie key) and execs the
# stock entrypoint. Nothing secret is written to opensearch_dashboards.yml.
#
# Exit codes: 0 never returns (exec); 4 password file missing/unreadable/too short.
set -Eeuo pipefail
IFS=$'\n\t'
trap 'printf "dashboards/entrypoint.sh: FAILED at line %s\n" "$LINENO" >&2' ERR

PW_FILE="${OPENSEARCH_PASSWORD_FILE:-/run/secrets/opensearch_admin_password}"
OSD_HOME="${OSD_HOME:-/usr/share/opensearch-dashboards}"
KEYSTORE="${OSD_HOME}/bin/opensearch-dashboards-keystore"
KEYSTORE_FILE="${OSD_HOME}/config/opensearch_dashboards.keystore"

die() {
  printf 'dashboards/entrypoint.sh: ERROR: %s\n' "$*" >&2
  exit 4
}

[[ -r "$PW_FILE" ]] || die "password file ${PW_FILE} is missing or not readable by uid $(id -u)"
PW="$(<"$PW_FILE")"
PW="${PW%$'\r'}"
((${#PW} >= 12)) || die "password in ${PW_FILE} must be at least 12 characters"
COOKIE_KEY="$(printf 'vendetta-dashboards-cookie:%s' "$PW" | sha256sum | cut -d' ' -f1)"

rm -f "$KEYSTORE_FILE"
"$KEYSTORE" create >/dev/null
printf '%s' "$PW" | "$KEYSTORE" add --stdin opensearch.password >/dev/null
printf '%s' "$COOKIE_KEY" | "$KEYSTORE" add --stdin opensearch_security.cookie.password >/dev/null
unset PW COOKIE_KEY

exec "${OSD_HOME}/opensearch-dashboards-docker-entrypoint.sh" opensearch-dashboards "$@"
