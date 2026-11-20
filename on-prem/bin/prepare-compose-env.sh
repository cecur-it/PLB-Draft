#!/usr/bin/env bash
# Prepare the environment file actually consumed by deployment/docker Compose.
# Values already present in deployment/docker/.env are preserved except for the
# on-prem telemetry invariants and the bundled indexer connection.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT_ENV="${CS3_ROOT_ENV_FILE:-$REPO_ROOT/.env}"
COMPOSE_DIR="${CS3_COMPOSE_DIR:-$REPO_ROOT/deployment/docker}"
COMPOSE_ENV="${CS3_COMPOSE_ENV_FILE:-$COMPOSE_DIR/.env}"
TEMPLATE="$COMPOSE_DIR/.env.example"

if [ ! -f "$TEMPLATE" ]; then
  echo "error: Compose environment template not found: $TEMPLATE" >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "error: node is required to generate Compose secrets" >&2
  exit 1
fi
if [ ! -f "$COMPOSE_ENV" ]; then
  cp "$TEMPLATE" "$COMPOSE_ENV"
fi
chmod 0600 "$COMPOSE_ENV"

get_env() {
  local file="$1" key="$2" line value=""
  if [ -f "$file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      if [[ "$line" == "$key="* ]]; then
        value="${line#*=}"
      fi
    done < "$file"
  fi
  printf '%s' "$value"
}

set_env() {
  local key="$1" value="$2" line found="false" tmp
  tmp="$(mktemp "$COMPOSE_DIR/.env.tmp.XXXXXX")"
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" == "$key="* ]]; then
      if [ "$found" = "false" ]; then
        printf '%s=%s\n' "$key" "$value"
        found="true"
      fi
    else
      printf '%s\n' "$line"
    fi
  done < "$COMPOSE_ENV" > "$tmp"
  if [ "$found" = "false" ]; then
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  chmod 0600 "$tmp"
  mv "$tmp" "$COMPOSE_ENV"
}

random_hex() {
  node -e 'process.stdout.write(require("node:crypto").randomBytes(Number(process.argv[1])).toString("hex"))' "$1"
}

ensure_secret() {
  local key="$1" value
  value="$(get_env "$COMPOSE_ENV" "$key")"
  if [ -z "$value" ]; then
    set_env "$key" "$(random_hex 32)"
  fi
}

jwt="$(get_env "$COMPOSE_ENV" JWT_SECRET)"
if [ -z "$jwt" ]; then
  jwt="$(get_env "$ROOT_ENV" JWT_SECRET)"
fi
if [ -z "$jwt" ]; then
  jwt="$(random_hex 32)"
fi
set_env JWT_SECRET "$jwt"

bootstrap="$(get_env "$COMPOSE_ENV" CS3_BOOTSTRAP_ADMIN_PASSWORD)"
if [ -z "$bootstrap" ]; then
  bootstrap="$(get_env "$ROOT_ENV" CS3_BOOTSTRAP_ADMIN_PASSWORD)"
fi
if [ -z "$bootstrap" ]; then
  bootstrap="$(random_hex 32)"
fi
set_env CS3_BOOTSTRAP_ADMIN_PASSWORD "$bootstrap"

for key in POSTGRES_PASSWORD CS3_APP_PASSWORD CS3_MIGRATOR_PASSWORD CS3_ARCHIVER_PASSWORD; do
  ensure_secret "$key"
done

# Import an explicitly configured remote Errow connector without exposing its key.
# Root-env loopback URLs are not container-reachable; leave the connector unconfigured
# instead of reporting a false LIVE state against the console container itself.
errow_base_url="$(get_env "$COMPOSE_ENV" ERROW_BASE_URL)"
if [ -z "$errow_base_url" ]; then
  root_errow_base_url="$(get_env "$ROOT_ENV" ERROW_BASE_URL)"
  case "$root_errow_base_url" in
    http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*|https://127.0.0.1|https://127.0.0.1:*|https://127.0.0.1/*|http://localhost|http://localhost:*|http://localhost/*|https://localhost|https://localhost:*|https://localhost/*|http://\[::1\]|http://\[::1\]:*|http://\[::1\]/*|https://\[::1\]|https://\[::1\]:*|https://\[::1\]/*)
      if [ -n "$root_errow_base_url" ]; then
        printf 'warning: root ERROW_BASE_URL uses loopback and was not imported into the container environment.\n' >&2
        printf 'Set a container-reachable Errow URL in %s; no Errow secret values are printed.\n' "$COMPOSE_ENV" >&2
      fi
      ;;
    *)
      if [ -n "$root_errow_base_url" ]; then
        set_env ERROW_BASE_URL "$root_errow_base_url"
        set_env ERROW_MODE remote
      fi
      ;;
  esac
fi

errow_base_url="$(get_env "$COMPOSE_ENV" ERROW_BASE_URL)"
errow_api_key="$(get_env "$COMPOSE_ENV" ERROW_API_KEY)"
if [ -n "$errow_base_url" ] && [ -z "$errow_api_key" ]; then
  root_errow_api_key="$(get_env "$ROOT_ENV" ERROW_API_KEY)"
  if [ -n "$root_errow_api_key" ]; then
    set_env ERROW_API_KEY "$root_errow_api_key"
  fi
fi

opensearch_password="$(get_env "$COMPOSE_ENV" OPENSEARCH_INITIAL_ADMIN_PASSWORD)"
indexer_password="$(get_env "$COMPOSE_ENV" CECUR_INDEXER_PASSWORD)"
if [ -z "$opensearch_password" ] && [ -z "$indexer_password" ]; then
  opensearch_password="Cs3!$(random_hex 24)"
  indexer_password="$opensearch_password"
elif [ -z "$opensearch_password" ]; then
  opensearch_password="$indexer_password"
elif [ -z "$indexer_password" ]; then
  indexer_password="$opensearch_password"
elif [ "$opensearch_password" != "$indexer_password" ]; then
  echo "error: OPENSEARCH_INITIAL_ADMIN_PASSWORD and CECUR_INDEXER_PASSWORD differ in $COMPOSE_ENV" >&2
  echo "Set both to the current bundled OpenSearch admin password; no containers were started." >&2
  exit 1
fi
set_env OPENSEARCH_INITIAL_ADMIN_PASSWORD "$opensearch_password"
set_env CECUR_INDEXER_PASSWORD "$indexer_password"

set_env CS3_PROFILE onprem
set_env CS3_DEMO_MODE false
set_env CS3_INGEST_REQUIRE_KEY true
set_env CS3_INDEXER_ENABLED true
set_env CECUR_INDEXER_URL https://indexer:9200
set_env CECUR_INDEXER_USERNAME admin
chmod 0600 "$COMPOSE_ENV"
printf 'Prepared %s (mode 0600); durable indexing is enabled.\n' "$COMPOSE_ENV"
