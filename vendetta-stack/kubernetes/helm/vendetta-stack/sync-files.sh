#!/usr/bin/env bash
#
# sync-files.sh - keep kubernetes/helm/vendetta-stack/files/ identical to the stack config files it mirrors.
#
# Traces: PROMPT section 1 Tier 3 (Helm chart); CONTRACT section 2 (config files are mounted read-only).
#
# Helm cannot read files outside the chart directory, so the ConfigMap sources (Fluent Bit tree, OpenSearch tree,
# Prometheus/Alertmanager config, Grafana provisioning and dashboards, HAProxy configs, models.json, the Ollama mock,
# the MCP target config and APPROVALS.md) are copied into files/ and committed.
#
#   --check  (default)  exit 1 when a mirrored file differs, is missing, or files/ holds a stale file
#   --write             copy the sources into files/ and delete stale files
#
# Exit codes: 0 in sync (or synced) | 1 drift / missing source | 2 usage

set -euo pipefail
IFS=$'\n\t'
trap 'echo "FAILED at line $LINENO" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FILES_DIR="$SCRIPT_DIR/files"
ACTION="check"
QUIET=0

# source (relative to the stack dir) @ destination (relative to files/) @ include regex @ exclude regex
# A source that is a directory is mirrored recursively; the regexes match the path relative to that directory.
MAPPINGS=(
  'fluent-bit@fluent-bit@.*@^(tests/|.*\.md$)'
  'opensearch@opensearch@.*@^(tests/|.*\.md$|dashboards/build_saved_objects\.py$)'
  'prometheus@prometheus@^(prometheus|alerts|alertmanager)\.yml$@^$'
  'grafana/provisioning@grafana/provisioning@.*@^$'
  'grafana/dashboards@grafana/dashboards@\.json$@^$'
  'ollama/models.json@ollama/models.json@@'
  'ollama/ollama-lb@ollama/ollama-lb@^(haproxy|worker-proxy)\.cfg$@^$'
  'ollama/mock@ollama/mock@^mock_ollama\.py$@^$'
  'errow/config@errow/config@.*@^$'
  'errow/feedback-loop/APPROVALS.md@errow/feedback-loop/APPROVALS.md@@'
  'vendetta/manager@vendetta/manager@.*@^$'
)

usage() {
  cat <<'EOF'
sync-files.sh - verify/sync kubernetes/helm/vendetta-stack/files/ with the stack config files.

Usage: sync-files.sh [--check | --write] [--stack-dir DIR] [-q] [-h]

  --check       (default) exit 1 on drift, a missing source, or a stale file in files/
  --write       copy the sources over files/ and remove stale files
  --stack-dir   stack root (default: three levels above this script)
  -q            only print problems

Exit codes: 0 in sync/synced | 1 drift | 2 usage
EOF
}

say() { if ((QUIET == 0)); then printf '%s\n' "$*"; fi; }

while (($#)); do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --check) ACTION="check" ;;
    --write) ACTION="write" ;;
    -q | --quiet) QUIET=1 ;;
    --stack-dir)
      [[ $# -ge 2 && -d "$2" ]] || { echo "--stack-dir needs an existing directory" >&2; exit 2; }
      STACK_DIR="$(cd "$2" && pwd)"
      shift
      ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

declare -A EXPECT=()
problems=0

collect() {
  local entry src dst inc exc base rel
  for entry in "${MAPPINGS[@]}"; do
    IFS='@' read -r src dst inc exc <<<"$entry"
    base="$STACK_DIR/$src"
    if [[ -f "$base" ]]; then
      EXPECT["$dst"]="$base"
    elif [[ -d "$base" ]]; then
      while IFS= read -r -d '' file; do
        rel="${file#"$base"/}"
        [[ -z "$inc" || "$rel" =~ $inc ]] || continue
        [[ -z "$exc" || ! "$rel" =~ $exc ]] || continue
        EXPECT["$dst/$rel"]="$file"
      done < <(find "$base" -type f -print0 | sort -z)
    else
      echo "missing source: $src" >&2
      problems=$((problems + 1))
    fi
  done
}

collect
mkdir -p "$FILES_DIR"

changed=0
for dst in "${!EXPECT[@]}"; do
  src="${EXPECT[$dst]}"
  if [[ ! -f "$FILES_DIR/$dst" ]]; then
    state=missing
  elif ! cmp -s "$src" "$FILES_DIR/$dst"; then
    state=differs
  else
    continue
  fi
  changed=$((changed + 1))
  if [[ "$ACTION" == write ]]; then
    mkdir -p "$(dirname "$FILES_DIR/$dst")"
    install -m 0644 "$src" "$FILES_DIR/$dst"
    say "synced  $dst"
  else
    echo "$state  $dst" >&2
    problems=$((problems + 1))
  fi
done

while IFS= read -r -d '' existing; do
  rel="${existing#"$FILES_DIR"/}"
  [[ -n "${EXPECT[$rel]:-}" ]] && continue
  changed=$((changed + 1))
  if [[ "$ACTION" == write ]]; then
    rm -f "$existing"
    say "removed $rel"
  else
    echo "stale    $rel" >&2
    problems=$((problems + 1))
  fi
done < <(find "$FILES_DIR" -type f -print0)

if [[ "$ACTION" == write ]]; then
  find "$FILES_DIR" -mindepth 1 -type d -empty -delete
  ((problems == 0)) || exit 1
  say "files/ in sync (${#EXPECT[@]} files, $changed updated)"
  exit 0
fi

if ((problems > 0)); then
  echo "files/ is out of sync: run kubernetes/helm/vendetta-stack/sync-files.sh --write" >&2
  exit 1
fi
say "files/ in sync (${#EXPECT[@]} files)"
