#!/usr/bin/env bash
# host-isolate.sh — Vendetta (Wazuh-protocol) active-response script: network-isolate this endpoint.
#
# Invoked by the manager (PUT /active-response, command "!host-isolate.sh", arguments ["-"]) on the AGENT.
# Reads ONE JSON line from stdin (active-response protocol v1):
#   {"version":1,"command":"add"|"delete","parameters":{"alert":{...},"extra_args":[...]}}
# add    -> drop all traffic except loopback and the allow-listed management addresses
# delete -> remove the isolation (manual un-isolate, also used by the test-suite)
#
# Safety: an empty/invalid allow-list means the host would cut itself off from its own manager, so the
# script REFUSES to isolate (exit 3). The allow-list is $VENDETTA_HOME/etc/isolate-allow.conf, one IPv4/
# IPv6 address or CIDR per line ('#' comments allowed); it must contain the manager (1514/1515) and, if
# you want remote recovery, your jump host. The script is idempotent (add twice == add once).
#
# Backends: nftables (preferred, one atomic table `inet vendetta_isolate`) or iptables+ip6tables (chain
# VENDETTA_ISOLATE). Logs to $VENDETTA_HOME/logs/active-responses.log. Requires: jq.
#
# Env: VENDETTA_HOME (default /var/ossec), ISOLATE_BACKEND=auto|nft|iptables, ISOLATE_DRY_RUN=1 (log only).
set -euo pipefail
IFS=$'\n\t'
umask 027

VENDETTA_HOME=${VENDETTA_HOME:-/var/ossec}
ALLOW_FILE=${ISOLATE_ALLOW_FILE:-${VENDETTA_HOME}/etc/isolate-allow.conf}
LOG_FILE=${ISOLATE_LOG_FILE:-${VENDETTA_HOME}/logs/active-responses.log}
BACKEND=${ISOLATE_BACKEND:-auto}
DRY_RUN=${ISOLATE_DRY_RUN:-0}
NFT_TABLE=vendetta_isolate
IPT_CHAIN=VENDETTA_ISOLATE

log() {
  local line
  line="$(date -u '+%Y/%m/%d %H:%M:%S') active-response/host-isolate: $*"
  mkdir -p -- "$(dirname -- "$LOG_FILE")" 2>/dev/null || true
  printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || printf '%s\n' "$line" >&2
}
die() { local code=$1; shift; log "ERROR: $*"; exit "$code"; }

command -v jq >/dev/null 2>&1 || die 4 "jq is required"

# One protocol line from stdin; tolerate a missing trailing newline.
IFS= read -r input || [[ -n ${input:-} ]] || die 2 "no input on stdin"
command=$(jq -er '.command' <<<"$input" 2>/dev/null) || die 2 "stdin is not an active-response JSON message"
case "$command" in add | delete) ;; *) die 2 "unsupported command '$command'" ;; esac

# Only IPv4/IPv6 literals and CIDRs are accepted into firewall rules.
valid_addr() {
  local a=$1
  [[ $a =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && return 0
  [[ $a =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ && $a == *:* ]] && return 0
  return 1
}

allowed_v4=()
allowed_v6=()
load_allow_list() {
  [[ -r $ALLOW_FILE ]] || die 3 "allow-list $ALLOW_FILE missing; refusing to isolate (would cut the manager link)"
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}
    line=${line//[[:space:]]/}
    [[ -n $line ]] || continue
    valid_addr "$line" || die 3 "invalid allow-list entry '$line'"
    if [[ $line == *:* ]]; then allowed_v6+=("$line"); else allowed_v4+=("$line"); fi
  done <"$ALLOW_FILE"
  ((${#allowed_v4[@]} + ${#allowed_v6[@]} > 0)) || die 3 "allow-list is empty; refusing to isolate"
}

pick_backend() {
  case "$BACKEND" in
    nft | iptables) return 0 ;;
    auto)
      if command -v nft >/dev/null 2>&1; then BACKEND=nft
      elif command -v iptables >/dev/null 2>&1; then BACKEND=iptables
      else die 4 "neither nft nor iptables found"; fi ;;
    *) die 2 "ISOLATE_BACKEND must be auto, nft or iptables" ;;
  esac
}

join_csv() { local IFS=,; printf '%s' "$*"; }

nft_add() {
  local rules="" v4="" v6=""
  ((${#allowed_v4[@]} == 0)) || v4=$(join_csv "${allowed_v4[@]}")
  ((${#allowed_v6[@]} == 0)) || v6=$(join_csv "${allowed_v6[@]}")
  rules+="table inet ${NFT_TABLE} {"$'\n'
  rules+="  chain input { type filter hook input priority -100; policy accept;"$'\n'
  rules+="    iifname \"lo\" accept"$'\n'
  [[ -z $v4 ]] || rules+="    ip saddr { ${v4} } accept"$'\n'
  [[ -z $v6 ]] || rules+="    ip6 saddr { ${v6} } accept"$'\n'
  rules+="    drop"$'\n'
  rules+="  }"$'\n'
  rules+="  chain output { type filter hook output priority -100; policy accept;"$'\n'
  rules+="    oifname \"lo\" accept"$'\n'
  [[ -z $v4 ]] || rules+="    ip daddr { ${v4} } accept"$'\n'
  [[ -z $v6 ]] || rules+="    ip6 daddr { ${v6} } accept"$'\n'
  rules+="    drop"$'\n'
  rules+="  }"$'\n'
  rules+="}"$'\n'
  # add-then-delete-then-add in one transaction keeps the operation idempotent and atomic
  { printf 'add table inet %s\ndelete table inet %s\n' "$NFT_TABLE" "$NFT_TABLE"; printf '%s' "$rules"; } | nft -f -
}
nft_del() { nft delete table inet "$NFT_TABLE" 2>/dev/null || true; }

ipt_one() { # <iptables-cmd> <addr...>
  local cmd=$1 a hook
  shift
  "$cmd" -N "$IPT_CHAIN" 2>/dev/null || "$cmd" -F "$IPT_CHAIN"
  "$cmd" -A "$IPT_CHAIN" -i lo -j ACCEPT
  "$cmd" -A "$IPT_CHAIN" -o lo -j ACCEPT
  for a in "$@"; do
    "$cmd" -A "$IPT_CHAIN" -s "$a" -j ACCEPT
    "$cmd" -A "$IPT_CHAIN" -d "$a" -j ACCEPT
  done
  "$cmd" -A "$IPT_CHAIN" -j DROP
  for hook in INPUT OUTPUT; do
    "$cmd" -C "$hook" -j "$IPT_CHAIN" 2>/dev/null || "$cmd" -I "$hook" 1 -j "$IPT_CHAIN"
  done
}
ipt_add() {
  ((${#allowed_v4[@]} == 0)) || ipt_one iptables "${allowed_v4[@]}"
  if ((${#allowed_v6[@]} > 0)); then
    command -v ip6tables >/dev/null 2>&1 || die 4 "IPv6 allow-list entries need ip6tables"
    ipt_one ip6tables "${allowed_v6[@]}"
  fi
}
ipt_del_one() {
  local cmd=$1 hook
  command -v "$cmd" >/dev/null 2>&1 || return 0
  for hook in INPUT OUTPUT; do
    while "$cmd" -D "$hook" -j "$IPT_CHAIN" 2>/dev/null; do :; done
  done
  "$cmd" -F "$IPT_CHAIN" 2>/dev/null || true
  "$cmd" -X "$IPT_CHAIN" 2>/dev/null || true
}
ipt_del() { ipt_del_one iptables; ipt_del_one ip6tables; }

pick_backend
alert_id=$(jq -r '.parameters.alert.id // "unknown"' <<<"$input")
fingerprint=$(jq -r '.parameters.alert.data.errow_fingerprint // "n/a"' <<<"$input")

if [[ $command == add ]]; then
  load_allow_list
  if [[ $DRY_RUN == 1 ]]; then
    log "DRY-RUN: would isolate host via $BACKEND (allow: ${allowed_v4[*]:-} ${allowed_v6[*]:-}) alert=$alert_id fingerprint=$fingerprint"
    exit 0
  fi
  if [[ $BACKEND == nft ]]; then nft_add; else ipt_add; fi
  log "host ISOLATED via $BACKEND (allow: ${allowed_v4[*]:-} ${allowed_v6[*]:-}) alert=$alert_id fingerprint=$fingerprint"
else
  if [[ $DRY_RUN == 1 ]]; then log "DRY-RUN: would remove isolation via $BACKEND"; exit 0; fi
  if [[ $BACKEND == nft ]]; then nft_del; else ipt_del; fi
  log "host isolation REMOVED via $BACKEND alert=$alert_id"
fi
