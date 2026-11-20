#!/usr/bin/env bash
# Hermetic test for vendetta/active-response/host-isolate.sh: nft / iptables are PATH stubs that record
# their invocations (and the ruleset on stdin), so no firewall is ever touched.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../active-response/host-isolate.sh"
STACK="$(cd "$HERE/../.." && pwd)"
mkdir -p "$STACK/.scratch"
WORK="$(mktemp -d "$STACK/.scratch/host-isolate.XXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT

mkdir -p "$WORK/bin" "$WORK/etc" "$WORK/logs"
for tool in nft iptables ip6tables; do
  cat >"$WORK/bin/$tool" <<'STUB'
#!/usr/bin/env bash
{ printf '%s' "$(basename "$0")"; for a in "$@"; do printf ' %s' "$a"; done; printf '\n'; } >>"$STUB_LOG"
if [[ ${1:-} == -f && ${2:-} == - ]]; then cat >>"$STUB_LOG"; fi
[[ -z ${STUB_FAIL_CHECK:-} || $* != *"-C "* ]] || exit 1
exit 0
STUB
  chmod +x "$WORK/bin/$tool"
done
export STUB_LOG="$WORK/stub.log"
export VENDETTA_HOME="$WORK"
export ISOLATE_ALLOW_FILE="$WORK/etc/isolate-allow.conf"
export ISOLATE_LOG_FILE="$WORK/logs/active-responses.log"
export PATH="$WORK/bin:$PATH"

pass=0 failn=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { failn=$((failn + 1)); printf 'FAIL %s\n' "$1" >&2; }
check() { # <desc> <expected-exit> <cmd...>
  local desc=$1 want=$2 rc=0
  shift 2
  "$@" >"$WORK/out" 2>&1 || rc=$?
  if [[ $rc == "$want" ]]; then ok "$desc"; else bad "$desc (exit $rc, wanted $want): $(cat "$WORK/out")"; fi
}
has() { if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi; }
hasnt() { if grep -qF -- "$2" "$1"; then bad "$3 (unexpected '$2' in $1)"; else ok "$3"; fi; }

ADD='{"version":1,"command":"add","parameters":{"alert":{"id":"1700000000.1","data":{"errow_fingerprint":"abc123"}},"extra_args":[]}}'
DEL='{"version":1,"command":"delete","parameters":{"alert":{"id":"1700000000.1"}}}'

: >"$STUB_LOG"
check "refuses to isolate without an allow-list" 3 bash -c "printf '%s\n' '$ADD' | '$SCRIPT'"
hasnt "$STUB_LOG" nft "no firewall call without allow-list"

printf '# manager\n10.0.0.5\n192.168.10.0/24  # jump hosts\nfd00::5\n' >"$ISOLATE_ALLOW_FILE"
: >"$STUB_LOG"
check "isolates with nft" 0 bash -c "printf '%s\n' '$ADD' | ISOLATE_BACKEND=nft '$SCRIPT'"
has "$STUB_LOG" 'ip saddr { 10.0.0.5,192.168.10.0/24 } accept' "nft input allow-list (IPv4)"
has "$STUB_LOG" 'ip6 daddr { fd00::5 } accept' "nft output allow-list (IPv6)"
has "$STUB_LOG" 'iifname "lo" accept' "loopback stays reachable"
has "$STUB_LOG" 'delete table inet vendetta_isolate' "idempotent re-creation"
has "$ISOLATE_LOG_FILE" 'host ISOLATED via nft' "audit log entry"
has "$ISOLATE_LOG_FILE" 'fingerprint=abc123' "fingerprint in audit log"

: >"$STUB_LOG"
check "removes isolation with nft" 0 bash -c "printf '%s\n' '$DEL' | ISOLATE_BACKEND=nft '$SCRIPT'"
has "$STUB_LOG" 'nft delete table inet vendetta_isolate' "nft table removed"

: >"$STUB_LOG"
check "isolates with iptables" 0 bash -c "printf '%s\n' '$ADD' | ISOLATE_BACKEND=iptables '$SCRIPT'"
has "$STUB_LOG" 'iptables -A VENDETTA_ISOLATE -s 10.0.0.5 -j ACCEPT' "iptables allow rule"
has "$STUB_LOG" 'ip6tables -A VENDETTA_ISOLATE -d fd00::5 -j ACCEPT' "ip6tables allow rule"
has "$STUB_LOG" 'iptables -A VENDETTA_ISOLATE -j DROP' "iptables default drop"

: >"$STUB_LOG"
check "dry-run never touches the firewall" 0 bash -c "printf '%s\n' '$ADD' | ISOLATE_DRY_RUN=1 '$SCRIPT'"
if [[ -s $STUB_LOG ]]; then bad "dry-run: firewall was called"; else ok "dry-run: zero firewall calls"; fi
has "$ISOLATE_LOG_FILE" 'DRY-RUN: would isolate' "dry-run audit entry"

printf '10.0.0.5\n10.0.0.1; rm -rf /\n' >"$ISOLATE_ALLOW_FILE"
: >"$STUB_LOG"
check "rejects an injected allow-list entry" 3 bash -c "printf '%s\n' '$ADD' | '$SCRIPT'"
if [[ -s $STUB_LOG ]]; then bad "invalid entry reached the firewall"; else ok "invalid entry: zero firewall calls"; fi

: >"$ISOLATE_ALLOW_FILE"
check "refuses an empty allow-list" 3 bash -c "printf '%s\n' '$ADD' | '$SCRIPT'"
check "rejects non-JSON input" 2 bash -c "printf 'hello\n' | '$SCRIPT'"
check "rejects an unknown command" 2 bash -c "printf '%s\n' '{\"command\":\"reboot\"}' | '$SCRIPT'"

printf '\n%d passed, %d failed\n' "$pass" "$failn"
[[ $failn -eq 0 ]]
