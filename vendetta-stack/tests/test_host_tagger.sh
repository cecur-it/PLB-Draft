#!/usr/bin/env bash
# tests/test_host_tagger.sh — conf.d/70-filters-global.conf must classify `host.syslog` into the four tags the manager leg
# consumes, in a way that cannot double-emit, cannot loop, and cannot starve a record of its `source`/`agentName` shape.
# Static assertions only (no fluent-bit binary).
set -uo pipefail

STACK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GLOBAL="$STACK/fluent-bit/conf.d/70-filters-global.conf"
LEG="$STACK/fluent-bit/legs/50-manager.conf"
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() {
  printf 'FAIL %s\n' "$1" >&2
  fail=1
}

# The tagger block: from its comment header up to the next `[FILTER]` that is not ours.
block=$(awk '/^# ---- 0\. Host-source tagger/,/^# ---- 1\./' "$GLOBAL")
rules=$(printf '%s\n' "$block" | grep -c '^[[:space:]]*Rule ')

((rules > 0)) && ok "tagger block present with $rules rules" || bad "no tagger rules found"

# Each of the four downstream tags must be produced.
for tag in host.auth host.audit host.network host.endpoint; do
  printf '%s\n' "$block" | grep -Eq "Rule .* ${tag} false" && ok "produces ${tag}" || bad "never produces ${tag}"
done

# KEEP=false everywhere, otherwise every record is emitted twice (once per tag).
strays=$(printf '%s\n' "$block" | grep '^[[:space:]]*Rule ' | grep -vc ' false$')
((strays == 0)) && ok "every rule drops the source record (no double emit)" || bad "$strays rule(s) with KEEP=true"

# Scoped to host.syslog only: retagged records re-enter the chain and must not be re-tagged (that would loop).
printf '%s\n' "$block" | grep -Eq '^[[:space:]]*Match +host\.syslog$' && ok "tagger matches host.syslog only" || bad "tagger match is not host.syslog"

# The catch-all keeps an unidentified appliance line from being stranded on a tag nobody routes.
tail_rule=$(printf '%s\n' "$block" | grep '^[[:space:]]*Rule ' | tail -n 1)
case "$tail_rule" in
  *host.endpoint\ false) ok "last rule is the endpoint catch-all" ;;
  *) bad "last rule is not the endpoint catch-all: $tail_rule" ;;
esac

# Order matters: a record dropped by rule N never reaches rule N+1. Classification must precede the catch-all and the
# specific auth/audit idents must precede the broader network patterns.
pos() { printf '%s\n' "$block" | grep -n "Rule .* $1 false" | head -n 1 | cut -d: -f1; }
(( $(pos host.audit) < $(pos host.network) )) && ok "audit before network" || bad "audit is not classified before network"
(( $(pos host.auth) < $(pos host.endpoint) )) && ok "auth before catch-all" || bad "auth is not classified before the catch-all"

# Every retagged stream must turn the emitting program into `source` (the RFC5424 appname the manager decoders key on),
# and the generic `source syslog` fallback must run last: modify `Add` never overwrites, so an earlier fallback would
# shadow the specific value.
for t in auth audit network endpoint; do
  grep -A 5 "Match  *host\\.$t\$" "$GLOBAL" | grep -q 'Rename  *ident source' &&
    ok "host.$t copies ident into source" || bad "host.$t does not carry the program name"
done
grep -A 4 'Alias  *host_auth_shape' "$GLOBAL" | grep -q 'Rename  *ident source' ||
  bad "host_auth_shape loses the program name"

generic=$(grep -n 'Alias  *host_syslog_shape' "$GLOBAL" | cut -d: -f1)
for t in auth audit network endpoint; do
  (( $(grep -n "Alias  *host_${t}_shape" "$GLOBAL" | cut -d: -f1) < generic )) &&
    ok "generic source fallback runs after host_$t" || bad "generic source fallback shadows host_$t"
done
grep -A 4 'Alias  *host_syslog_shape' "$GLOBAL" | grep -q 'Add  *agentName' ||
  bad "agentName is not set on every host stream"
grep -B 3 -A 4 'Alias  *host_syslog_shape' "$GLOBAL" | grep -Eq 'Match_Regex +\^host\\\.\(syslog\|auth\|audit\|network\|endpoint\)\$' &&
  ok "generic block covers all four tags" || bad "generic block lost the retagged tags"

# ---- journal classifier (section 2b) ---------------------------------------------------------------------------
# Journald is where endpoint/container events actually originate. Without this block `host.endpoint` only ever came from
# appliance syslog, and journal records stayed on `host.journal`, which the manager leg does not route.
jn=$(awk '/^# ---- 2b\. Journal classifier/,/^# ---- 3\./' "$GLOBAL")
[[ -n "$jn" ]] && ok "journal classifier block present" || bad "journal classifier block missing"
printf '%s\n' "$jn" | grep -Eq '^[[:space:]]*Match +host\.journal$' && ok "journal classifier matches host.journal" || bad "journal classifier has the wrong match"
for tag in host.auth host.audit host.network host.endpoint; do
  printf '%s\n' "$jn" | grep -Eq "Rule .* ${tag} false" && ok "journal classifier produces ${tag}" || bad "journal classifier never produces ${tag}"
done
strays=$(printf '%s\n' "$jn" | grep '^[[:space:]]*Rule ' | grep -vc ' false$')
((strays == 0)) && ok "journal rules drop the source record" || bad "$strays journal rule(s) with KEEP=true"

# Ordering: the leaky bucket keys on host.journal, so classifying before it would let a whole-journal burst bypass
# CS3_EPS_LIMIT. The classifier must therefore come after the throttle and before the Lua section.
bucket=$(grep -n 'Alias  *leaky_bucket_noisy' "$GLOBAL" | cut -d: -f1)
classifier=$(grep -n 'Alias  *host_journal_tagger' "$GLOBAL" | cut -d: -f1)
((classifier > bucket)) && ok "journal classifier runs after the leaky bucket" || bad "journal classifier bypasses the throttle"
grep -A 6 'Alias  *host_journal_shape' "$GLOBAL" | grep -q 'Rename  *SYSLOG_IDENTIFIER source' &&
  ok "journal shape promotes SYSLOG_IDENTIFIER into source" || bad "journal records reach the manager as source=syslog"
grep -A 7 'Alias  *host_journal_shape' "$GLOBAL" | grep -q 'Rename  *HOSTNAME host' &&
  ok "journal shape promotes HOSTNAME into host" || bad "journal records arrive without a device identity"

# Every rewritten tag field must exist in a shaped journal record: the classifier keys on $source (set by the shape) and
# optionally $message. A rule keyed on a field nobody sets silently never fires.
printf '%s\n' "$jn" | grep '^[[:space:]]*Rule ' | grep -Evq '\$(source|message) ' && bad "a journal rule keys on a field the shape does not set" ||
  ok "journal rules key on shaped fields only"

# The manager leg and the console leg must both accept what the tagger produces.
grep -Eq 'Match_Regex +\^\(host\\\.\(syslog\|auth\|audit\|network\|endpoint\)\)\$' "$LEG" &&
  ok "manager leg routes all four tags" || bad "manager leg does not route all four tags"
grep -Eq 'Match_Regex +\^\(host\\\.\.\*\|' "$STACK/fluent-bit/legs/10-console.conf" &&
  ok "console leg still routes host.*" || bad "console leg no longer routes host.*"

exit "$fail"
