#!/bin/bash
# patch-ossec-conf.sh — splice the CS3 manager block into /var/ossec/etc/ossec.conf, idempotently, with a check that
# the CS3 rule block is actually ours to use.
#
# Exits non-zero (so the manager does not boot half-configured) when:
#   * a rule ID in cs3-rules.xml falls outside 10120-10199,
#   * such an ID already exists in the ruleset (a collision would silently shadow one of them),
#   * ossec.conf cannot be parsed after the splice (wazuh-analysisd -t), in which case ossec.conf is restored.
#
# Idempotent through the `cs3:manager-integration` marker: a second run is a no-op, and the block is re-spliced if the
# marker is present but the receiver is gone.
set -euo pipefail

CONF=/var/ossec/etc/ossec.conf
RULES=cs3-rules.xml
MARKER='cs3:manager-integration'
# The block sits low in the stock ID space on purpose: analysisd evaluates rules in load order and stops at the first
# match that raises the level, so a CS3 rule has to be a child of the stock grouping rule that owns the line, and the
# whole block has to load after those parents exist. 10120-10199 is a free gap in the stock ruleset.
BLOCK_LO=10120
BLOCK_HI=10199
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '[manager-integration] %s\n' "$*" >&2; }
die() {
  log "ERROR: $*"
  exit 1
}

[[ -f "$CONF" ]] || die "$CONF not found; the base image is not what this wrapper expects"
[[ -f "$HERE/$RULES" ]] || die "$HERE/$RULES not found"
[[ -f "$HERE/cs3-manager.conf" ]] || die "$HERE/cs3-manager.conf not found"

# ---- 1. the rule block must be inside the reserved range and free of collisions -------------------------------
ids=$(grep -o 'rule id="[0-9]*"' "$HERE/$RULES" | grep -o '[0-9]*' | sort -u)
[[ -n "$ids" ]] || die "no rule IDs found in $RULES"

while read -r id; do
  [[ "$id" =~ ^[0-9]+$ ]] || die "rule ID '$id' is not numeric"
  if ((10#$id < BLOCK_LO || 10#$id > BLOCK_HI)); then
    die "rule ID $id is outside the reserved CS3 block $BLOCK_LO-$BLOCK_HI"
  fi
done <<<"$ids"

collisions=0
for dir in /var/ossec/ruleset/rules /var/ossec/etc/rules; do
  [[ -d "$dir" ]] || continue
  for f in "$dir"/*.xml; do
    [[ -e "$f" ]] || continue
    # Skip our own copies: the source name when run from etc/rules, and the installed name under ruleset/rules (the
    # installer writes 9999-$RULES before this runs).
    base=$(basename "$f")
    [[ "$base" == "$RULES" || "$base" == "9999-$RULES" ]] && continue
    while read -r id; do
      if grep -q "rule id=\"$id\"" "$f"; then
        log "ERROR: rule ID $id in $RULES already defined by $f"
        collisions=$((collisions + 1))
      fi
    done <<<"$ids"
  done
done
((collisions == 0)) || die "$collisions rule ID collision(s); renumber or drop the duplicates"
log "rule block $BLOCK_LO-$BLOCK_HI validated ($(wc -w <<<"$ids" | tr -d ' ') IDs, no collisions)"

# ---- 2. splice, unless already spliced ----------------------------------------------------------------------
if grep -q "$MARKER" "$CONF" && grep -q '<connection>syslog</connection>' "$CONF"; then
  log "receiver already present in $CONF; nothing to do"
  exit 0
fi

cp -a "$CONF" "$CONF.cs3.bak"

# The block is an <ossec_config> wrapper; keep only its children so they can sit inside the existing one.
inner=$(sed -n '/<ossec_config>/,/<\/ossec_config>/p' "$HERE/cs3-manager.conf" | sed '1d;$d')
[[ -n "$inner" ]] || die "manager block has no <ossec_config> children"

# Insert before the LAST closing tag, so the existing top-level block stays intact and ours lands inside it. Pure
# coreutils (no python3): the manager image is not guaranteed to expose an interpreter on PATH.
last=$(grep -n '^[[:space:]]*</ossec_config>' "$CONF" | tail -n 1 | cut -d: -f1)
[[ -n "$last" ]] || die "$CONF has no closing </ossec_config>"
{
  head -n "$((last - 1))" "$CONF"
  printf '%s\n' "$inner"
  tail -n +"$last" "$CONF"
} >"$CONF.cs3.new" || die "cannot write $CONF.cs3.new"
# Copied through a redirection, not `mv`: replacing the file would give it the ownership and mode of whoever ran the patch,
# and wazuh-db does not run as that user (it then fails with (1226) Error reading XML file and the manager will not boot).
cat "$CONF.cs3.new" >"$CONF" || die "cannot write $CONF"
rm -f "$CONF.cs3.new"

# ---- 3. the result must parse; otherwise restore and stop ---------------------------------------------
# analysisd covers decoders/rules, remoted owns <remote>; each reports its own section, so both run. wazuh-logtest style
# single-daemon checks are not enough: a valid <allowed-ips> for remoted still fails analysisd and vice versa.
checked=0
for daemon in wazuh-analysisd wazuh-remoted; do
  [[ -x "/var/ossec/bin/$daemon" ]] || continue
  if ! "/var/ossec/bin/$daemon" -t >"/tmp/cs3-$daemon-test.log" 2>&1; then
    cat "$CONF.cs3.bak" >"$CONF"
    cat "/tmp/cs3-$daemon-test.log" >&2 || true
    die "manager configuration did not validate ($daemon -t); ossec.conf restored"
  fi
  checked=$((checked + 1))
  log "configuration validated by $daemon -t"
done
[[ "$checked" -gt 0 ]] || log "WARN: no wazuh daemon found under /var/ossec/bin; skipping configuration validation"

log "syslog receiver spliced into $CONF (backup: $CONF.cs3.bak)"
