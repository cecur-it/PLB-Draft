#!/bin/bash
# configure-feeds.sh — own the manager's CTI / vulnerability-feed settings.
#
# Why this exists: the stock manager image ships
#   <vulnerability-detection><enabled>yes</enabled><feed-update-interval>60m</feed-update-interval></vulnerability-detection>
# so wazuh-modulesd's content updater resolves cti.wazuh.com on every interval. A deployment without egress (the usual CS3
# case: loopback-bound ports, air-gapped enclave) fails that fetch forever and logs
#   wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: ... Couldn't resolve host name
# every interval. That is configuration, not an environment fault to live with: `enabled`, `cti-url` and
# `feed-update-interval` are all supported keys (they are in the wazuh-modulesd binary).
#
# CS3_MANAGER_FEED_MODE:
#   auto   (default) leave the block alone; log what will happen so the operator can decide
#   off              <enabled>no</enabled> — the updater never fetches, and the error disappears
#   mirror           keep it enabled and point <cti-url> at CS3_MANAGER_CTI_URL (an internal mirror)
# CS3_MANAGER_CTI_URL: required by `mirror`, honoured by `auto` when set.
#
# Idempotent: the block is set to a fixed state, so a second run is byte-identical. Exits non-zero only when it cannot do
# what it was asked and CS3_MANAGER_STRICT=true; otherwise it warns, because a manager that still analyses logs is more
# useful than one that refuses to boot over a feed setting.
set -uo pipefail

CONF=${CS3_MANAGER_CONF:-/var/ossec/etc/ossec.conf}
MODE=${CS3_MANAGER_FEED_MODE:-auto}
CTI_URL=${CS3_MANAGER_CTI_URL:-}
STRICT=${CS3_MANAGER_STRICT:-false}
MODULESD=/var/ossec/bin/wazuh-modulesd

log() { printf '[manager-integration] %s\n' "$*" >&2; }
fail() {
  log "ERROR: $*"
  [[ "$STRICT" == "true" ]] && exit 1
  log "WARN: continuing with the feed settings untouched (CS3_MANAGER_STRICT=$STRICT)"
  exit 0
}

[[ -f "$CONF" ]] || fail "$CONF not found"

# 'mirror' without a URL is a configuration bug, not something to guess at.
if [[ "$MODE" == "mirror" ]]; then
  [[ -n "$CTI_URL" ]] || fail "CS3_MANAGER_FEED_MODE=mirror needs CS3_MANAGER_CTI_URL"
elif [[ "$MODE" == "auto" && -n "$CTI_URL" ]]; then
  MODE=mirror
fi

case "$MODE" in
  auto | off | mirror) ;;
  *) fail "CS3_MANAGER_FEED_MODE='$MODE' is not one of auto|off|mirror" ;;
esac

have_block() { grep -q '<vulnerability-detection>' "$CONF"; }

if ! have_block; then
  # A full CS3_MANAGER_CONF_TEMPLATE may simply not carry the block; there is then nothing to fetch and nothing to set.
  [[ "$MODE" == "off" ]] && log "no <vulnerability-detection> block; the feed updater is not configured, nothing to disable"
  [[ "$MODE" != "off" ]] && log "WARN: no <vulnerability-detection> block; cannot set feed mode '$MODE'"
  exit 0
fi

# Portable extraction (BSD and GNU sed disagree about \| in a BRE): field 2 between </?enabled> is the value.
current=$(awk -F'</?enabled>' '/<vulnerability-detection>/ { f = 1 } f && /<enabled>/ { print $2; exit }' "$CONF")

if [[ "$MODE" == "auto" ]]; then
  if [[ "$current" == "yes" ]]; then
    log "vulnerability feed updater is enabled and no mirror is configured: it fetches from cti.wazuh.com every 60m. Set CS3_MANAGER_FEED_MODE=off where there is no egress, or set CS3_MANAGER_CTI_URL to an internal mirror."
  else
    log "vulnerability feed updater is disabled in $CONF; leaving it disabled"
  fi
  exit 0
fi

want_enabled=yes
[[ "$MODE" == "off" ]] && want_enabled=no

cp -a "$CONF" "$CONF.feeds.bak"
# Rewrite only inside the block: set <enabled>, and for mirror mode set/replace <cti-url>. Outside the block the file is
# copied byte for byte, so no other setting is touched.
tmp="$CONF.feeds.new"
MODE="$MODE" WANT="$want_enabled" CTI_URL="$CTI_URL" awk '
  /<vulnerability-detection>/ { inblk = 1 }
  inblk && /<enabled>/ {
    match($0, /^[ \t]*/); indent = substr($0, 1, RLENGTH)
    print indent "<enabled>" ENVIRON["WANT"] "</enabled>"
    seen_enabled = 1
    next
  }
  inblk && /<\/vulnerability-detection>/ {
    # A block without <enabled> gets one inserted; mirror mode also inserts <cti-url> if the block never had it.
    if (!seen_enabled) { match($0, /^[ \t]*/); indent = substr($0, 1, RLENGTH); print indent "<enabled>" ENVIRON["WANT"] "</enabled>" }
    if (ENVIRON["MODE"] == "mirror" && !seen_url) { match($0, /^[ \t]*/); print substr($0, 1, RLENGTH) "  <cti-url>" ENVIRON["CTI_URL"] "</cti-url>" }
    inblk = 0
  }
  inblk && /<cti-url>/ {
    match($0, /^[ \t]*/); indent = substr($0, 1, RLENGTH)
    if (ENVIRON["MODE"] == "mirror") print indent "<cti-url>" ENVIRON["CTI_URL"] "</cti-url>"
    seen_url = 1
    next
  }
  { print }
' "$CONF" >"$tmp" || {
  rm -f "$tmp"
  fail "cannot rewrite $CONF"
}

# The rewrite is a no-op unless something actually differs; skip the swap (and the validation) when nothing changed.
# Plain `cat` comparison rather than cmp/diff: neither is guaranteed in the manager image.
if [[ "$(cat "$CONF")" == "$(cat "$tmp")" ]]; then
  rm -f "$tmp" "$CONF.feeds.bak"
  log "feed mode $MODE already applied; nothing to do"
  exit 0
fi

# Written through a redirection, never with mv: replacing the file creates a new inode owned by whoever ran this script,
# and wazuh-db does not run as that user -- it then reports (1226) Error reading XML file and the whole manager fails to
# start. Redirection keeps the inode, so ossec.conf keeps the ownership and mode the image gave it.
if [[ -x "$MODULESD" ]]; then
  cat "$tmp" >"$CONF" || fail "cannot write $CONF"
  if ! "$MODULESD" -t >/tmp/cs3-modulesd-test.log 2>&1; then
    cat "$CONF.feeds.bak" >"$CONF"
    cat /tmp/cs3-modulesd-test.log >&2 || true
    fail "manager configuration did not validate; ossec.conf restored"
  fi
  log "configuration validated by wazuh-modulesd -t"
else
  cat "$tmp" >"$CONF" || fail "cannot write $CONF"
  log "WARN: $MODULESD missing; skipping configuration validation"
fi
rm -f "$tmp"

log "vulnerability feed updater set to '$MODE' (backup: $CONF.feeds.bak)"
