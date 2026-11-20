# shellcheck shell=bash
# shellcheck disable=SC2016  # single-quoted jq/awk/sed programs and literal $ patterns are intentional
# Cases: backup-opensearch.sh against a TLS OpenSearch mock (snapshot repo + snapshot + retention + verified restore)
# and the encrypted file backups (pki/, secrets/, models.json).

BK_PASS="correct-horse-battery-staple-1234"

# bk_spec <out.json> — OpenSearch mock; BK_SEQ (JSON array) replaces the per-snapshot GET sequence, BK_REPO_EXISTS=1 answers 200 for the repo,
# BK_RESTORE_FAILED sets the failed shard count of the restore response
bk_spec() {
  local out=$1 pw
  pw="$(<"$TREE/secrets/opensearch_admin_password")"
  jq -n --arg pw "$pw" --arg pki "$TREE/pki" --argjson seq "${BK_SEQ:-null}" --arg repo_exists "${BK_REPO_EXISTS:-0}" --argjson rfail "${BK_RESTORE_FAILED:-0}" '
    def snap($state): {json: {snapshots: [{snapshot: "x", state: $state,
      indices: ["vendetta-alerts-2026.11.13", "errow-2026.11.13", ".opendistro-x", "cs3-ai-audit-2026.11.13"],
      shards: {total: 3, failed: 0, successful: 3}}]}};
    def old($n; $state): {snapshot: "vendetta-old\($n)", state: $state, start_time_in_millis: $n};
    def repo: {json: {"vendetta-snapshots": {type: "fs", settings: {location: "/usr/share/opensearch/snapshots"}}}};
    {listeners: [{name: "os", auth: {basic: "admin:\($pw)"},
      tls: {cert: "\($pki)/opensearch.crt", key: "\($pki)/opensearch.key", ca: "\($pki)/ca.crt", require_client_cert: false},
      routes: {
        "GET /_cluster/health": {json: {status: "green"}},
        "GET /_snapshot/vendetta-snapshots": (if $repo_exists == "1" then repo else {sequence: [{status: 404, json: {error: {type: "repository_missing_exception"}}}, repo]} end),
        "PUT /_snapshot/vendetta-snapshots": {json: {acknowledged: true}},
        "GET /_snapshot/vendetta-snapshots/vendetta-*": {sequence: ($seq // [{status: 404, json: {error: {type: "snapshot_missing_exception"}}}, snap("IN_PROGRESS"), snap("SUCCESS")])},
        "PUT /_snapshot/vendetta-snapshots/vendetta-*": {json: {accepted: true}},
        "GET /_snapshot/vendetta-snapshots/_all": {json: {snapshots: [old(1; "SUCCESS"), old(2; "SUCCESS"), old(3; "SUCCESS"), old(4; "SUCCESS"),
          {snapshot: "other-manual", state: "SUCCESS", start_time_in_millis: 0}, {snapshot: "vendetta-broken", state: "FAILED", start_time_in_millis: 0}]}},
        "DELETE /_snapshot/vendetta-snapshots/*": {json: {acknowledged: true}},
        "POST /_snapshot/vendetta-snapshots/*": {json: {snapshot: {shards: {failed: $rfail, total: 3, successful: (3 - $rfail)}}}},
        "DELETE /restore-test-*": {json: {acknowledged: true}},
        "GET /_cluster/health/*": {json: {status: "yellow"}},
        "GET /restore-test-*": {json: {count: 5, _shards: {total: 1, failed: 0}}}
      }}]}' >"$out"
}

bk_start() { # <mock-name> — spec from the current BK_* variables; sets BK_URL and BK_PID
  bk_spec "$WORK/$1.json"
  start_mock "$1" "$WORK/$1.json"
  BK_PID=$MOCK_LAST_PID
  BK_URL="https://localhost:$(mock_port "$1" os)"
}

bk_passphrase() { # <file>
  printf '%s' "$BK_PASS" >"$1"
  chmod 0600 "$1"
}

case_backup_dry_run_and_policy() {
  local pp bkdir
  new_tree_pki bkd || return 1
  pp="$WORK/bkd.pass"
  bk_passphrase "$pp"
  bkdir="$WORK/bkd-backups"
  mkdir -p "$TREE/ollama"

  t_run "--help lists the exit codes" 0 "$S/backup-opensearch.sh" --help
  out_has "--help documents restore verification" 'verify-restore'
  t_run "dry-run: no network, no writes" 0 "$S/backup-opensearch.sh" --dry-run --url https://localhost:1 --backup-dir "$bkdir" --passphrase-file "$pp" --verify-restore --keep 3
  out_has "plans the repository" 'would ensure repository vendetta-snapshots'
  out_has "plans the restore test" 'restore up to 3 index.*restore-test-'
  out_has "plans the encrypted pki archive" 'pki\.tar\.enc'
  out_lacks "secrets are not planned without --include-secrets" 'secrets\.tar\.enc'
  check_not "dry-run created no backup directory" test -e "$bkdir"
  t_run "dry-run with --include-secrets plans secrets.tar.enc" 0 "$S/backup-opensearch.sh" --dry-run --backup-dir "$bkdir" --passphrase-file "$pp" --include-secrets --files-only
  out_has "secrets archive planned" 'secrets\.tar\.enc'
  out_lacks "passphrase never printed" "$BK_PASS"

  t_run "pki/ present but no passphrase file → usage error" 2 "$S/backup-opensearch.sh" --dry-run --backup-dir "$bkdir"
  out_has "explains why" 'always encrypted'
  t_run "--skip-pki needs no passphrase" 0 "$S/backup-opensearch.sh" --dry-run --backup-dir "$bkdir" --skip-pki --files-only
  t_run "missing passphrase file without --create-passphrase → 2" 2 "$S/backup-opensearch.sh" --backup-dir "$bkdir" --passphrase-file "$WORK/nope.pass" --files-only
  chmod 0644 "$pp"
  t_run "group/world-readable passphrase file → policy refusal (3)" 3 "$S/backup-opensearch.sh" --backup-dir "$bkdir" --passphrase-file "$pp" --files-only
  out_has "names the fix" 'chmod 600'
  check_not "refusal wrote nothing" test -e "$bkdir"
  chmod 0600 "$pp"
  printf 'short' >"$WORK/bkd.short"
  chmod 0600 "$WORK/bkd.short"
  t_run "passphrase shorter than 16 chars → 2" 2 "$S/backup-opensearch.sh" --backup-dir "$bkdir" --passphrase-file "$WORK/bkd.short" --files-only
  t_run "--url must be https" 2 "$S/backup-opensearch.sh" --dry-run --url http://localhost:9200 --skip-pki
  t_run "--keep 0 rejected" 2 "$S/backup-opensearch.sh" --dry-run --keep 0 --skip-pki
  t_run "--verify-restore needs the snapshot step" 2 "$S/backup-opensearch.sh" --dry-run --verify-restore --files-only --skip-pki
  t_run "--snapshot-only and --files-only conflict" 2 "$S/backup-opensearch.sh" --dry-run --snapshot-only --files-only --skip-pki
  t_run "invalid --indices rejected" 2 "$S/backup-opensearch.sh" --dry-run --indices 'a b;rm' --skip-pki
  t_run "--create-passphrase generates a 0600 file" 0 "$S/backup-opensearch.sh" --backup-dir "$bkdir" --passphrase-file "$WORK/bkd.new.pass" --create-passphrase --files-only
  mode_is "generated passphrase file mode" 600 "$WORK/bkd.new.pass"
  out_has "warns to keep an offline copy" 'OFFLINE'
  check "generated passphrase is long enough" test "$(wc -c <"$WORK/bkd.new.pass")" -ge 32
  t_run "re-run reuses the passphrase file" 0 "$S/backup-opensearch.sh" --backup-dir "$bkdir" --passphrase-file "$WORK/bkd.new.pass" --create-passphrase --files-only
  out_lacks "no second generation" 'generated'
}

case_backup_snapshot() {
  local pp bkdir
  new_tree_pki bks || return 1
  pp="$WORK/bks.pass"
  bk_passphrase "$pp"
  bkdir="$WORK/bks-backups"
  bk_start bks
  local common=(--url "$BK_URL" --passphrase-file "$pp" --backup-dir "$bkdir" --keep 2)

  t_run "full run: repo registered, snapshot SUCCESS, retention, files" 0 "$S/backup-opensearch.sh" "${common[@]}"
  out_has "snapshot named vendetta-<ts>" 'snapshot vendetta-[0-9]{8}-[0-9]{6} SUCCESS: 4 index'
  out_has "summary line" 'backup complete: snapshot=vendetta-[0-9]{8}-[0-9]{6} state=SUCCESS pruned_snapshots=2'
  eq "repository registered exactly once" 1 "$(req_count bks '.method=="PUT" and .path=="/_snapshot/vendetta-snapshots"')"
  eq "every request carried valid credentials" 0 "$(req_count bks '.auth_ok == false')"
  eq "snapshot created once" 1 "$(req_count bks '.method=="PUT" and (.path|test("^/_snapshot/vendetta-snapshots/vendetta-[0-9]+-[0-9]+$"))')"
  eq "retention deleted the two oldest vendetta-* snapshots" 2 "$(req_count bks '.method=="DELETE" and (.path|test("^/_snapshot/vendetta-snapshots/vendetta-old[12]$"))')"
  eq "newer / foreign / failed snapshots untouched" 0 "$(req_count bks '.method=="DELETE" and (.path|test("old[34]|other-manual|vendetta-broken"))')"
  eq "no restore without --verify-restore" 0 "$(req_count bks '.method=="POST"')"
  out_lacks "admin password never printed" "$(<"$TREE/secrets/opensearch_admin_password")"
  stop_mock "$BK_PID"

  BK_REPO_EXISTS=1 bk_start bks2
  t_run "existing repository is reused (idempotent)" 0 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --keep 14
  out_has "reuse reported" 'already registered'
  eq "no repository PUT when it exists" 0 "$(req_count bks2 '.method=="PUT" and .path=="/_snapshot/vendetta-snapshots"')"
  eq "keep 14 prunes nothing" 0 "$(req_count bks2 '.method=="DELETE"')"
  t_run "wrong admin password → exit 5" 5 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --password-file "$pp"
  out_has "credentials refused" 'refused the credentials'
  stop_mock "$BK_PID"
  t_run "OpenSearch unreachable → exit 5" 5 "$S/backup-opensearch.sh" --url https://localhost:1 --snapshot-only
  out_has "retried with backoff" 'retry 1/3'

  BK_SEQ='[{"status":404,"json":{}},{"json":{"snapshots":[{"snapshot":"x","state":"PARTIAL","failures":[{"reason":"shard 0 failed"}]}]}}]' bk_start bks3
  t_run "PARTIAL snapshot → failure (1)" 1 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only
  out_has "state named" 'finished as PARTIAL'
  eq "no retention after a failed snapshot" 0 "$(req_count bks3 '.method=="DELETE"')"
  stop_mock "$BK_PID"

  BK_SEQ='[{"status":404,"json":{}},{"json":{"snapshots":[{"snapshot":"x","state":"IN_PROGRESS"}]}}]' bk_start bks4
  t_run "snapshot that never finishes → failure (1) after --wait-timeout" 1 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --wait-timeout 20
  out_has "timeout named" 'still IN_PROGRESS after 20s'
  stop_mock "$BK_PID"

  BK_SEQ='[{"status":404,"json":{}},{"json":{"snapshots":[{"snapshot":"x","state":"SUCCESS","indices":["errow-2026.11.13"],"shards":{"total":1,"failed":1}}]}}]' bk_start bks5
  t_run "SUCCESS with failed shards → failure (1)" 1 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only
  out_has "failed shards named" 'failed shards'
  stop_mock "$BK_PID"
}

case_backup_restore() {
  local pp
  new_tree_pki bkr || return 1
  pp="$WORK/bkr.pass"
  bk_passphrase "$pp"
  bk_start bkr
  t_run "--verify-restore restores a sample into restore-test-* and removes it" 0 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --verify-restore --keep 14
  out_has "restore test passed" 'restore test passed \(15 document\(s\) readable\)'
  eq "one restore call" 1 "$(req_count bkr '.method=="POST" and (.path|test("/_restore$"))')"
  eq "data indices restored under the scratch prefix (3)" 3 "$(req_count bkr '.method=="GET" and (.path|test("^/restore-test-.*/_count$"))')"
  eq "dot indices are never restored" 0 "$(req_count bkr '.path|test("restore-test-\\.")')"
  eq "scratch indices deleted (pre-clean + cleanup, 3 each)" 6 "$(req_count bkr '.method=="DELETE" and (.path|test("^/restore-test-[a-z0-9.-]+$"))')"
  eq "nothing outside restore-test-* deleted" 0 "$(req_count bkr '.method=="DELETE" and (.path|test("^/restore-test-|^/_snapshot/")|not)')"
  t_run "--restore-sample 1 restores one index" 0 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --verify-restore --restore-sample 1 --keep 14
  out_has "one index" 'restore test: 1 index'
  stop_mock "$BK_PID"

  BK_RESTORE_FAILED=2 bk_start bkr2
  t_run "restore with failed shards → failure (1)" 1 "$S/backup-opensearch.sh" --url "$BK_URL" --snapshot-only --verify-restore --keep 14
  out_has "failure named" 'reported 2 failed shard'
  check "scratch indices cleaned up even after the failure" test "$(req_count bkr2 '.method=="DELETE" and (.path|test("^/restore-test-"))')" -ge 6
  stop_mock "$BK_PID"
}

case_backup_files() {
  local pp bkdir d n
  new_tree_pki bkf || return 1
  pp="$WORK/bkf.pass"
  bk_passphrase "$pp"
  bkdir="$WORK/bkf-backups"
  mkdir -p "$bkdir/20200101T000000Z" "$bkdir/20200102T000000Z" "$bkdir/20200103T000000Z" "$bkdir/notes"

  t_run "--files-only writes the encrypted backup set" 0 "$S/backup-opensearch.sh" --files-only --backup-dir "$bkdir" --passphrase-file "$pp" --keep 2
  d="$(find "$bkdir" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*T[0-9]*Z' | sort | tail -n 1)"
  check "backup directory created" test -n "$d"
  for n in ollama-models.json pki.tar.enc SHA256SUMS MANIFEST.json; do check "has $n" test -f "$d/$n"; done
  check_not "no secrets archive by default" test -e "$d/secrets.tar.enc"
  mode_is "backup dir mode" 700 "$d"
  mode_is "pki archive mode" 600 "$d/pki.tar.enc"
  mode_is "backup root mode" 700 "$bkdir"
  check "SHA256SUMS verifies" bash -c 'cd "$1" && sha256sum -c SHA256SUMS' _ "$d"
  check "models.json copied byte-identical" cmp -s "$TREE/ollama/models.json" "$d/ollama-models.json"
  check "MANIFEST lists the pki archive as encrypted" jq -e '.files[] | select(.name == "pki.tar.enc" and .encrypted == true)' "$d/MANIFEST.json"
  check "MANIFEST records kdf and cipher but no passphrase" bash -c '! grep -q "$2" "$1" && jq -e ".encryption.kdf == \"pbkdf2\" and .encryption.iterations == 600000" "$1"' _ "$d/MANIFEST.json" "$BK_PASS"
  check "archive is not a plain tar" bash -c '! tar -tf "$1"' _ "$d/pki.tar.enc"
  check "archive does not leak the CA key in clear text" bash -c '! grep -q "BEGIN" "$1"' _ "$d/pki.tar.enc"
  check "retention pruned the two oldest backup dirs" test ! -e "$bkdir/20200101T000000Z" -a ! -e "$bkdir/20200102T000000Z"
  check "newer backup kept" test -d "$bkdir/20200103T000000Z"
  check "foreign directory untouched" test -d "$bkdir/notes"

  t_run "--decrypt restores the pki tree" 0 "$S/backup-opensearch.sh" --decrypt "$d/pki.tar.enc" --extract-to "$WORK/bkf-x" --passphrase-file "$pp"
  check "CA certificate round-trips" cmp -s "$TREE/pki/ca.crt" "$WORK/bkf-x/pki/ca.crt"
  check "CA key round-trips" cmp -s "$TREE/pki/ca.key" "$WORK/bkf-x/pki/ca.key"
  mode_is "extract dir mode" 700 "$WORK/bkf-x"
  t_run "--extract-to must be empty" 2 "$S/backup-opensearch.sh" --decrypt "$d/pki.tar.enc" --extract-to "$WORK/bkf-x" --passphrase-file "$pp"
  printf '%s' "another-passphrase-that-is-wrong-1" >"$WORK/bkf.wrong"
  chmod 0600 "$WORK/bkf.wrong"
  t_run "wrong passphrase → failure (1)" 1 "$S/backup-opensearch.sh" --decrypt "$d/pki.tar.enc" --extract-to "$WORK/bkf-y" --passphrase-file "$WORK/bkf.wrong"
  out_has "decryption failure explained" 'decryption failed'
  check_not "nothing extracted on failure" test -e "$WORK/bkf-y/pki"
  t_run "--decrypt of a missing archive → 2" 2 "$S/backup-opensearch.sh" --decrypt "$WORK/missing.enc" --extract-to "$WORK/bkf-z" --passphrase-file "$pp"

  # --include-secrets: encrypted, and the backups directory is not archived into itself
  mkdir -p "$TREE/secrets/backups"
  printf 'x' >"$TREE/secrets/backups/must-not-be-archived"
  t_run "--include-secrets adds an encrypted secrets archive" 0 "$S/backup-opensearch.sh" --files-only --backup-dir "$bkdir" --passphrase-file "$pp" --include-secrets --keep 5
  d="$(find "$bkdir" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*T[0-9]*Z' | sort | tail -n 1)"
  check "secrets archive written" test -f "$d/secrets.tar.enc"
  t_run "secrets archive decrypts" 0 "$S/backup-opensearch.sh" --decrypt "$d/secrets.tar.enc" --extract-to "$WORK/bkf-s" --passphrase-file "$pp"
  check "admin password archived" cmp -s "$TREE/secrets/opensearch_admin_password" "$WORK/bkf-s/secrets/opensearch_admin_password"
  check_not "backups dir excluded from the secrets archive" test -e "$WORK/bkf-s/secrets/backups"
  rm -rf -- "$TREE/secrets/backups"

  # an archive with a traversal member is refused before extraction
  mkdir -p "$WORK/bkf-t"
  printf 'evil' >"$WORK/bkf-t/payload"
  # --transform is GNU-only: rename on disk instead of rewriting member names in the archive
  mkdir -p "$WORK/bkf-t/pkg" && mv "$WORK/bkf-t/payload" "$WORK/bkf-t/pkg/payload"
  cp -R "$WORK/bkf-t/pkg" "$WORK/escaped" && tar -C "$WORK/bkf-t" -cf "$WORK/bkf-t.tar" ../escaped
  rm -rf -- "$WORK/escaped" # the member must not already exist when extraction is refused
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$pp" -in "$WORK/bkf-t.tar" -out "$WORK/bkf-t.enc"
  t_run "archive with a path-traversal member is refused" 1 "$S/backup-opensearch.sh" --decrypt "$WORK/bkf-t.enc" --extract-to "$WORK/bkf-t-out" --passphrase-file "$pp"
  out_has "unsafe member named" 'unsafe member path'
  check_not "nothing escaped" test -e "$WORK/escaped"
}
