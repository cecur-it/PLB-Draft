#!/usr/bin/env node
/**
 * Guards the opt-in mTLS wiring of the forwarder installers: the templates must keep the
 * commented client-cert lines the installers un-comment, and the installers must expose the flags.
 *
 *   node --test scripts/forwarder-mtls.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const agents = join(dirname(fileURLToPath(import.meta.url)), '..', 'deployment', 'agents');
const read = (p) => readFileSync(join(agents, p), 'utf8');

// Same pattern the installers apply (sed -E / PowerShell -replace).
const enable = (conf) => conf.replace(/^(\s*)# (tls\.(crt|key)_file)/gm, '$1$2');

for (const tpl of ['templates/fluent-bit-linux.conf', 'templates/fluent-bit-windows.conf']) {
  test(`${tpl}: client cert lines are commented and enable cleanly`, () => {
    const conf = read(tpl);
    assert.doesNotMatch(conf, /^\s*tls\.(crt|key)_file/m);
    const on = enable(conf);
    assert.match(on, /^\s*tls\.crt_file\s+\S+/m);
    assert.match(on, /^\s*tls\.key_file\s+\S+/m);
    assert.match(on, /^\s*tls\.verify\s+On/m);
  });
}

test('installers expose client cert flags', () => {
  const sh = read('install-forwarder.sh');
  assert.match(sh, /--client-cert\)/);
  assert.match(sh, /--client-key\)/);
  const ps = read('Install-CecurForwarder.ps1');
  assert.match(ps, /\[string\]\$ClientCert/);
  assert.match(ps, /\[string\]\$ClientKey/);
});

test('Windows ZIP installation requires a SHA-256 and preserves state on uninstall', () => {
  const ps = read('Install-CecurForwarder.ps1');
  assert.match(ps, /\$FluentBitSha256 -notmatch '\^\[0-9a-fA-F\]\{64\}\$'/);
  assert.doesNotMatch(ps, /package integrity is NOT verified/);
  assert.match(ps, /function Backup-ForwarderState/);
  assert.match(ps, /Get-FileHash -LiteralPath \$copy -Algorithm SHA256/);
  const uninstall = ps.slice(ps.indexOf('if ($Uninstall)'), ps.indexOf('# ------------------------------------------------------------------------------------------ validate'));
  assert.ok(uninstall.indexOf('Backup-ForwarderState $BackupDir') < uninstall.indexOf('Remove-Item -LiteralPath $path'));
});
