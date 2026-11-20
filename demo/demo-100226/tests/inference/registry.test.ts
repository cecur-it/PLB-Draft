import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ModelRegistry, RegistryError, verifyArtifact, loadManifest } from '../../server/inference/registry';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();

const manifest = (o: Record<string, string> = {}) => `name: m1
roles: [triage, forensic]
license: "${o.license ?? 'Apache-2.0'}"
digest: "${o.digest ?? 'sha256:' + 'a'.repeat(64)}"
quantization: Q4_K_M
context: 8192
eval: { baseline: b0, passThreshold: 0.9 }
`;

function make(root: string, id: string, text: string, opts: { sign?: boolean; tamper?: boolean } = {}) {
  const dir = join(root, id);
  mkdirSync(dir);
  writeFileSync(join(dir, 'manifest.yaml'), text);
  if (opts.sign !== false) {
    writeFileSync(join(dir, 'manifest.yaml.sig'), sign(null, Buffer.from(text), privateKey).toString('base64'));
  }
  if (opts.tamper) writeFileSync(join(dir, 'manifest.yaml'), text.replace('m1', 'evil'));
  return dir;
}

test('unsigned, tampered and wrong-key manifests fail closed', () => {
  const root = mkdtempSync(join(tmpdir(), 'reg-'));
  make(root, 'unsigned', manifest(), { sign: false });
  make(root, 'tampered', manifest(), { tamper: true });
  make(root, 'good', manifest());
  const reg = new ModelRegistry(root, [pem]).load();
  assert.deepEqual(reg.list().map((e) => e.state), ['staging']);
  assert.equal(reg.rejected.length, 2);
  assert.throws(() => loadManifest(join(root, 'good'), [other]), RegistryError);
  assert.throws(() => loadManifest(join(root, 'good'), []), /no trusted/);
});

test('promotion requires allowed license and passing eval', () => {
  const root = mkdtempSync(join(tmpdir(), 'reg-'));
  make(root, 'lic', manifest({ license: '<unverified>' }));
  make(root, 'ok', manifest());
  const reg = new ModelRegistry(root, [pem]).load();
  assert.throws(() => reg.promote('lic', 1), /allowlist/);
  assert.throws(() => reg.promote('ok', 0.5), /below threshold/);
  assert.equal(reg.resolve('triage'), undefined);
  reg.promote('ok', 0.95);
  assert.equal(reg.resolve('forensic')?.manifest.name, 'm1');
});

test('artifact digest mismatch is rejected', async () => {
  const root = mkdtempSync(join(tmpdir(), 'reg-'));
  const f = join(root, 'w.gguf');
  writeFileSync(f, 'weights');
  const digest = 'sha256:' + createHash('sha256').update('weights').digest('hex');
  const dir = make(root, 'a', manifest({ digest }));
  const m = loadManifest(dir, [pem]);
  await verifyArtifact(m, f);
  writeFileSync(f, 'tampered');
  await assert.rejects(verifyArtifact(m, f), /digest mismatch/);
});
