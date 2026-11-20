import { createHash, createPublicKey, verify } from 'node:crypto';
import { createReadStream, existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import type { DeploymentProfile, ModelRole } from './types';

/** Signed model registry: fail-closed manifest loading, digest pinning, license + eval-gated promotion. */
export class RegistryError extends Error {}

export type PromotionState = 'staging' | 'approved';

const ROLES: readonly ModelRole[] = ['triage', 'forensic', 'security'];

export interface ModelManifest {
  name: string;
  roles: ModelRole[];
  license: string;
  digest: string; // sha256:<hex>
  quantization: string;
  context: number;
  profiles: Partial<Record<DeploymentProfile, { backend: string; replicas?: number; gpu?: string; bundle?: string }>>;
  eval: { baseline: string; passThreshold: number };
}

export interface EvalRecord {
  score: number;
  injectionResistance: number;
  scriptSafety: number;
}

export interface RegistryEntry {
  manifest: ModelManifest;
  state: PromotionState;
  dir: string;
}

const DEFAULT_LICENSE_ALLOWLIST = ['Apache-2.0', 'MIT', 'BSD-3-Clause'];
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

export function licenseAllowlist(): string[] {
  const env = process.env.MODEL_LICENSE_ALLOWLIST;
  return env ? env.split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_LICENSE_ALLOWLIST;
}

/** Trusted Ed25519 public keys (PEM) from MODEL_REGISTRY_PUBKEYS (PEM blocks) when not injected. */
function envTrustedKeys(): string[] {
  const raw = process.env.MODEL_REGISTRY_PUBKEYS || '';
  return raw.split(/(?=-----BEGIN PUBLIC KEY-----)/).map((s) => s.trim()).filter(Boolean);
}

function verifySignature(data: Buffer, sigB64: string, keys: string[]): boolean {
  const sig = Buffer.from(sigB64.trim(), 'base64');
  return keys.some((pem) => {
    try {
      return verify(null, data, createPublicKey(pem), sig);
    } catch {
      return false;
    }
  });
}

function validate(m: any, dir: string): ModelManifest {
  const bad = (why: string) => new RegistryError(`invalid manifest in ${dir}: ${why}`);
  if (!m || typeof m !== 'object') throw bad('not a mapping');
  if (typeof m.name !== 'string' || !m.name) throw bad('name');
  if (!Array.isArray(m.roles) || !m.roles.length || m.roles.some((r: unknown) => !ROLES.includes(r as ModelRole))) throw bad('roles');
  if (typeof m.license !== 'string') throw bad('license');
  if (typeof m.digest !== 'string' || !DIGEST_RE.test(m.digest)) throw bad('digest must be sha256:<64 hex>');
  if (typeof m.eval?.passThreshold !== 'number') throw bad('eval.passThreshold');
  return m as ModelManifest;
}

export function loadManifest(dir: string, trustedKeys: string[] = envTrustedKeys()): ModelManifest {
  const mPath = join(dir, 'manifest.yaml');
  const sPath = join(dir, 'manifest.yaml.sig');
  if (!existsSync(mPath)) throw new RegistryError(`missing manifest in ${dir}`);
  if (!existsSync(sPath)) throw new RegistryError(`unsigned manifest in ${dir}`);
  if (!trustedKeys.length) throw new RegistryError('no trusted registry keys configured');
  const data = readFileSync(mPath);
  if (!verifySignature(data, readFileSync(sPath, 'utf8'), trustedKeys)) {
    throw new RegistryError(`manifest signature verification failed for ${dir}`);
  }
  return validate(parse(data.toString('utf8')), dir);
}

/** Streams a model artifact and compares its SHA-256 with the pinned manifest digest. */
export async function verifyArtifact(manifest: ModelManifest, file: string): Promise<void> {
  const h = createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    createReadStream(file).on('data', (c) => h.update(c)).on('error', reject).on('end', () => resolve());
  });
  if (`sha256:${h.digest('hex')}` !== manifest.digest) {
    throw new RegistryError(`artifact digest mismatch for ${manifest.name}`);
  }
}

export class ModelRegistry {
  private entries = new Map<string, RegistryEntry>();
  readonly rejected: Array<{ dir: string; reason: string }> = [];

  constructor(private readonly root: string, private readonly trustedKeys: string[] = envTrustedKeys()) {}

  /** Loads every model dir; unsigned/tampered ones are rejected (never registered). */
  load(): this {
    this.entries.clear();
    this.rejected.length = 0;
    if (!existsSync(this.root)) return this;
    for (const d of readdirSync(this.root)) {
      const dir = join(this.root, d);
      if (!statSync(dir).isDirectory()) continue;
      try {
        this.entries.set(d, { manifest: loadManifest(dir, this.trustedKeys), state: 'staging', dir });
      } catch (e: any) {
        this.rejected.push({ dir, reason: e.message });
      }
    }
    return this;
  }

  get(id: string): RegistryEntry | undefined {
    return this.entries.get(id);
  }

  list(): RegistryEntry[] {
    return [...this.entries.values()];
  }

  /** staging -> approved. Requires an allowed license, a real digest and an eval score >= passThreshold. */
  promote(id: string, evalScore: number): RegistryEntry {
    const e = this.entries.get(id);
    if (!e) throw new RegistryError(`unknown model ${id}`);
    const { license, eval: ev } = e.manifest;
    if (!licenseAllowlist().includes(license)) throw new RegistryError(`license "${license}" is not on the allowlist`);
    if (!(evalScore >= ev.passThreshold)) throw new RegistryError(`eval score ${evalScore} below threshold ${ev.passThreshold}`);
    e.state = 'approved';
    return e;
  }

  /**
   * Eval-gated promotion: score must meet passThreshold and injection resistance / script safety must not
   * regress against the baseline record (when one exists).
   */
  promoteWithEval(id: string, current: EvalRecord, baseline?: EvalRecord): RegistryEntry {
    const e = this.entries.get(id);
    if (!e) throw new RegistryError(`unknown model ${id}`);
    if (baseline && current.injectionResistance < baseline.injectionResistance) {
      throw new RegistryError('injection resistance regressed vs baseline');
    }
    if (baseline && current.scriptSafety < baseline.scriptSafety) throw new RegistryError('script safety regressed vs baseline');
    return this.promote(id, current.score);
  }

  demote(id: string): void {
    const e = this.entries.get(id);
    if (e) e.state = 'staging';
  }

  /** Only approved models are served. */
  resolve(role: ModelRole): RegistryEntry | undefined {
    return this.list().find((e) => e.state === 'approved' && e.manifest.roles.includes(role));
  }
}
