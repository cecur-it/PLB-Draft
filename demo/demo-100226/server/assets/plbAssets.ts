import fs from 'node:fs';
import path from 'node:path';
import type { AssetCriticality, AssetRecord } from '../../src/types';

/**
 * Asset inventory loader. PLB_Assets.csv (repository root, exported from the CMDB) is the source of
 * truth for the endpoints/assets the platform reports on. Nothing is generated: every field below is a
 * column of that file, and anything the file does not say is left undefined.
 */

/** RFC 4180 parser (quoted fields, embedded commas/newlines, "" escapes). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  const src = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && src[i + 1] === '\n') i++;
      row.push(field);
      field = '';
      if (row.some((f) => f.trim() !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((f) => f.trim() !== '')) rows.push(row);
  return rows;
}

const clean = (v: string | undefined) => (v ?? '').replace(/\s+/g, ' ').trim();
const optional = (v: string | undefined) => {
  const t = clean(v);
  return t === '' || /^(na|n\/a)$/i.test(t) ? undefined : t;
};

/** Normalises the "Asset Type"/"Type" columns into a role; the CSV has a blank Asset Type for AP1. */
function classify(assetType: string, type: string): AssetRecord['category'] {
  const t = `${assetType} ${type}`.toLowerCase();
  if (t.includes('firewall')) return 'firewall';
  if (t.includes('wireless') || t.includes('access point')) return 'wireless_ap';
  if (t.includes('switch')) return 'switch';
  return 'other';
}

function parseCriticality(value: string | undefined): AssetCriticality | undefined {
  switch (value?.trim().toUpperCase().replace(/[ -]+/g, '_')) {
    case 'TIER_0_MISSION_CRITICAL': return 'TIER_0_MISSION_CRITICAL';
    case 'TIER_1_HIGH': return 'TIER_1_HIGH';
    case 'TIER_2_MEDIUM': return 'TIER_2_MEDIUM';
    case 'TIER_3_LOW': return 'TIER_3_LOW';
    default: return undefined;
  }
}

export function parseAssets(csv: string): AssetRecord[] {
  const rows = parseCsv(csv);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => clean(h).toLowerCase());
  const col = (name: string, nth = 0) => {
    let seen = -1;
    for (let i = 0; i < header.length; i++) {
      if (header[i] === name && ++seen === nth) return i;
    }
    return -1;
  };
  const idx = {
    no: col('no.'),
    location: col('location'),
    assetType: col('asset type'),
    type: col('type'),
    oem: col('oem'),
    model: col('model'),
    serial: col('serial no'),
    host: col('host name'),
    ip: col('management ip address'),
    monitoring: col('monitoring tool'),
    admins: col('admin account holders'),
    auth: col('authentication'),
    backup: col('config backup'),
    os: col('base os'),
    version: col('software version'),
    required: col('required software ver'),
    eol: col('end of life'),
    eos: col('end of support'),
    owner: col('asset owner'),
    managedBy: col('managed by'),
    redundancy: col('redundancy'),
    cpu: col('thresholds- cpu p3/p2/p1'),
    memory: col('thresholds- memory p3/p2/p1'),
    iface: col('thresholds- interface p3/p2/p1'),
    criticality: col('criticality'),
  };
  const get = (r: string[], i: number) => (i >= 0 ? r[i] : undefined);

  const assets: AssetRecord[] = [];
  rows.slice(1).forEach((r, n) => {
    const hostname = clean(get(r, idx.host));
    if (!hostname) return;
    const assetType = clean(get(r, idx.assetType));
    const type = clean(get(r, idx.type));
    const ip = clean(get(r, idx.ip));
    assets.push({
      id: `asset-${hostname.toLowerCase()}`,
      sourceRow: n + 2,
      cmdbNumber: optional(get(r, idx.no)),
      hostname,
      managementIp: ip || undefined,
      location: clean(get(r, idx.location)),
      category: classify(assetType, type),
      criticality: parseCriticality(get(r, idx.criticality)),
      assetType,
      role: type,
      oem: clean(get(r, idx.oem)),
      model: clean(get(r, idx.model)),
      serialNo: optional(get(r, idx.serial)),
      monitoringTool: optional(get(r, idx.monitoring)),
      adminAccountHolders: clean(get(r, idx.admins)).split(',').map((s) => s.trim()).filter(Boolean),
      authentication: optional(get(r, idx.auth)),
      configBackup: optional(get(r, idx.backup)),
      baseOs: optional(get(r, idx.os)),
      softwareVersion: optional(get(r, idx.version)),
      requiredSoftwareVersion: optional(get(r, idx.required)),
      endOfLife: optional(get(r, idx.eol)),
      endOfSupport: optional(get(r, idx.eos)),
      assetOwner: optional(get(r, idx.owner)),
      managedBy: optional(get(r, idx.managedBy)),
      redundancy: /^yes$/i.test(clean(get(r, idx.redundancy))),
      thresholds: {
        cpu: optional(get(r, idx.cpu)),
        memory: optional(get(r, idx.memory)),
        interface: optional(get(r, idx.iface)),
      },
    });
  });
  return assets;
}

export function resolveAssetsPath(): string | null {
  const candidates = [
    process.env.PLB_ASSETS_CSV,
    path.resolve(process.cwd(), 'PLB_Assets.csv'),
    path.resolve(process.cwd(), '../../PLB_Assets.csv'),
  ].filter((p): p is string => Boolean(p));
  return candidates.find((p) => fs.existsSync(p)) ?? null;
}

export interface AssetLoadResult {
  assets: AssetRecord[];
  source: string | null;
  error?: string;
}

export function loadAssets(): AssetLoadResult {
  const source = resolveAssetsPath();
  if (!source) {
    return {
      assets: [],
      source: null,
      error: 'PLB_Assets.csv not found; set PLB_ASSETS_CSV to the inventory path.',
    };
  }
  try {
    return { assets: parseAssets(fs.readFileSync(source, 'utf8')), source };
  } catch (err) {
    return { assets: [], source, error: `failed to read ${source}: ${(err as Error).message}` };
  }
}
