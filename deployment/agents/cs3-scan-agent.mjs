#!/usr/bin/env node
/**
 * cs3-scan-agent — on-host scan worker for the Cecur CS3 console (Linux).
 *
 * Polls the console for scan jobs queued by an operator (FIM, SCA, vulnerability), runs them against THIS host
 * and reports what it measured. The console never fabricates scan output: if a scan cannot run here (unsupported
 * platform, missing package tooling) the job is reported as failed with the reason.
 *
 *   cs3-scan-agent [--once] [--interval 30]
 *
 * Node >= 18, core modules only.
 *
 * Environment (the same file the forwarder uses: /etc/cecur/forwarder.env):
 *   CS3_HOST, CS3_PORT        console endpoint (HTTPS unless CS3_SCHEME=http is set for a lab)
 *   CS3_INGEST_KEY            per-agent key issued at enrollment (never passed on argv)
 *   CS3_CA_FILE               optional internal CA bundle
 *   CS3_FIM_PATHS             comma separated files/dirs to baseline (default: security-relevant /etc files)
 *   CS3_FIM_BASELINE          baseline file (default /var/lib/cecur-scan/fim-baseline.json)
 *   CS3_SCAN_INTERVAL         poll interval in seconds (default 30)
 *
 * FIM: the first run records a SHA-256 baseline and reports 0 deviations; later runs report ADDED, MODIFIED,
 * DELETED and PERMISSIONS_CHANGED against that baseline.
 * Vulnerabilities: official Canonical USN OVAL via OpenSCAP (Ubuntu), debsecan (Debian; fixed-in-archive CVEs
 * only), or `dnf updateinfo` advisories (RHEL family). Nothing else is guessed.
 */
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import crypto from 'node:crypto';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const DEFAULT_FIM_PATHS = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/group',
  '/etc/sudoers',
  '/etc/ssh/sshd_config',
  '/etc/hosts',
  '/etc/crontab',
  '/etc/fstab',
];
const MAX_DIR_FILES = 2000;

export function sha256File(file) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(1 << 16);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return h.digest('hex');
}

function expand(target, out) {
  let st;
  try {
    st = fs.lstatSync(target);
  } catch {
    return;
  }
  if (st.isDirectory()) {
    for (const e of fs.readdirSync(target)) {
      if (out.length >= MAX_DIR_FILES) return;
      expand(path.join(target, e), out);
    }
  } else if (st.isFile()) {
    out.push(target);
  }
}

/** Snapshot of { path: {hash, perms} } for every regular file under the monitored paths. */
export function snapshot(paths) {
  const files = [];
  for (const p of paths) expand(p, files);
  const snap = {};
  for (const f of files) {
    try {
      snap[f] = { hash: sha256File(f), perms: (fs.statSync(f).mode & 0o7777).toString(8).padStart(4, '0') };
    } catch {
      // unreadable file: not part of the snapshot
    }
  }
  return snap;
}

export function fileTypeFor(p) {
  if (/\/(shadow|gshadow|sudoers)/.test(p) || /\/\.ssh\//.test(p)) return 'credential';
  if (/\/(bin|sbin)\//.test(p)) return 'binary';
  if (/\/(www|html)\//.test(p)) return 'web_root';
  if (p.startsWith('/etc/')) return 'config';
  return 'system';
}

export function diffSnapshots(base, cur) {
  const events = [];
  for (const [p, now] of Object.entries(cur)) {
    const was = base[p];
    if (!was) events.push({ path: p, eventType: 'ADDED', fileType: fileTypeFor(p), newHash: now.hash, newPerms: now.perms });
    else if (was.hash !== now.hash)
      events.push({ path: p, eventType: 'MODIFIED', fileType: fileTypeFor(p), oldHash: was.hash, newHash: now.hash, oldPerms: was.perms, newPerms: now.perms });
    else if (was.perms !== now.perms)
      events.push({ path: p, eventType: 'PERMISSIONS_CHANGED', fileType: fileTypeFor(p), oldHash: was.hash, newHash: now.hash, oldPerms: was.perms, newPerms: now.perms });
  }
  for (const [p, was] of Object.entries(base)) {
    if (!cur[p]) events.push({ path: p, eventType: 'DELETED', fileType: fileTypeFor(p), oldHash: was.hash, oldPerms: was.perms });
  }
  return events;
}

function runFim(cfg) {
  const cur = snapshot(cfg.fimPaths);
  let baseline = null;
  try {
    baseline = JSON.parse(fs.readFileSync(cfg.fimBaseline, 'utf8'));
  } catch {
    // first run
  }
  const monitoredFiles = Object.keys(cur).length;
  if (!baseline) {
    fs.mkdirSync(path.dirname(cfg.fimBaseline), { recursive: true, mode: 0o700 });
    fs.writeFileSync(cfg.fimBaseline, JSON.stringify(cur), { mode: 0o600 });
    return { monitoredFiles, events: [] };
  }
  const events = diffSnapshots(baseline, cur);
  // Accept the new state as the baseline only after the deviations are reported with this result.
  cfg.pendingBaseline = cur;
  return { monitoredFiles, events };
}

function readOsRelease() {
  try {
    const kv = Object.fromEntries(
      fs.readFileSync('/etc/os-release', 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => {
        const i = l.indexOf('=');
        return [l.slice(0, i), l.slice(i + 1).replace(/^"|"$/g, '')];
      })
    );
    return kv;
  } catch {
    return {};
  }
}

function sh(cmd, args) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    timeout: 120000,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function commandFailure(error) {
  return String(error?.stderr || error?.message || error).replace(/\s+/g, ' ').trim().slice(0, 300);
}

function sysctl(key) {
  try {
    return fs.readFileSync(`/proc/sys/${key.replace(/\./g, '/')}`, 'utf8').trim();
  } catch {
    return null;
  }
}

function sshdSetting(name) {
  try {
    const m = fs.readFileSync('/etc/ssh/sshd_config', 'utf8').split('\n').filter((l) => new RegExp(`^\\s*${name}\\s+`, 'i').test(l));
    return m.length ? m[m.length - 1].trim().split(/\s+/)[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

function mode(file) {
  try {
    return fs.statSync(file).mode & 0o777;
  } catch {
    return null;
  }
}

/** CIS Linux checks that can be evaluated from local files only. Unreadable state yields MANUAL, never PASS. */
export function evaluateSca() {
  const checks = [];
  const add = (checkId, section, title, ok, rationale, remediation, compliance = ['CIS_Linux_2.0']) =>
    checks.push({ checkId, section, title, status: ok === null ? 'MANUAL' : ok ? 'PASS' : 'FAIL', rationale, remediation, compliance });

  const rootLogin = sshdSetting('PermitRootLogin');
  add('5.2.10', 'SSH', 'SSH root login is disabled', rootLogin === null ? null : rootLogin === 'no', 'Direct root login bypasses individual accountability.', 'Set "PermitRootLogin no" in /etc/ssh/sshd_config and reload sshd.');
  const passAuth = sshdSetting('PasswordAuthentication');
  add('5.2.12', 'SSH', 'SSH password authentication is disabled', passAuth === null ? null : passAuth === 'no', 'Key-based authentication resists brute force.', 'Set "PasswordAuthentication no" in /etc/ssh/sshd_config.');
  const shadow = mode('/etc/shadow');
  add('6.1.3', 'File permissions', '/etc/shadow is not readable by group/other', shadow === null ? null : (shadow & 0o027) === 0, 'Password hashes must be protected.', 'chmod 0640 /etc/shadow (root:shadow).');
  const passwd = mode('/etc/passwd');
  add('6.1.1', 'File permissions', '/etc/passwd is not writable by group/other', passwd === null ? null : (passwd & 0o022) === 0, 'Account database integrity.', 'chmod 0644 /etc/passwd.');
  const aslr = sysctl('kernel.randomize_va_space');
  add('1.5.3', 'Kernel', 'ASLR is fully enabled', aslr === null ? null : aslr === '2', 'Address space randomization hinders exploitation.', 'sysctl -w kernel.randomize_va_space=2 and persist in /etc/sysctl.d.');
  const fwd = sysctl('net.ipv4.ip_forward');
  add('3.2.1', 'Network', 'IP forwarding is disabled', fwd === null ? null : fwd === '0', 'Hosts that are not routers should not forward packets.', 'sysctl -w net.ipv4.ip_forward=0 and persist.');
  const redirects = sysctl('net.ipv4.conf.all.accept_redirects');
  add('3.3.2', 'Network', 'ICMP redirects are not accepted', redirects === null ? null : redirects === '0', 'Redirects can alter routing.', 'sysctl -w net.ipv4.conf.all.accept_redirects=0 and persist.');
  const synCookies = sysctl('net.ipv4.tcp_syncookies');
  add('3.3.8', 'Network', 'TCP SYN cookies are enabled', synCookies === null ? null : synCookies === '1', 'Mitigates SYN floods.', 'sysctl -w net.ipv4.tcp_syncookies=1 and persist.');
  return checks;
}

export function parseDebsecan(out) {
  // debsecan summary lines: "CVE-2021-3177 python3.9 (remotely exploitable, medium urgency)"
  const urgency = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW', unimportant: 'LOW' };
  const findings = [];
  for (const line of out.split('\n')) {
    const m = line.trim().match(/^(CVE-\d{4}-\d+)\s+(\S+)\s*(?:\((.*)\))?$/);
    if (!m) continue;
    const u = (m[3] || '').match(/(high|medium|low|unimportant) urgency/);
    findings.push({ cve: m[1], package: m[2], severity: u ? urgency[u[1]] : 'MEDIUM', remediationGuide: `Upgrade ${m[2]} to the fixed version from the distribution security repository.` });
  }
  return findings;
}

export function parseDnfUpdateinfo(out) {
  // `dnf -q updateinfo list --security` lines: "RHSA-2024:1234 Important/Sec. pkg-1.2-3.el9.x86_64"
  const findings = [];
  const sev = { critical: 'CRITICAL', important: 'HIGH', moderate: 'MEDIUM', low: 'LOW' };
  for (const line of out.split('\n')) {
    const m = line.trim().match(/^(RH[SBEA]A-\d{4}:\d+|ALSA-\d{4}:\d+|ELSA-\d{4}-\d+)\s+(\w+)\/Sec\.\s+(\S+)/);
    if (!m) continue;
    findings.push({ cve: m[1], severity: sev[m[2].toLowerCase()] || 'MEDIUM', package: m[3] });
  }
  return findings;
}

function decodeXml(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_, decimal) => String.fromCodePoint(Number(decimal)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function xmlAttr(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*(["'])(.*?)\\1`));
  return match ? decodeXml(match[2]) : '';
}

function xmlText(block, tag) {
  const match = block.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`));
  return match ? decodeXml(match[1]).trim() : '';
}

function ubuntuSeverity(value) {
  return ({ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', negligible: 'LOW' })[String(value).toLowerCase()] || 'MEDIUM';
}

/** Parse only Canonical USN OVAL and OpenSCAP's corresponding definition results; unknown true definitions fail closed. */
export function parseUbuntuOval(sourceXml, resultXml, codename, sourceVersions = {}) {
  if (!/^[a-z][a-z0-9-]*$/.test(codename) || !sourceXml.includes('<oval_definitions') ||
      !sourceXml.includes(`oval:com.ubuntu.${codename}:def:`) || !resultXml.includes('<oval_results')) {
    throw new Error('OVAL document validation failed.');
  }

  const patches = new Map();
  for (const block of sourceXml.match(/<definition\b[\s\S]*?<\/definition>/g) || []) {
    const opening = block.match(/^<definition\b[^>]*>/)?.[0] || '';
    if (xmlAttr(opening, 'class') !== 'patch') continue;
    const id = xmlAttr(opening, 'id');
    if (!id) continue;

    const references = (block.match(/<reference\b[^>]*>/g) || []).map((tag) => ({
      source: xmlAttr(tag, 'source'), id: xmlAttr(tag, 'ref_id'), url: xmlAttr(tag, 'ref_url'),
    }));
    const advisory = references.find((ref) => ref.source === 'USN' || ref.source === 'LSN') ||
      { id: '', url: 'https://ubuntu.com/security/notices' };
    const cves = new Map();
    for (const ref of references.filter((item) => item.source === 'CVE' && /^CVE-\d{4}-\d+$/.test(item.id))) {
      cves.set(ref.id, {});
    }
    for (const tag of block.match(/<cve\b[^>]*>CVE-\d{4}-\d+<\/cve>/g) || []) {
      const idMatch = tag.match(/>(CVE-\d{4}-\d+)</);
      if (!idMatch) continue;
      cves.set(idMatch[1], {
        severity: xmlAttr(tag, 'cvss_severity'),
        cvss: Number(xmlAttr(tag, 'cvss_score')) || 0,
      });
    }

    const packages = [];
    const packageKeys = new Set();
    for (const tag of block.match(/<criterion\b[^>]*>/g) || []) {
      const comment = xmlAttr(tag, 'comment');
      const fixed = comment.match(/^(.+?) source package\b.*?fixed \(note: '([^']+)'\)/) ||
        comment.match(/^'([^']+)' kernel\b.*?fixed \(note: '([^']+)'\)/);
      const livepatch = comment === 'livepatch';
      if (!fixed && !livepatch) continue;
      const name = livepatch ? 'canonical-livepatch' : fixed[1];
      const fixedVersion = livepatch ? '' : fixed[2];
      const key = `${name}\0${fixedVersion}`;
      if (!packageKeys.has(key)) {
        packageKeys.add(key);
        packages.push({ name, fixedVersion, livepatch });
      }
    }
    patches.set(id, {
      title: xmlText(block, 'title'),
      advisory,
      cves,
      packages,
      severity: ubuntuSeverity(xmlText(block, 'severity')),
    });
  }

  const resultTags = (resultXml.match(/<definition\b[^>]*>/g) || [])
    .filter((tag) => xmlAttr(tag, 'definition_id') && xmlAttr(tag, 'result'));
  if (resultTags.length === 0) throw new Error('OpenSCAP returned no evaluated definitions.');
  const findings = [];
  const findingKeys = new Set();
  let evaluatedPatchDefinitions = 0;
  let truePatchDefinitions = 0;
  for (const tag of resultTags) {
    const id = xmlAttr(tag, 'definition_id');
    const patch = patches.get(id);
    if (!patch) continue;
    evaluatedPatchDefinitions += 1;
    if (xmlAttr(tag, 'result') !== 'true') continue;
    truePatchDefinitions += 1;
    if (patch.packages.length === 0) throw new Error(`No supported package criteria in true OVAL definition ${id}.`);
    const identifiers = patch.cves.size > 0 ? [...patch.cves.keys()] : [patch.advisory.id];
    if (!identifiers[0]) throw new Error(`No CVE or advisory identifier in true OVAL definition ${id}.`);
    for (const identifier of identifiers) {
      const cve = patch.cves.get(identifier) || {};
      for (const pkg of patch.packages) {
        const key = `${identifier}\0${pkg.name}\0${pkg.fixedVersion}`;
        if (findingKeys.has(key)) continue;
        findingKeys.add(key);
        findings.push({
          cve: identifier,
          package: pkg.name,
          title: patch.title,
          installedVersion: pkg.livepatch ? '' : (sourceVersions[pkg.name] || ''),
          fixedVersion: pkg.fixedVersion,
          severity: ubuntuSeverity(cve.severity || patch.severity),
          cvss: cve.cvss || 0,
          remediationGuide: pkg.livepatch
            ? `Apply ${patch.advisory.id} with Canonical Livepatch: ${patch.advisory.url}`
            : `Update ${pkg.name} to ${pkg.fixedVersion} (${patch.advisory.id}): ${patch.advisory.url}`,
        });
      }
    }
  }
  if (evaluatedPatchDefinitions === 0) throw new Error('OpenSCAP returned no evaluated Ubuntu patch definitions.');
  return { evaluatedDefinitions: resultTags.length, evaluatedPatchDefinitions, truePatchDefinitions, findings };
}

export function parseDpkgSourceVersions(out) {
  const sourceVersions = Object.create(null);
  const lines = out.split('\n').filter(Boolean);
  for (const line of lines) {
    const [binary, version, sourcePackage, sourceVersion] = line.split('\t');
    if (!binary || !version) continue;
    const name = sourcePackage || binary;
    const installed = sourceVersion || version;
    if (!(name in sourceVersions)) sourceVersions[name] = installed;
    else if (sourceVersions[name] !== installed) sourceVersions[name] = '';
  }
  return { installedPackages: lines.length, sourceVersions };
}

function readOvalFile(file, label) {
  const size = fs.statSync(file).size;
  if (size === 0 || size > 512 * 1024 * 1024) throw new Error(`${label} has an invalid size (${size} bytes).`);
  return fs.readFileSync(file, 'utf8');
}

function runUbuntuOval(rel, jobId) {
  const codename = rel.VERSION_CODENAME || rel.UBUNTU_CODENAME || '';
  if (!/^[a-z][a-z0-9-]*$/.test(codename)) throw new Error('Ubuntu release codename is missing or invalid.');
  const stateDir = '/var/lib/cecur-scan';
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const safeJobId = String(jobId || 'job').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 80) || 'job';
  const workDir = fs.mkdtempSync(path.join(stateDir, `${safeJobId}-`));
  const compressed = path.join(workDir, 'usn.oval.xml.bz2');
  const source = path.join(workDir, 'usn.oval.xml');
  const results = path.join(workDir, 'results.xml');
  const url = `https://security-metadata.canonical.com/oval/com.ubuntu.${codename}.usn.oval.xml.bz2`;
  let stage = 'package inventory';
  try {
    const inventory = parseDpkgSourceVersions(sh('dpkg-query', [
      '-W', '-f', '${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n',
    ]));
    stage = 'download';
    sh('curl', ['--disable', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
      '--tlsv1.2', '--max-time', '110', '--max-filesize', '104857600', '--output', compressed, url]);
    stage = 'decompression';
    sh('bunzip2', ['--force', compressed]);
    stage = 'OpenSCAP evaluation';
    execFileSync('oscap', ['oval', 'eval', '--results', results, source], {
      encoding: 'utf8', timeout: 300000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'ignore', 'pipe'],
    });
    stage = 'result parsing';
    const parsed = parseUbuntuOval(readOvalFile(source, 'OVAL source'), readOvalFile(results, 'OVAL results'), codename, inventory.sourceVersions);
    return { installedPackages: inventory.installedPackages, findings: parsed.findings };
  } catch (error) {
    throw new Error(`Ubuntu OVAL ${stage} failed: ${commandFailure(error)}`);
  } finally {
    try {
      fs.rmSync(workDir, { recursive: true, force: true });
    } catch (error) {
      console.error(`[cs3-scan-agent] OVAL cleanup failed: ${commandFailure(error)}`);
    }
  }
}

function runVuln(jobId) {
  const rel = readOsRelease();
  const family = `${rel.ID || ''} ${rel.ID_LIKE || ''}`.toLowerCase();
  let findings;
  let installedPackages;
  if (/(?:^|\s)ubuntu(?:\s|$)/.test(family)) {
    return runUbuntuOval(rel, jobId);
  }
  if (/debian/.test(family)) {
    try {
      installedPackages = sh('dpkg-query', ['-f', '.\n', '-W']).split('\n').filter(Boolean).length;
    } catch {
      installedPackages = undefined;
    }
    let out;
    try {
      out = sh('debsecan', ['--suite', rel.VERSION_CODENAME || 'stable', '--only-fixed']);
    } catch (error) {
      throw new Error(`debsecan failed: ${commandFailure(error)}`);
    }
    findings = parseDebsecan(out);
  } else if (/rhel|fedora|centos|rocky|alma/.test(family)) {
    const bin = fs.existsSync('/usr/bin/dnf') ? 'dnf' : 'yum';
    try {
      installedPackages = sh('rpm', ['-qa']).split('\n').filter(Boolean).length;
      findings = parseDnfUpdateinfo(sh(bin, ['-q', 'updateinfo', 'list', '--security']));
    } catch {
      throw new Error(`${bin} updateinfo failed; the advisory plugin or repository metadata is unavailable.`);
    }
  } else {
    throw new Error(`Vulnerability scanning is not supported on ${rel.PRETTY_NAME || os.platform()}.`);
  }
  return { installedPackages, findings };
}

function loadConfig(env = process.env) {
  const host = env.CS3_HOST;
  if (!host) throw new Error('CS3_HOST is required');
  if (!env.CS3_INGEST_KEY) throw new Error('CS3_INGEST_KEY is required');
  return {
    host,
    port: Number(env.CS3_PORT) || (env.CS3_SCHEME === 'http' ? 80 : 443),
    scheme: env.CS3_SCHEME === 'http' ? 'http' : 'https',
    key: env.CS3_INGEST_KEY,
    ca: env.CS3_CA_FILE ? fs.readFileSync(env.CS3_CA_FILE) : undefined,
    fimPaths: (env.CS3_FIM_PATHS ? env.CS3_FIM_PATHS.split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_FIM_PATHS),
    fimBaseline: env.CS3_FIM_BASELINE || '/var/lib/cecur-scan/fim-baseline.json',
    interval: Number(env.CS3_SCAN_INTERVAL) || 30,
  };
}

function request(cfg, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const mod = cfg.scheme === 'http' ? http : https;
    const payload = body ? JSON.stringify(body) : undefined;
    const req = mod.request(
      {
        host: cfg.host,
        port: cfg.port,
        method,
        path: urlPath,
        ca: cfg.ca,
        timeout: 30000,
        headers: { 'x-api-key': cfg.key, ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}) },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(data ? JSON.parse(data) : {});
            } catch (e) {
              reject(e);
            }
          } else reject(new Error(`${method} ${urlPath} -> HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function execute(cfg, task) {
  if (os.platform() !== 'linux') throw new Error(`Scans are not supported on ${os.platform()} by this agent.`);
  if (task.kind === 'fim') return runFim(cfg);
  if (task.kind === 'sca') return { benchmark: 'CIS_Linux_2.0', checks: evaluateSca() };
  if (task.kind === 'vuln') return runVuln(task.jobId);
  throw new Error(`Unknown scan kind: ${task.kind}`);
}

export async function pollOnce(cfg, log = console.log) {
  const { tasks = [] } = await request(cfg, 'GET', '/api/fleet/agent/tasks');
  for (const task of tasks) {
    let report;
    try {
      report = { jobId: task.jobId, status: 'completed', ...execute(cfg, task) };
    } catch (err) {
      report = { jobId: task.jobId, status: 'failed', error: String(err.message || err).slice(0, 500) };
    }
    await request(cfg, 'POST', '/api/fleet/agent/results', report);
    if (report.status === 'completed' && task.kind === 'fim' && cfg.pendingBaseline) {
      fs.writeFileSync(cfg.fimBaseline, JSON.stringify(cfg.pendingBaseline), { mode: 0o600 });
      cfg.pendingBaseline = undefined;
    }
    log(`[cs3-scan-agent] ${task.kind} job ${task.jobId}: ${report.status}${report.error ? ` (${report.error})` : ''}`);
  }
  return tasks.length;
}

async function main() {
  const args = process.argv.slice(2);
  const once = args.includes('--once');
  const iv = args.indexOf('--interval');
  const cfg = loadConfig();
  if (iv >= 0) cfg.interval = Number(args[iv + 1]) || cfg.interval;
  let stop = false;
  for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => (stop = true));
  do {
    try {
      await pollOnce(cfg);
    } catch (err) {
      console.error(`[cs3-scan-agent] poll failed: ${err.message}`);
      if (once) process.exitCode = 1;
    }
    if (once) break;
    for (let i = 0; i < cfg.interval * 4 && !stop; i++) await new Promise((r) => setTimeout(r, 250));
  } while (!stop);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch((err) => {
    console.error(`[cs3-scan-agent] fatal: ${err.message}`);
    process.exit(1);
  });
}
