import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { db } from '../../server/db';
import { parseAssets, loadAssets } from '../../server/assets/plbAssets';
import { linkAssetsToTelemetry } from '../../server/assets/linkage';
import { queueScans, claimJobs, applyAgentReport, ScanResultError, eligibleAgents } from '../../server/scans/jobs';
import { runErrowScan, getErrowStatus, ErrowUnavailableError } from '../../server/connectors/errowClient';
import { assertNoDemoMode } from '../../server/profile';
import { postureScore } from '../../server/posture';
import { buildAssetFusionGraph } from '../../server/fusion';

const CSV = path.resolve(process.cwd(), '../../PLB_Assets.csv');

const agent = (id: string, name = id, ip = '10.0.0.5') =>
  ({
    id,
    name,
    hostname: name,
    ip,
    os: { name: 'Ubuntu', platform: 'linux', version: '22.04', arch: 'x64' },
    workloadType: 'server',
    status: 'active',
    version: '1',
    lastKeepAlive: new Date().toISOString(),
    registeredAt: new Date().toISOString(),
    group: [],
    cpuUsage: 0,
    memoryUsage: 0,
    diskUsage: 0,
    installedPackagesCount: 0,
    vulnerabilitiesCount: { critical: 0, high: 0, medium: 0, low: 0 },
    fimMonitoredFilesCount: 0,
    scaScore: 0,
    isolationStatus: false,
  }) as any;

const reset = () => {
  db.cecurAgents = [];
  db.cecurScanJobs = [];
  db.cecurFIMEvents = [];
  db.cecurAlerts = [];
  db.cecurLogs = [];
  db.cecurVulnerabilities = [];
  db.incidents = [];
  db.errowJobs = [];
  db.targetAllowlist = [];
};
beforeEach(reset);
afterEach(reset);

test('PLB_Assets.csv parses into the real inventory', () => {
  const assets = parseAssets(fs.readFileSync(CSV, 'utf8'));
  assert.equal(assets.length, 18);
  assert.equal(new Set(assets.map((a) => a.id)).size, 18);
  assert.equal(assets.filter((a) => a.category === 'firewall').length, 2);
  assert.ok(assets.every((a) => a.hostname));
  const view = linkAssetsToTelemetry(assets);
  const dup = view.filter((a) => a.duplicateIp);
  assert.ok(dup.length >= 2, 'EFW1/EFW2 share a management IP');
  assert.ok(view.every((a) => a.telemetry.coverage === 'none'), 'no telemetry ingested => no coverage is claimed');
});

test('loadAssets reports a missing file instead of inventing assets', () => {
  const prev = process.env.PLB_ASSETS_CSV;
  process.env.PLB_ASSETS_CSV = '/nonexistent/PLB_Assets.csv';
  const cwd = process.cwd();
  try {
    process.chdir('/tmp');
    const r = loadAssets();
    assert.equal(r.assets.length, 0);
    assert.ok(r.error);
  } finally {
    process.chdir(cwd);
    if (prev === undefined) delete process.env.PLB_ASSETS_CSV;
    else process.env.PLB_ASSETS_CSV = prev;
  }
});

test('linkage uses real agents and ingested events only', () => {
  const [asset] = parseAssets(fs.readFileSync(CSV, 'utf8')).filter((a) => a.category === 'switch');
  db.cecurLogs = [
    { id: 'l1', timestamp: '2025-01-01T00:00:00Z', agentName: 'x', message: `link flap on ${asset.hostname}`, fields: {} } as any,
  ];
  const [v] = linkAssetsToTelemetry([asset]);
  assert.equal(v.telemetry.coverage, 'syslog');
  assert.equal(v.telemetry.eventCount, 1);
  db.cecurAgents = [agent('a1', asset.hostname)];
  assert.equal(linkAssetsToTelemetry([asset])[0].telemetry.coverage, 'agent');
});

test('scan-support wording distinguishes the Linux worker from Windows forwarding', () => {
  const [networkAsset] = parseAssets(fs.readFileSync(CSV, 'utf8')).filter((a) => a.category === 'switch');
  const windowsAsset = { ...networkAsset, id: 'asset-windows', hostname: 'WIN-ENDPOINT-01', category: 'other' as const };
  const linux = agent('linux-agent', 'cs3-endpoint-01');
  const windows = agent('windows-agent', windowsAsset.hostname);
  windows.os = { name: 'Windows', platform: 'windows', version: '11', arch: 'x64' };
  db.cecurAgents = [linux, windows];

  const [windowsView] = linkAssetsToTelemetry([windowsAsset]);
  const [linuxView] = linkAssetsToTelemetry([{ ...windowsAsset, id: 'asset-linux', hostname: linux.name }]);
  assert.match(linuxView.telemetry.scanSupport, /compatible scan worker must report results/);
  assert.match(windowsView.telemetry.scanSupport, /Windows agent enrolled for forwarding/);
  assert.match(windowsView.telemetry.scanSupport, /scan worker is unsupported/);
});

test('fusion derives coverage and risk from endpoints without arbitrarily linking duplicate-IP incidents', () => {
  const ubuntu = agent('cecur-ag-6cf7d0180761', 'cs3-endpoint-01', '192.168.1.157');
  ubuntu.installedPackagesCount = 1656;
  ubuntu.fimMonitoredFilesCount = 7;
  ubuntu.vulnerabilitiesCount = { critical: 1, high: 0, medium: 2, low: 0 };
  const windows = agent('cecur-ag-c7d82fd99bd6', 'WIN-ENDPOINT-01', '192.168.1.158');
  windows.os = { name: 'Windows', platform: 'windows', version: '11', arch: 'x64' };
  windows.workloadType = 'workstation';
  db.cecurAgents = [ubuntu, windows];
  db.incidents = [{ id: 'incident-shared-ip', status: 'OPEN', affectedAssets: ['10.10.1.253'] } as any];

  const graph = buildAssetFusionGraph();
  assert.equal(graph.nodes.length, 20);
  assert.equal(graph.metrics?.zeroTrustCoveragePercent, 10);
  assert.equal(graph.metrics?.overallNetworkRiskScore, 5);
  assert.equal(graph.links.length, 0);
  assert.equal(graph.criticalPath.length, 0);
  assert.equal(graph.attackPaths?.length, 0);

  const ubuntuNode = graph.nodes.find((node) => node.agentId === ubuntu.id);
  assert.equal(ubuntuNode?.installedPackagesCount, 1656);
  assert.equal(ubuntuNode?.fimMonitoredFilesCount, 7);
  assert.deepEqual(ubuntuNode?.vulnerabilitiesCount, { critical: 1, high: 0, medium: 2 });
  const firewalls = graph.nodes.filter((node) => /ASM-PLB-EFW[12]/.test(node.label));
  assert.equal(firewalls.length, 2);
  assert.ok(firewalls.every((node) => node.linkedIncidentIds.length === 0));

  db.incidents = [{ id: 'incident-named-firewall', status: 'OPEN', affectedAssets: ['ASM-PLB-EFW1'] } as any];
  const namedGraph = buildAssetFusionGraph();
  assert.deepEqual(namedGraph.nodes.find((node) => node.label === 'ASM-PLB-EFW1')?.linkedIncidentIds, ['incident-named-firewall']);
  assert.deepEqual(namedGraph.nodes.find((node) => node.label === 'ASM-PLB-EFW2')?.linkedIncidentIds, []);
});

test('scan jobs: queue, claim, and result validation', () => {
  db.cecurAgents = [agent('a1'), agent('a2')];
  const [job] = queueScans('fim', [db.cecurAgents[0]], 'admin');
  assert.equal(queueScans('fim', [db.cecurAgents[0]], 'admin')[0].id, job.id, 'no duplicate in-flight job');

  assert.throws(() => applyAgentReport('a1', { jobId: job.id, status: 'completed' }), (e: any) => e instanceof ScanResultError && e.status === 409);
  assert.equal(claimJobs('a2').length, 0);
  assert.equal(claimJobs('a1').length, 1);
  assert.throws(() => applyAgentReport('a2', { jobId: job.id, status: 'completed' }), (e: any) => e instanceof ScanResultError && e.status === 404);

  const done = applyAgentReport('a1', {
    jobId: job.id,
    status: 'completed',
    monitoredFiles: 8,
    events: [{ path: '/etc/passwd', eventType: 'MODIFIED', fileType: 'credential', oldHash: 'a', newHash: 'b' }, { path: '', eventType: 'BOGUS' }],
  });
  assert.equal(done.status, 'completed');
  assert.deepEqual(done.summary, { filesChecked: 8, deviations: 1 });
  assert.equal(db.cecurFIMEvents.length, 1);
  assert.equal(db.cecurAgents[0].fimMonitoredFilesCount, 8);
  assert.throws(() => applyAgentReport('a1', { jobId: job.id, status: 'completed' }), (e: any) => e.status === 409);
});

test('a failed agent report is recorded as failed with its error, not as results', () => {
  db.cecurAgents = [agent('a1')];
  const [job] = queueScans('vuln', eligibleAgents(), 'admin');
  claimJobs('a1');
  const r = applyAgentReport('a1', { jobId: job.id, status: 'failed', error: 'debsecan missing' });
  assert.equal(r.status, 'failed');
  assert.equal(r.error, 'debsecan missing');
  assert.equal(db.cecurVulnerabilities.length, 0);
});

test('Errow: unconfigured connector rejects, remote failure is FAILED (never simulated)', async () => {
  const prev = process.env.ERROW_BASE_URL;
  db.targetAllowlist = [
    { id: 't1', hostname: 'scan-target.vendetta.lab', ipRange: '', ownerDepartment: '', authorizedBy: '', authorizationDate: '', status: 'AUTHORIZED', notes: '', scanCount: 0 },
  ];
  try {
    delete process.env.ERROW_BASE_URL;
    assert.equal(getErrowStatus().mode, 'UNCONFIGURED');
    await assert.rejects(runErrowScan('scan-target.vendetta.lab', 't1', 'nmap_scan', 'u'), ErrowUnavailableError);
    assert.equal(db.errowJobs.length, 0);

    process.env.ERROW_BASE_URL = 'http://127.0.0.1:1';
    const job = await runErrowScan('scan-target.vendetta.lab', 't1', 'nmap_scan', 'u');
    assert.equal(job.status, 'FAILED');
    assert.equal(job.findings.length, 0);
    assert.match(job.error ?? '', /failed/i);
  } finally {
    if (prev === undefined) delete process.env.ERROW_BASE_URL;
    else process.env.ERROW_BASE_URL = prev;
  }
});

test('CS3_DEMO_MODE=true fails startup', () => {
  const prev = process.env.CS3_DEMO_MODE;
  try {
    process.env.CS3_DEMO_MODE = 'true';
    assert.throws(() => assertNoDemoMode(), /no longer supported/);
    delete process.env.CS3_DEMO_MODE;
    assert.doesNotThrow(() => assertNoDemoMode());
  } finally {
    if (prev !== undefined) process.env.CS3_DEMO_MODE = prev;
  }
});

test('posture score is null without telemetry', () => {
  assert.equal(postureScore().score, null);
});
