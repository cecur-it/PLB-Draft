import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const prepareScript = path.join(repoRoot, 'on-prem/bin/prepare-compose-env.sh');
const verifyScript = path.join(repoRoot, 'on-prem/bin/verify-real-telemetry.sh');
const preflightScript = path.join(repoRoot, 'on-prem/bin/preflight-check.sh');

function temporaryDirectory(t) {
  const directory = mkdtempSync(path.join(tmpdir(), 'plb-onprem-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function run(script, args, env) {
  return spawnSync('bash', [script, ...args], { env, encoding: 'utf8' });
}

function parseEnv(file) {
  return Object.fromEntries(
    readFileSync(file, 'utf8')
      .split('\n')
      .filter((line) => line && !line.startsWith('#') && line.includes('='))
      .map((line) => {
        const separator = line.indexOf('=');
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
}

test('Compose preparation imports root secrets, generates required secrets, and is idempotent', (t) => {
  const directory = temporaryDirectory(t);
  const composeDirectory = path.join(directory, 'deployment/docker');
  const rootEnv = path.join(directory, '.env');
  const composeEnv = path.join(composeDirectory, '.env');
  mkdirSync(composeDirectory, { recursive: true });
  copyFileSync(path.join(repoRoot, 'deployment/docker/.env.example'), path.join(composeDirectory, '.env.example'));
  writeFileSync(rootEnv, 'JWT_SECRET=root-jwt\nCS3_BOOTSTRAP_ADMIN_PASSWORD=root-bootstrap\n');
  const env = {
    PATH: process.env.PATH,
    CS3_ROOT_ENV_FILE: rootEnv,
    CS3_COMPOSE_DIR: composeDirectory,
    CS3_COMPOSE_ENV_FILE: composeEnv,
  };

  const first = run(prepareScript, [], env);
  assert.equal(first.status, 0, first.stderr);
  const firstContents = readFileSync(composeEnv, 'utf8');
  const values = parseEnv(composeEnv);
  assert.equal(values.JWT_SECRET, 'root-jwt');
  assert.equal(values.CS3_BOOTSTRAP_ADMIN_PASSWORD, 'root-bootstrap');
  for (const key of ['POSTGRES_PASSWORD', 'CS3_APP_PASSWORD', 'CS3_MIGRATOR_PASSWORD', 'CS3_ARCHIVER_PASSWORD']) {
    assert.match(values[key], /^[a-f0-9]{64}$/);
  }
  assert.match(values.OPENSEARCH_INITIAL_ADMIN_PASSWORD, /^Cs3![a-f0-9]{48}$/);
  assert.equal(values.CECUR_INDEXER_PASSWORD, values.OPENSEARCH_INITIAL_ADMIN_PASSWORD);
  assert.equal(values.CS3_PROFILE, 'onprem');
  assert.equal(values.CS3_DEMO_MODE, 'false');
  assert.equal(values.CS3_INGEST_REQUIRE_KEY, 'true');
  assert.equal(values.CS3_INDEXER_ENABLED, 'true');
  assert.equal(values.CECUR_INDEXER_URL, 'https://indexer:9200');
  assert.equal(statSync(composeEnv).mode & 0o777, 0o600);

  const second = run(prepareScript, [], env);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(readFileSync(composeEnv, 'utf8'), firstContents);
});

test('Compose preparation imports a reachable Errow connector without exposing its key', (t) => {
  const directory = temporaryDirectory(t);
  const composeDirectory = path.join(directory, 'deployment/docker');
  const rootEnv = path.join(directory, '.env');
  const composeEnv = path.join(composeDirectory, '.env');
  mkdirSync(composeDirectory, { recursive: true });
  copyFileSync(path.join(repoRoot, 'deployment/docker/.env.example'), path.join(composeDirectory, '.env.example'));
  writeFileSync(rootEnv, 'ERROW_BASE_URL=http://errow.internal:8088\nERROW_API_KEY=root-errow-secret\n');

  const result = run(prepareScript, [], {
    PATH: process.env.PATH,
    CS3_ROOT_ENV_FILE: rootEnv,
    CS3_COMPOSE_DIR: composeDirectory,
    CS3_COMPOSE_ENV_FILE: composeEnv,
  });
  assert.equal(result.status, 0, result.stderr);
  const values = parseEnv(composeEnv);
  assert.equal(values.ERROW_BASE_URL, 'http://errow.internal:8088');
  assert.equal(values.ERROW_API_KEY, 'root-errow-secret');
  assert.equal(values.ERROW_MODE, 'remote');
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /root-errow-secret/);
});

test('Compose preparation rejects root loopback Errow URLs and preserves an existing connector', (t) => {
  const directory = temporaryDirectory(t);
  const composeDirectory = path.join(directory, 'deployment/docker');
  const rootEnv = path.join(directory, '.env');
  const composeEnv = path.join(composeDirectory, '.env');
  mkdirSync(composeDirectory, { recursive: true });
  copyFileSync(path.join(repoRoot, 'deployment/docker/.env.example'), path.join(composeDirectory, '.env.example'));
  writeFileSync(rootEnv, 'ERROW_BASE_URL=http://127.0.0.1:8088\nERROW_API_KEY=root-errow-secret\n');
  const env = {
    PATH: process.env.PATH,
    CS3_ROOT_ENV_FILE: rootEnv,
    CS3_COMPOSE_DIR: composeDirectory,
    CS3_COMPOSE_ENV_FILE: composeEnv,
  };

  const loopback = run(prepareScript, [], env);
  assert.equal(loopback.status, 0, loopback.stderr);
  assert.match(loopback.stderr, /loopback.*not imported/);
  assert.equal(parseEnv(composeEnv).ERROW_BASE_URL, '');
  assert.equal(parseEnv(composeEnv).ERROW_API_KEY, '');
  assert.doesNotMatch(loopback.stderr, /root-errow-secret/);

  writeFileSync(composeEnv, `${readFileSync(composeEnv, 'utf8')}\nERROW_BASE_URL=http://existing-errow:8088\nERROW_API_KEY=existing-errow-secret\n`);
  const preserved = run(prepareScript, [], env);
  assert.equal(preserved.status, 0, preserved.stderr);
  assert.equal(parseEnv(composeEnv).ERROW_BASE_URL, 'http://existing-errow:8088');
  assert.equal(parseEnv(composeEnv).ERROW_API_KEY, 'existing-errow-secret');
});

test('Compose preparation preserves existing secrets and rejects mismatched indexer passwords', (t) => {
  const directory = temporaryDirectory(t);
  const composeDirectory = path.join(directory, 'deployment/docker');
  const composeEnv = path.join(composeDirectory, '.env');
  mkdirSync(composeDirectory, { recursive: true });
  copyFileSync(path.join(repoRoot, 'deployment/docker/.env.example'), path.join(composeDirectory, '.env.example'));
  const env = {
    PATH: process.env.PATH,
    CS3_ROOT_ENV_FILE: path.join(directory, 'missing-root.env'),
    CS3_COMPOSE_DIR: composeDirectory,
    CS3_COMPOSE_ENV_FILE: composeEnv,
  };
  assert.equal(run(prepareScript, [], env).status, 0);
  const initial = parseEnv(composeEnv);
  writeFileSync(
    composeEnv,
    `${readFileSync(composeEnv, 'utf8')}\nCS3_APP_PASSWORD=existing-app-secret\nCS3_PROFILE=cloud\n`,
  );

  assert.equal(run(prepareScript, [], env).status, 0);
  const preserved = parseEnv(composeEnv);
  assert.equal(preserved.CS3_APP_PASSWORD, 'existing-app-secret');
  assert.equal(preserved.JWT_SECRET, initial.JWT_SECRET);
  assert.equal(preserved.CS3_PROFILE, 'onprem');

  const mismatched = readFileSync(composeEnv, 'utf8').replace(
    `CECUR_INDEXER_PASSWORD=${preserved.CECUR_INDEXER_PASSWORD}`,
    'CECUR_INDEXER_PASSWORD=different-password',
  );
  writeFileSync(composeEnv, mismatched);
  const result = run(prepareScript, [], env);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /PASSWORD.*differ/);
});

const curlMock = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const state = process.env.MOCK_STATE;
const url = args.find((arg) => arg.startsWith('http')) || '';
let kind = 'unknown';
if (url.endsWith('/api/cecur/logs/ingest')) kind = 'ingest';
else if (url.endsWith('/api/cecur/logs')) kind = 'hot';
else if (url.endsWith('/cs3-logs/_search')) kind = 'search';
else if (url.endsWith('/api/health') || url.endsWith('/_cluster/health')) kind = 'health';
fs.appendFileSync(process.env.MOCK_LOG, JSON.stringify({ kind, url, args }) + '\\n');
const dataIndex = args.indexOf('--data-binary');
const body = dataIndex >= 0 ? JSON.parse(fs.readFileSync(args[dataIndex + 1].replace(/^@/, ''), 'utf8')) : null;
if (kind === 'ingest') {
  fs.writeFileSync(state + '/ingest.json', JSON.stringify(body));
  process.stdout.write(process.env.MOCK_INGEST_RESPONSE || '{"success":true,"indexed":true,"logId":"synthetic-id"}');
} else if (kind === 'hot') {
  process.stdout.write(JSON.stringify({ logs: [JSON.parse(fs.readFileSync(state + '/ingest.json', 'utf8'))] }));
} else if (kind === 'search') {
  const message = body?.query?.bool?.must?.[0]?.match_phrase?.message;
  const agentName = body?.query?.bool?.must?.[1]?.match_phrase?.agentName || 'plb-syslog-relay-01';
  const sourceIp = body?.query?.bool?.must?.[2]?.match_phrase?.['fields.source_ip'] || '';
  const hits = message && message === process.env.MOCK_EMPTY_DEVICE ? [] : [{
    _index: 'cs3-logs-000001', _id: body?.query?.ids?.values?.[0] || 'device-id',
    _source: { timestamp: '2026-01-01T00:00:00Z', agentName, fields: { source_ip: sourceIp } },
  }];
  process.stdout.write(JSON.stringify({ hits: { total: { value: hits.length }, hits } }));
} else if (kind === 'health') {
  process.stdout.write(url.endsWith('/_cluster/health') ? '{"status":"green"}' : '{"status":"nominal"}');
} else {
  process.stderr.write('unexpected URL: ' + url);
  process.exit(22);
}
`;

const dockerMock = `#!/usr/bin/env node
const fs = require('node:fs');
fs.appendFileSync(process.env.MOCK_LOG, JSON.stringify({ kind: 'docker', args: process.argv.slice(2) }) + '\\n');
const status = Number(process.env.MOCK_DOCKER_STATUS || 0);
if (status) process.stderr.write('mock restart failure');
process.exit(status);
`;

function mockVerifier(t) {
  const directory = temporaryDirectory(t);
  const bin = path.join(directory, 'bin');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'curl'), curlMock);
  writeFileSync(path.join(bin, 'docker'), dockerMock);
  writeFileSync(path.join(bin, 'sleep'), '#!/usr/bin/env bash\nexit 0\n');
  for (const command of ['curl', 'docker', 'sleep']) chmodSync(path.join(bin, command), 0o755);
  const log = path.join(directory, 'calls.jsonl');
  writeFileSync(log, '');
  const composeDirectory = path.join(directory, 'compose');
  mkdirSync(composeDirectory);
  writeFileSync(path.join(composeDirectory, 'docker-compose.yml'), 'services: {}\n');
  const env = {
    PATH: `${bin}:${process.env.PATH}`,
    MOCK_STATE: directory,
    MOCK_LOG: log,
    CS3_COMPOSE_DIR: composeDirectory,
    CECUR_INDEXER_VERIFY_URL: 'https://indexer.example',
    CECUR_INDEXER_USERNAME: 'admin',
    CECUR_INDEXER_PASSWORD: 'not-a-real-secret',
  };
  return { directory, env, calls: () => readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) };
}

function verifierArgs(extra = []) {
  return [
    '--url', 'https://console.example/api/cecur/logs/ingest',
    '--ingest-key', 'test-key', '--agent-id', 'plb-syslog-relay-01', '--token', 'test-token',
    ...extra,
  ];
}

test('Verifier rejects success:true with indexed:false before hot-cache checks', (t) => {
  const mock = mockVerifier(t);
  const result = run(verifyScript, verifierArgs(), { ...mock.env, MOCK_INGEST_RESPONSE: '{"success":true,"indexed":false,"logId":"id"}' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /indexed:false is a C3 failure/);
  assert.deepEqual(mock.calls().map((call) => call.kind), ['ingest']);
});

test('Preflight enforces durable indexing and supports host-side indexer verification', (t) => {
  const disabled = mockVerifier(t);
  const disabledResult = run(preflightScript, [], {
    ...disabled.env,
    CS3_PROFILE: 'onprem',
    CS3_DEMO_MODE: 'false',
    CS3_INGEST_REQUIRE_KEY: 'true',
    CS3_INDEXER_ENABLED: 'false',
  });
  assert.notEqual(disabledResult.status, 0);
  assert.match(disabledResult.stdout, /CS3_INDEXER_ENABLED=false/);
  assert.equal(disabled.calls().length, 0);

  const enabled = mockVerifier(t);
  const enabledResult = run(preflightScript, [], {
    ...enabled.env,
    CS3_PROFILE: 'onprem',
    CS3_DEMO_MODE: 'false',
    CS3_INGEST_REQUIRE_KEY: 'true',
    CS3_INDEXER_ENABLED: 'true',
  });
  assert.equal(enabledResult.status, 0, enabledResult.stdout + enabledResult.stderr);
  assert.match(enabledResult.stdout, /Indexer \(https:\/\/indexer\.example\) is reachable/);
  assert.match(enabledResult.stdout, /Preflight PASSED/);
  assert.ok(enabled.calls().some((call) => call.url.endsWith('/_cluster/health')));
});

test('Verifier requires a console token and host-reachable indexer configuration', (t) => {
  const mock = mockVerifier(t);
  const missingToken = run(verifyScript, [
    '--url', 'https://console.example', '--ingest-key', 'key', '--agent-id', 'relay',
  ], mock.env);
  assert.notEqual(missingToken.status, 0);
  assert.match(missingToken.stderr, /hot-cache verification cannot be skipped/);

  const missingIndexer = run(verifyScript, verifierArgs(), { ...mock.env, CECUR_INDEXER_VERIFY_URL: '' });
  assert.notEqual(missingIndexer.status, 0);
  assert.match(missingIndexer.stderr, /host-reachable CECUR_INDEXER_URL/);
});

test('Verifier rejects incomplete, duplicate, and wrong-count expectation manifests', async (t) => {
  const mock = mockVerifier(t);
  const cases = [
    { name: 'missing field', json: '[{"device":"PLB1","message":"PLB1"}]', error: /expectations must be/ },
    { name: 'duplicate device', json: '[{"device":"PLB1","message":"one","agentName":"PLB1"},{"device":"PLB1","message":"two","agentName":"PLB1"}]', error: /must be unique/ },
    { name: 'wrong count', json: '[{"device":"PLB1","message":"one","agentName":"PLB1"}]', error: /required: 18/, count: '18' },
  ];
  for (const item of cases) {
    await t.test(item.name, () => {
      const manifest = path.join(mock.directory, `${item.name.replaceAll(' ', '-')}.json`);
      writeFileSync(manifest, item.json);
      const result = run(verifyScript, verifierArgs([
        '--expectations', manifest, '--since', '2026-01-01T00:00:00Z', ...(item.count ? ['--expect-count', item.count] : []),
      ]), mock.env);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, item.error);
    });
  }
});

test('Verifier accepts a full ingest URL and repeats all direct queries after restart', (t) => {
  const mock = mockVerifier(t);
  const manifest = path.join(mock.directory, 'expectations.json');
  writeFileSync(manifest, '[{"device":"PLB1","message":"PLB1-token","agentName":"PLB1","sourceIp":"10.10.2.2"}]');
  const result = run(verifyScript, verifierArgs([
    '--expectations', manifest, '--expect-count', '1', '--since', '2026-01-01T00:00:00Z', '--restart-console',
  ]), mock.env);
  assert.equal(result.status, 0, result.stderr);
  const calls = mock.calls();
  assert.deepEqual(calls.map((call) => call.kind), ['ingest', 'hot', 'search', 'search', 'docker', 'health', 'search', 'search'], `${result.stdout}\n${result.stderr}`);
  assert.equal(calls[0].url, 'https://console.example/api/cecur/logs/ingest');
  assert.equal(calls.filter((call) => call.kind === 'health')[0].url, 'https://console.example/api/health');
  assert.match(result.stdout, /C3 verification PASSED for 2 evidence item/);
});

test('Verifier blocks restart acceptance when any device has no OpenSearch evidence', (t) => {
  const mock = mockVerifier(t);
  const manifest = path.join(mock.directory, 'expectations.json');
  writeFileSync(manifest, '[{"device":"PLB1","message":"PLB1-token","agentName":"PLB1"}]');
  const result = run(verifyScript, verifierArgs([
    '--expectations', manifest, '--since', '2026-01-01T00:00:00Z', '--restart-console',
  ]), { ...mock.env, MOCK_EMPTY_DEVICE: 'PLB1-token' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /no post-.*OpenSearch evidence for PLB1/);
  assert.equal(mock.calls().some((call) => call.kind === 'docker'), false);
});

test('Verifier fails closed when the requested console restart fails', (t) => {
  const mock = mockVerifier(t);
  const manifest = path.join(mock.directory, 'expectations.json');
  writeFileSync(manifest, '[{"device":"PLB1","message":"PLB1-token","agentName":"PLB1"}]');
  const result = run(verifyScript, verifierArgs([
    '--expectations', manifest, '--expect-count', '1', '--since', '2026-01-01T00:00:00Z', '--restart-console',
  ]), { ...mock.env, MOCK_DOCKER_STATUS: '1' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /mock restart failure/);
  assert.deepEqual(mock.calls().map((call) => call.kind), ['ingest', 'hot', 'search', 'search', 'docker']);
});

test('Synthetic-only diagnostics accept a base URL without claiming C3 acceptance', (t) => {
  const mock = mockVerifier(t);
  const result = run(verifyScript, [
    '--url', 'https://console.example', '--ingest-key', 'test-key',
    '--agent-id', 'plb-syslog-relay-01', '--token', 'test-token',
  ], mock.env);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /not C3 restart-durability acceptance/);
  assert.equal(mock.calls()[0].url, 'https://console.example/api/cecur/logs/ingest');
  assert.deepEqual(mock.calls().map((call) => call.kind), ['ingest', 'hot', 'search']);
});

test('Query-only mode requires no synthetic ingest or console token', (t) => {
  const mock = mockVerifier(t);
  const manifest = path.join(mock.directory, 'expectations.json');
  writeFileSync(manifest, '[{"device":"PLB1","message":"PLB1-token","agentName":"PLB1"}]');
  const result = run(verifyScript, [
    '--query-only', '--expectations', manifest, '--expect-count', '1', '--since', '2026-01-01T00:00:00Z',
  ], mock.env);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(mock.calls().map((call) => call.kind), ['search'], `${result.stdout}\n${result.stderr}`);
});
