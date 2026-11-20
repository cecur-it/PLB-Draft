#!/usr/bin/env node
/**
 * Guards the Linux forwarder "gateway profile" (Fluent Bit fragments, installer, env contract, optional
 * Fluentd aggregator, Ansible flags). These are static checks on the shipped files; the runtime behaviour is
 * validated by the runbook in deployment/operations/fluent-telemetry-fabric.md.
 *
 *   node --test scripts/forwarder-gateway.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const deployment = join(dirname(fileURLToPath(import.meta.url)), '..', 'deployment');
const agents = join(deployment, 'agents');
const read = (p) => readFileSync(join(agents, p), 'utf8');
const gatewayDir = join(agents, 'templates', 'gateway.d');
const fragments = readdirSync(gatewayDir).filter((f) => f.endsWith('.conf') || f.endsWith('.lua'));

const installer = read('install-forwarder.sh');
const edge = read('templates/fluent-bit-linux.conf');
const envExample = read('templates/forwarder.env.example');
const strip = (s) => s.replace(/^\s*#.*$/gm, '');

test('every ${CS3_*} variable used by the templates is documented in forwarder.env.example', () => {
  const used = new Set();
  for (const text of [edge, ...fragments.map((f) => read(`templates/gateway.d/${f}`))]) {
    for (const m of text.matchAll(/\$\{(CS3_[A-Z0-9_]+)\}/g)) used.add(m[1]);
  }
  used.add('CS3_MESSAGE_MAX_CHARS'); // read by the Lua normaliser via os.getenv
  assert.ok(used.size >= 20, 'expected the gateway variable set');
  for (const v of used) {
    assert.match(envExample, new RegExp(`^#?\\s*${v}=`, 'm'), `${v} missing from forwarder.env.example`);
  }
});

test('every variable the installer writes is documented in forwarder.env.example', () => {
  for (const m of installer.matchAll(/echo "(CS3_[A-Z0-9_]+)=/g)) {
    assert.match(envExample, new RegExp(`^#?\\s*${m[1]}=`, 'm'), `${m[1]} missing from forwarder.env.example`);
  }
});

test('forwarder.env.example carries no real secrets', () => {
  assert.match(envExample, /CS3_INGEST_KEY=REPLACE_WITH_/);
  assert.match(envExample, /CS3_SIEM_TOKEN=REPLACE_WITH_/);
});

test('installer-owned fragments match the shipped gateway.d files', () => {
  const owned = installer.match(/GATEWAY_FRAGS=\(([^)]*)\)/)?.[1].trim().split(/\s+/).sort();
  assert.deepEqual(owned, [...fragments].sort());
  // Examples are never installed or owned.
  assert.ok(readdirSync(gatewayDir).includes('70-app-logs.conf.example'));
  assert.ok(!owned.some((f) => f.includes('example')));
});

test('edge template keeps a commented @INCLUDE the installer un-comments', () => {
  assert.match(edge, /^# @INCLUDE \/etc\/cecur\/fluent-bit\.d\/\*\.conf$/m);
  assert.doesNotMatch(edge, /^@INCLUDE/m, 'an uncommented @INCLUDE glob is fatal when the directory is empty');
  // Same substitution install_gateway() applies.
  const on = edge.replace(/^# (@INCLUDE \/etc\/cecur\/fluent-bit\.d\/)/m, '$1');
  assert.match(on, /^@INCLUDE \/etc\/cecur\/fluent-bit\.d\/\*\.conf$/m);
  assert.match(installer, /s\|\^# \(@INCLUDE \/etc\/cecur\/fluent-bit\\\.d\/\)\|\\1\|/);
});

test('console output stays logs-only and excludes AI-tier tags', () => {
  const out = edge.match(/\[OUTPUT\][\s\S]*?Match_Regex\s+(\S+)/)?.[1];
  assert.equal(out, '^(host\\..*|v1_logs)$');
  assert.doesNotMatch(out, /cs3\\\.ai/);
});

test('OTLP mTLS listener requires client certificates on TLS 1.3', () => {
  const c = strip(read('templates/gateway.d/10-otlp-input-mtls.conf'));
  assert.match(c, /^\s*Name\s+opentelemetry/m);
  assert.match(c, /^\s*tls\.verify_client_cert\s+On/m);
  assert.match(c, /^\s*tls\.min_version\s+TLSv1\.3/m);
  assert.match(c, /^\s*tls\.ca_file\s+\$\{CS3_OTLP_CA_FILE\}/m);
  assert.match(c, /^\s*storage\.type\s+filesystem/m);
});

test('ESOC egress: OTLP/gRPC, mTLS, TLS 1.3, unlimited retries, gzip', () => {
  const c = strip(read('templates/gateway.d/40-esoc-otlp.conf'));
  for (const re of [
    /^\s*Name\s+opentelemetry/m,
    /^\s*grpc\s+On/m,
    /^\s*compress\s+gzip/m,
    /^\s*tls\.min_version\s+TLSv1\.3/m,
    /^\s*tls\.crt_file\s+\$\{CS3_ESOC_CERT_FILE\}/m,
    /^\s*tls\.key_file\s+\$\{CS3_ESOC_KEY_FILE\}/m,
    /^\s*Retry_Limit\s+False/m,
  ]) {
    assert.match(c, re);
  }
});

test('SIEM egress: verified TLS, secret only via environment, no proxy unless enabled', () => {
  const raw = read('templates/gateway.d/50-siem-http.conf');
  const c = strip(raw);
  assert.match(c, /^\s*tls\.verify\s+On/m);
  assert.match(c, /^\s*Header\s+Authorization\s+\$\{CS3_SIEM_AUTH_SCHEME\}\s+\$\{CS3_SIEM_TOKEN\}/m);
  assert.match(c, /^\s*Compress\s+gzip/m);
  assert.match(c, /^\s*Retry_Limit\s+False/m);
  assert.doesNotMatch(c, /^\s*Proxy\s/m, 'Proxy is commented; the installer enables it with --siem-proxy');
  assert.match(raw, /^ {4}# Proxy\s+\$\{CS3_SIEM_PROXY\}/m);
  assert.match(installer, /s\/\^ {4}# \(Proxy \)\//);
});

test('Lua normaliser is wired to the path the installer uses', () => {
  const lua = read('templates/gateway.d/cs3-otlp-normalize.lua');
  assert.match(lua, /^function cs3_normalize\(tag, timestamp, record\)/m);
  const norm = read('templates/gateway.d/20-normalize.conf');
  assert.match(norm, /script\s+\/etc\/cecur\/fluent-bit\.d\/cs3-otlp-normalize\.lua/);
  assert.match(norm, /call\s+cs3_normalize/);
});

test('installer exposes the gateway flags and enforces the zero-trust rules', () => {
  for (const flag of [
    '--profile', '--otlp-listen', '--otlp-port', '--otlp-cert', '--otlp-key', '--otlp-client-ca',
    '--esoc-host', '--esoc-port', '--esoc-cert', '--esoc-key', '--esoc-ca',
    '--siem-url', '--siem-token-file', '--siem-auth-scheme', '--siem-format', '--siem-ca', '--siem-proxy', '--ai-tier',
  ]) {
    assert.ok(installer.includes(`${flag})`), `${flag} not handled`);
  }
  assert.match(installer, /off-loopback|non-loopback|mTLS/i);
  assert.match(installer, /CS3_SIEM_TOKEN/);
  assert.doesNotMatch(installer, /--siem-token\)/, 'the SIEM credential must never be an argv flag');
});

test('watchdog tracks the gateway certificates the installer lays down', () => {
  const wd = read('cs3-forwarder-watchdog.sh');
  const pki = installer.match(/GATEWAY_PKI=\(.*?\{(.*?)\}\)/)?.[1].split(',');
  assert.ok(pki && pki.length >= 7);
  const certs = pki.filter((f) => /\.(crt|pem)$/.test(f));
  for (const f of certs) assert.ok(wd.includes(f), `${f} not covered by the cert-expiry check`);
});

test('Ansible gateway flags are all supported by the installer', () => {
  const yml = readFileSync(join(deployment, 'ansible', 'playbooks', 'deploy-forwarders.yml'), 'utf8');
  const flags = new Set([...yml.matchAll(/'(--[a-z0-9-]+)'/g)].map((m) => m[1]));
  for (const f of flags) assert.ok(installer.includes(`${f})`), `${f} used by Ansible but not handled by the installer`);
  assert.ok(flags.has('--profile') && flags.has('--esoc-host') && flags.has('--siem-url'));
  assert.match(yml, /CS3_SIEM_TOKEN/);
});

test('Fluentd aggregator: mTLS in, valid auth, env via #{ENV}, buffered, no shadowed matches', () => {
  const raw = read('templates/fluentd-aggregator.conf');
  const c = strip(raw);
  assert.doesNotMatch(c, /\$\{[A-Z_]+\}/, 'Fluentd does not expand ${VAR}');
  assert.match(c, /@type opentelemetry\b/);
  assert.match(c, /client_cert_auth true/);
  assert.match(c, /authentication bearer/);
  assert.match(c, /buffered true/);
  assert.match(c, /ENV\.fetch\('CS3_SIEM_TOKEN'\)/);
  assert.doesNotMatch(c, /queue_limit_length/);
  assert.doesNotMatch(c, /authentication token/);
  // Top-level <match> blocks must not be shadowed by an earlier, broader pattern.
  const top = c.replace(/<label[\s\S]*?<\/label>/g, '');
  const patterns = [...top.matchAll(/<match\s+(\S+?)>/g)].map((m) => m[1]);
  assert.deepEqual(patterns, ['cs3.otlp.logs', 'cs3.**']);
});

test('Parsers_File is an absolute path to a file the installer actually installs', () => {
  const m = strip(edge).match(/^\s*Parsers_File\s+(\S+)/m);
  assert.ok(m, 'edge config must declare Parsers_File');
  // A relative path resolves under /etc/cecur/ where nothing was installed, and Fluent Bit aborts at startup.
  assert.match(m[1], /^\/etc\/cecur\/parsers\.conf$/, 'Parsers_File must be the absolute /etc/cecur/parsers.conf');
  assert.match(
    installer,
    /install -m 0640 "\$SRC_DIR\/templates\/parsers\.conf" "\$CONF_DIR\/parsers\.conf"/,
    'installer must install templates/parsers.conf to $CONF_DIR/parsers.conf',
  );
});

test('every `Parser X` used by the templates is defined in templates/parsers.conf', () => {
  const defined = new Set([...strip(read('templates/parsers.conf')).matchAll(/^\s*Name\s+(\S+)/gm)].map((m) => m[1]));
  assert.ok(defined.has('json'), 'parsers.conf must define the json parser');
  for (const [name, text] of [
    ['fluent-bit-linux.conf', edge],
    ...fragments.map((f) => [f, read(`templates/gateway.d/${f}`)]),
    ['70-app-logs.conf.example', read('templates/gateway.d/70-app-logs.conf.example')],
  ]) {
    for (const m of strip(text).matchAll(/^\s*Parser\s+(\S+)/gm)) {
      assert.ok(defined.has(m[1]), `${name} uses parser "${m[1]}" that parsers.conf does not define`);
    }
  }
  // The example documents the parser as a comment; it must name one that exists.
  for (const m of read('templates/gateway.d/70-app-logs.conf.example').matchAll(/^\s*#\s*Parser\s+(\S+)/gm)) {
    assert.ok(defined.has(m[1]), `example references undefined parser "${m[1]}"`);
  }
});
