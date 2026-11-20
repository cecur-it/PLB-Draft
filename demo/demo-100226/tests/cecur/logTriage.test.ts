import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLogAnomalyWithAI } from '../../server/ai/cecurAI';
import { resolveAsset } from '../../server/assets/resolution';
import { setGateway } from '../../server/inference/gateway';
import type { InferenceGateway, InferenceRequest } from '../../server/inference/types';
import type { AssetRecord } from '../../src/types';

const previousProfile = process.env.CS3_PROFILE;

function networkAsset(category: 'switch' | 'firewall', criticality?: AssetRecord['criticality']): AssetRecord {
  const hostname = category === 'switch' ? 'PLB-SW1' : 'PLB-FW1';
  return {
    id: `asset-${hostname.toLowerCase()}`,
    sourceRow: 2,
    hostname,
    managementIp: category === 'switch' ? '10.10.1.11' : '10.10.1.1',
    location: 'PLB',
    category,
    criticality,
    assetType: category,
    role: category,
    oem: 'Test',
    model: 'Test',
    adminAccountHolders: [],
    redundancy: false,
    thresholds: {},
  };
}

function mockGateway(output: Record<string, unknown>, seen?: { request?: InferenceRequest }, fallback = false): InferenceGateway {
  return {
    describe: () => ({ backend: 'mock', baseUrl: '', models: { triage: 'mock-triage', forensic: 'mock-forensic', security: 'mock-security' } }),
    infer: async (request) => {
      if (seen) seen.request = request;
      return {
        output,
        model: { name: 'mock-triage', digest: '', quantization: '', backend: 'mock' },
        usage: { promptTokens: 1, completionTokens: 1, gpuSeconds: 0 },
        guardrail: { passed: true, violations: [] },
        latencyMs: 1,
        fallback,
      };
    },
  };
}

afterEach(() => {
  setGateway(null);
  if (previousProfile === undefined) delete process.env.CS3_PROFILE;
  else process.env.CS3_PROFILE = previousProfile;
});

test('AI log triage exposes provenance and receives the selected asset evidence', async () => {
  process.env.CS3_PROFILE = 'onprem';
  const assetContext = resolveAsset({ hostname: 'plb-sw1.' }, {
    inventory: [networkAsset('switch', 'TIER_1_HIGH')],
    agents: [],
    inventorySource: 'PLB_Assets.csv',
  });
  const seen: { request?: InferenceRequest } = {};
  setGateway(mockGateway({
    triageSummary: 'Resolved switch telemetry requires review.',
    severityAssessment: 'HIGH',
    mitreTactic: 'Discovery',
    mitreTechnique: 'T1046 - Network Service Discovery',
    probableRootCause: 'Log evidence requires device review.',
    recommendedImmediateAction: 'Validate the switch management plane.',
    confidenceScore: 82,
  }, seen));

  const result = await analyzeLogAnomalyWithAI({
    logMessage: 'host=PLB-SW1 unusual configuration command',
    source: 'syslog',
    agentName: 'PLB-SW1',
    agentOs: 'unknown',
    anomalyScore: 0.7,
  }, assetContext);

  assert.equal(result.source, 'ai');
  assert.equal(result.assetContext.asset?.id, 'asset-plb-sw1');
  assert.match(seen.request?.input.user ?? '', /asset-plb-sw1/);
  assert.match(seen.request?.input.user ?? '', /TIER_1_HIGH/);
  assert.match(seen.request?.input.user ?? '', /"matchConfidence":98/);
  assert.match(seen.request?.input.system ?? '', /not a topology or correlation claim/i);
});

test('incomplete AI triage is not mislabeled as AI output', async () => {
  process.env.CS3_PROFILE = 'onprem';
  const assetContext = resolveAsset({ hostname: 'PLB-SW1' }, {
    inventory: [networkAsset('switch')],
    agents: [],
  });
  setGateway(mockGateway({ triageSummary: 'Incomplete response' }));

  const result = await analyzeLogAnomalyWithAI({
    logMessage: 'host=PLB-SW1 incomplete test',
    source: 'syslog',
    agentName: 'PLB-SW1',
    agentOs: 'unknown',
    anomalyScore: 0.4,
  }, assetContext);

  assert.equal(result.source, 'deterministic');
  assert.match(result.engineUsed, /Deterministic/);
  assert.match(result.triageSummary, /Cecur SIEM Engine/);
});

test('deterministic fallback is labeled and does not prescribe agent isolation for a firewall', async () => {
  process.env.CS3_PROFILE = 'onprem';
  const assetContext = resolveAsset({ ip: '10.10.1.1' }, {
    inventory: [networkAsset('firewall')],
    agents: [],
    inventorySource: 'PLB_Assets.csv',
  });
  setGateway(mockGateway({}, undefined, true));

  const result = await analyzeLogAnomalyWithAI({
    logMessage: 'firewall denied an unexpected management connection',
    source: 'syslog',
    agentName: 'PLB-FW1',
    agentOs: 'unknown',
    anomalyScore: 0.9,
  }, assetContext);

  assert.equal(result.source, 'deterministic');
  assert.match(result.engineUsed, /Deterministic/);
  assert.equal(result.assetContext.asset?.category, 'firewall');
  assert.equal(result.assetContext.asset?.criticality, null);
  assert.match(result.triageSummary, /asset-plb-fw1/);
  assert.match(result.triageSummary, /No behavior classification, topology, or cross-event correlation is inferred/);
  assert.equal(result.mitreTactic, 'Not determined');
  assert.equal(result.mitreTechnique, 'Not determined');
  assert.match(result.probableRootCause, /^Not determined by deterministic fallback/);
  assert.equal(result.confidenceScore, 0);
  assert.doesNotMatch(result.probableRootCause, /high entropy/i);
  assert.match(result.recommendedImmediateAction, /do not issue endpoint-agent isolation/i);
  assert.match(result.recommendedImmediateAction, /device-appropriate containment/i);
});
