import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveAsset } from '../../server/assets/resolution';
import type { AssetCategory, AssetCriticality, AssetRecord } from '../../src/types';

function asset(
  id: string,
  hostname: string,
  category: Exclude<AssetCategory, 'endpoint'>,
  managementIp?: string,
  criticality?: AssetCriticality,
): AssetRecord {
  return {
    id,
    sourceRow: 2,
    hostname,
    managementIp,
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

const endpointAgents = [
  { id: 'agent-a', name: 'workstation-a', hostname: 'workstation-a.plb.local', ip: '10.20.0.10' },
  { id: 'agent-b', name: 'workstation-b', hostname: 'workstation-b.plb.local', ip: '10.20.0.11' },
];

test('two endpoints retain separate identities across normalized agent and IP evidence', () => {
  const byAgent = resolveAsset({
    agentId: 'agent-b',
    agentName: 'WORKSTATION-B.PLB.LOCAL.',
    agentIp: '010.020.000.011',
  }, { inventory: [], agents: endpointAgents, inventorySource: 'test-agents' });

  assert.equal(byAgent.status, 'matched');
  assert.equal(byAgent.asset?.id, 'agent:agent-b');
  assert.equal(byAgent.asset?.category, 'endpoint');
  assert.equal(byAgent.asset?.criticality, null);
  assert.equal(byAgent.matchMethod, 'agent_id');
  assert.equal(byAgent.matchConfidence, 100);
  assert.equal(byAgent.scope, 'identity_only');

  const byIp = resolveAsset({ fields: { source_ip: '10.20.0.10' } }, {
    inventory: [],
    agents: endpointAgents,
  });
  assert.equal(byIp.status, 'matched');
  assert.equal(byIp.asset?.id, 'agent:agent-a');
  assert.equal(byIp.matchMethod, 'ip');
});

test('equal source and destination identity evidence remains ambiguous', () => {
  const result = resolveAsset({
    fields: { source_ip: '10.20.0.10', destination_ip: '10.20.0.11' },
  }, { inventory: [], agents: endpointAgents });

  assert.equal(result.status, 'ambiguous');
  assert.equal(result.asset, null);
  assert.deepEqual(result.candidates.map((candidate) => candidate.id), ['agent:agent-a', 'agent:agent-b']);
  assert.equal(result.matchConfidence, 0);
  assert.match(result.reason, /no asset was selected/i);
});

test('a duplicate management IP never selects one firewall arbitrarily', () => {
  const firewalls = [
    asset('asset-efw1', 'ASM-PLB-EFW1', 'firewall', '10.10.1.253'),
    asset('asset-efw2', 'ASM-PLB-EFW2', 'firewall', '10.10.1.253'),
  ];
  const result = resolveAsset({ ip: '10.10.1.253' }, {
    inventory: firewalls,
    agents: [],
    inventorySource: 'PLB_Assets.csv',
  });

  assert.equal(result.status, 'ambiguous');
  assert.equal(result.asset, null);
  assert.deepEqual(result.candidates.map((candidate) => candidate.id), ['asset-efw1', 'asset-efw2']);
  assert.deepEqual(result.evidence[0].candidateIds, ['asset-efw1', 'asset-efw2']);
  assert.match(result.reason, /IP evidence maps to multiple/);

  const named = resolveAsset({ hostname: 'asm-plb-efw2.', ip: '10.10.1.253' }, {
    inventory: firewalls,
    agents: [],
  });
  assert.equal(named.status, 'matched');
  assert.equal(named.asset?.id, 'asset-efw2');
  assert.equal(named.matchMethod, 'hostname');
});

test('agentless switch, firewall, and wireless AP matches preserve category and criticality provenance', async (t) => {
  const cases = [
    {
      asset: asset('asset-sw1', 'PLB-SW1', 'switch', '10.10.1.11', 'TIER_1_HIGH'),
      input: { hostname: 'plb-sw1.' },
      category: 'switch',
      criticality: 'TIER_1_HIGH',
    },
    {
      asset: asset('asset-fw1', 'PLB-FW1', 'firewall', '10.10.1.1'),
      input: { ip: '10.10.1.1' },
      category: 'firewall',
      criticality: null,
    },
    {
      asset: asset('asset-ap1', 'PLB-AP1', 'wireless_ap', '10.10.1.21'),
      input: { logMessage: 'host=plb-ap1 association event' },
      category: 'wireless_ap',
      criticality: null,
    },
  ] as const;

  for (const testCase of cases) {
    await t.test(testCase.asset.id, () => {
      const result = resolveAsset(testCase.input, { inventory: [testCase.asset], agents: [] });
      assert.equal(result.status, 'matched');
      assert.equal(result.asset?.category, testCase.category);
      assert.equal(result.asset?.criticality, testCase.criticality);
      assert.deepEqual(result.asset?.sources, ['plb_inventory']);
      assert.equal(result.asset?.agentId, null);
    });
  }
});
