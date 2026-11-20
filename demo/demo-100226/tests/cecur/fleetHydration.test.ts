import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Request, Response } from 'express';
import { db } from '../../server/db';
import {
  bulkEnroll,
  fleetSummary,
  hydrateFleet,
  requireAgentKey,
  sha256,
} from '../../server/fleet/enrollment';
import type { CecurAgent } from '../../src/types';

const now = Date.now();
const agent: CecurAgent = {
  id: 'cecur-ag-persisted',
  name: 'ubuntu-endpoint',
  hostname: 'ubuntu-endpoint',
  ip: '192.0.2.10',
  os: { name: 'Ubuntu', platform: 'linux', version: '22.04', arch: 'x86_64' },
  workloadType: 'virtual',
  status: 'active',
  version: '5.2.0',
  lastKeepAlive: new Date(now).toISOString(),
  registeredAt: new Date(now - 60_000).toISOString(),
  group: ['lab-endpoints', 'default'],
  cpuUsage: 0,
  memoryUsage: 0,
  diskUsage: 0,
  installedPackagesCount: 0,
  vulnerabilitiesCount: { critical: 0, high: 0, medium: 0, low: 0 },
  fimMonitoredFilesCount: 0,
  scaScore: 0,
  isolationStatus: false,
};

test('boot hydration restores inventory, pending enrollment state, and agent-key authentication', async () => {
  db.cecurAgents.splice(0);
  const ingestKey = 'cs3k_hydration-test-key';
  const queries: string[] = [];
  const query = async (text: string) => {
    queries.push(text);
    if (text.includes('FROM cs3.agents')) return { rows: [{ data: agent }] };
    if (text.includes('FROM cs3.enrollments')) {
      return {
        rows: [
          {
            agent_id: agent.id,
            token_sha256: 'a'.repeat(64),
            key_sha256: sha256(ingestKey),
            batch_id: 'enr-claimed',
            requested_by: 'admin',
            expires_at: String(now + 60_000),
            claimed_at: String(now - 30_000),
          },
          {
            agent_id: 'cecur-ag-pending',
            token_sha256: 'b'.repeat(64),
            key_sha256: null,
            batch_id: 'enr-pending',
            requested_by: 'admin',
            expires_at: String(now + 60_000),
            claimed_at: null,
          },
        ],
      };
    }
    throw new Error(`Unexpected query: ${text}`);
  };

  assert.deepEqual(await hydrateFleet(query), { agents: 1, enrollments: 2 });
  assert.equal(db.cecurAgents[0]?.id, agent.id);
  assert.deepEqual(fleetSummary(), {
    total: 1,
    byStatus: { active: 1 },
    pendingEnrollments: 1,
  });

  const duplicate = await bulkEnroll({
    agents: [{ hostname: agent.hostname, platform: 'linux' }],
    defaultGroups: [],
    ttlHours: 24,
    dryRun: true,
    requestedBy: 'admin',
  });
  assert.equal(duplicate.results[0]?.status, 'duplicate', 'hydrated inventory must prevent duplicate enrollment');

  let authenticated = false;
  let responseStatus = 0;
  const req = {
    header: (name: string) => (name === 'x-api-key' ? ingestKey : undefined),
  } as unknown as Request;
  const res = {
    status(code: number) {
      responseStatus = code;
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;
  await requireAgentKey(req, res, () => {
    authenticated = true;
  });

  assert.equal(responseStatus, 0);
  assert.equal(authenticated, true);
  assert.equal((req as any).ingestAgentId, agent.id);
  assert.equal(queries.length, 2, 'the hydrated key index should avoid another database lookup');
});
