import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACTION_PERMISSIONS, PANEL_PERMISSIONS, isActionAllowed, isPanelAllowed } from '../../server/rbac';

const CURATOR_ACTIONS = ['view_model_registry', 'promote_model'];
const GPU_ACTIONS = ['view_model_registry', 'manage_gpu_capacity'];

test('model_curator can promote models but cannot reseed, run SOAR, scan or administer', () => {
  const allowed = Object.keys(ACTION_PERMISSIONS).filter((a) => isActionAllowed('model_curator', a));
  assert.deepEqual(allowed.sort(), [...CURATOR_ACTIONS].sort());
  for (const a of ['cecur_isolate_host', 'cecur_active_response', 'sensor_reboot', 'run_scan', 'manage_users', 'update_incident']) {
    assert.equal(isActionAllowed('model_curator', a), false, a);
  }
});

test('gpu_capacity_owner manages capacity only; cannot promote models', () => {
  const allowed = Object.keys(ACTION_PERMISSIONS).filter((a) => isActionAllowed('gpu_capacity_owner', a));
  assert.deepEqual(allowed.sort(), [...GPU_ACTIONS].sort());
  assert.equal(isActionAllowed('gpu_capacity_owner', 'promote_model'), false);
});

test('admin is separated from model approval and GPU capacity', () => {
  assert.equal(isActionAllowed('admin', 'promote_model'), false);
  assert.equal(isActionAllowed('admin', 'manage_gpu_capacity'), false);
  assert.equal(isActionAllowed('admin', 'view_model_registry'), true);
});

test('new roles only see overview and audit panels', () => {
  for (const role of ['model_curator', 'gpu_capacity_owner'] as const) {
    const panels = Object.keys(PANEL_PERMISSIONS).filter((p) => isPanelAllowed(role, p));
    assert.deepEqual(panels.sort(), ['audit', 'overview']);
  }
});
