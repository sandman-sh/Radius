import test from 'node:test';
import assert from 'node:assert/strict';
import { advisoryConfig, scanDependencies } from '../src/advisories.js';
import { buildRemediationPlan } from '../src/remediation.js';

test('advisory scanner exposes the live OSV provider and handles an empty scan', async () => {
  assert.equal(advisoryConfig().source, 'OSV.dev');
  const result = await scanDependencies([]);
  assert.deepEqual(result, { source: 'OSV.dev', scanned: 0, findings: [], skipped: [] });
});

test('npm remediation plan is explicit and reviewable', () => {
  const plan = buildRemediationPlan({ packageName: 'lodash', version: '4.17.20', targetVersion: '4.17.21', ecosystem: 'npm', advisoryId: 'GHSA-example', fileName: 'package-lock.json' });
  assert.equal(plan.status, 'ready-for-review');
  assert.equal(plan.actions[0].command, 'npm install --save-exact lodash@4.17.21');
  assert.deepEqual(plan.files, ['package-lock.json']);
  assert.equal(plan.pullRequest.automaticCreation, false);
});

test('unfixed advisories do not produce a fabricated target version', () => {
  const plan = buildRemediationPlan({ packageName: 'demo', version: '1.0.0', ecosystem: 'pypi', advisoryId: 'OSV-1' });
  assert.equal(plan.status, 'needs-review');
  assert.deepEqual(plan.actions, []);
  assert.match(plan.reason, /fixed version/);
});
