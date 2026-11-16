// P0: production deploy/credential workflows must never run from ordinary pushes.
// Read-only regression: no cloud calls, no secrets, no GitHub API calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve, dirname} from 'node:path';
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const load = name => readFileSync(resolve(repo,'.github','workflows',name),'utf8');

function getTriggers(yaml) {
  const start = yaml.indexOf('\non:\n');
  assert.ok(start !== -1, 'workflow must declare on:');
  const end = yaml.indexOf('\npermissions:\n',start);
  assert.ok(end > start,'workflow trigger must precede permissions:');
  const block = yaml.slice(start + 1, end);
  return [...block.matchAll(/^  ([a-z_]+):/gm)].map(m=>m[1]);
}
function assertManualAuthority(yaml,workflow) {
  assert.deepEqual(getTriggers(yaml),['workflow_dispatch'], workflow+' must be dispatch-only');
  assert.match(yaml,/^      approved_commit_sha:\s*$/m);
  assert.match(yaml,/^        required: true\s*$/m);
  const jobIf = yaml.match(/^    if: \|\n((?:^      .*\n)+)/m);
  assert.ok(jobIf, workflow+': explicit job-level guard required');
  for(const required of [
    "github.event_name == 'workflow_dispatch'",
    "github.ref == 'refs/heads/main'",
    'inputs.approved_commit_sha == github.sha',
    "github.actor != 'github-actions[bot]'"
  ]) assert.ok(jobIf[1].includes(required),workflow+' missing '+required);
  assert.doesNotMatch(jobIf[1], /\|\|/,workflow+': no OR bypass allowed');
}
test('Swarm Worker release is manual-only, approved main SHA',()=>{
  const yaml = load('deploy-swarm-live.yml');
  assertManualAuthority(yaml,'deploy-swarm-live.yml');
  assert.match(yaml,/npm ci --ignore-scripts/);
  assert.match(yaml,/run: npm test/);
  assert.match(yaml,/npm run deploy:dry/);
  assert.match(yaml,/npx wrangler deploy/);
  assert.match(yaml,/Post-deploy certification/);
});
test('Authenticated E2E mission cannot auto-create production credentials',()=>{
  const yaml=load('swarm-v4470-authenticated-e2e-cert.yml');
  assertManualAuthority(yaml,'swarm-v4470-authenticated-e2e-cert.yml');
  assert.match(yaml,/Create short-lived production demo credential/);
  assert.match(yaml,/Post-mission durable evidence certification/);
  assert.match(yaml,/Revoke temporary production credential/);
});
test('Non-mutating Swarm regression remains eligible on PR and push',()=>{
  const yaml=load('swarm-live-regression-gate.yml');
  const triggers=getTriggers(yaml);
  assert.ok(triggers.includes('push'));
  assert.ok(triggers.includes('pull_request'));
  assert.match(yaml,/node --test \.\.\/\.\.\/tests\/p0-swarm-manual-production-authority\.test\.mjs/);
  assert.match(yaml,/npm run deploy:dry/);
  assert.doesNotMatch(yaml,/^\s*run: npx wrangler deploy\s*$/m);
});

function assertLatestMainBeforeProductionWrite(yaml,operationStep,workflow) {
  assert.match(yaml,/^  cancel-in-progress: false$/m,workflow+': in-flight operations must not be canceled');
  assert.match(yaml,/^          ref: \${{ inputs.approved_commit_sha }}$/m,workflow+': checkout must pin approved SHA');
  assert.match(yaml,/^          persist-credentials: false$/m,workflow+': checkout must not persist token');
  const preflight = yaml.indexOf('      - name: "P0 verified current-main production authority (fail closed)"');
  const operation = yaml.indexOf(operationStep);
  assert.ok(preflight >= 0 && operation > preflight,workflow+': current main check must precede operation');
  const guard = yaml.slice(preflight,operation);
  for(const token of [
    'GH_TOKEN: ${{ github.token }}',
    'CDB_APPROVED_SHA: ${{ inputs.approved_commit_sha }}',
    'set -euo pipefail',
    'GITHUB_SHA',
    'git rev-parse HEAD',
    'CURRENT_MAIN_SHA',
    'gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main"',
    'CURRENT_MAIN_SHA" != "$CDB_APPROVED_SHA'
  ]) assert.ok(guard.includes(token),workflow+': missing release invariant '+token);
}

test('Both production workflows serialize dispatch and reauthorize current main immediately before write',()=>{
  assertLatestMainBeforeProductionWrite(load('deploy-swarm-live.yml'),'      - name: "Deploy Worker to Cloudflare (with retry)"','deploy-swarm-live');
  assertLatestMainBeforeProductionWrite(load('swarm-v4470-authenticated-e2e-cert.yml'),'      - name: Create short-lived production demo credential','authenticated-e2e-cert');
  assert.match(load('swarm-v4470-authenticated-e2e-cert.yml'),/^        if: always\(\) && steps.demo_key.outcome != 'skipped'$/m);
});

test('Negative control: accidental push trigger is rejected by manual authority assertions',()=>{
  for(const name of ['deploy-swarm-live.yml','swarm-v4470-authenticated-e2e-cert.yml']) {
    const yaml=load(name);
    const mutation=yaml.replace('  workflow_dispatch:','  push:\n    branches: [main]\n  workflow_dispatch:');
    assert.notEqual(mutation,yaml);
    assert.throws(()=>assertManualAuthority(mutation,name),/dispatch-only/);
  }
});
