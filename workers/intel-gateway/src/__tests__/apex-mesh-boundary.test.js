import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  beginApexMeshBoundary,
  completeApexMeshBoundary,
  __test,
} from '../apex-mesh-boundary.js';

const VALID_KEY = 'sentinel-production-key-material-1234567890';

function request(requestId = 'sentinel-req-1', body = { ioc_value: '8.8.8.8', ioc_type: 'ipv4' }) {
  return new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': VALID_KEY,
      'X-Request-ID': requestId,
    },
    body: JSON.stringify(body),
  });
}

function envFor(record = { tier: 'PRO', customer_id: 'cust-1', subscription_status: 'active' }, mutate = null) {
  const calls = [];
  let executionId = null;
  return {
    calls,
    env: {
      APEX_MESH_SERVICE_KEY: 'm'.repeat(64),
      API_KEYS_KV: {
        async get(key, type) {
          assert.equal(key, VALID_KEY);
          assert.equal(type, 'json');
          return record;
        },
      },
      SECURITY_HUB_KV: { async get() { return null; } },
      APEX_MESH: {
        async fetch(req) {
          const path = new URL(req.url).pathname;
          const body = JSON.parse(await req.text());
          calls.push({ path, body, authorization: req.headers.get('authorization') });
          if (path === '/v1/mesh/admit') {
            executionId = 'e'.repeat(64);
            const payload = {
              version: 'cdb.mesh.v1',
              execution_id: executionId,
              tenant_id: body.tenant_id,
              mission_id: body.mission_id,
              correlation_id: body.correlation_id,
              capability: body.capability,
              state: 'admitted',
            };
            return Response.json(mutate?.('admit', payload) ?? payload);
          }
          if (path === '/v1/mesh/complete') {
            const payload = {
              version: 'cdb.mesh.v1',
              execution_id: executionId,
              mission_id: body.mission_id,
              state: body.outcome,
            };
            return Response.json(mutate?.('complete', payload) ?? payload);
          }
          return Response.json({ error: 'unexpected' }, { status: 404 });
        },
      },
    },
  };
}

test('only POST /api/intel/correlate is mesh-bound', () => {
  assert.equal(__test.routePolicy(request()).capability, 'intel.enrich');
  assert.equal(__test.routePolicy(new Request('https://intel.cyberdudebivash.com/api/intel/correlate')), null);
  assert.equal(__test.routePolicy(new Request('https://intel.cyberdudebivash.com/api/search', { method: 'POST' })), null);
});

test('server API-key record is the commercial source of truth', async () => {
  const principal = await __test.resolveMeshPrincipal(request('commercial', {
    ioc_value: '8.8.8.8',
    tier: 'MSSP',
    customer_id: 'attacker',
  }), envFor({ tier: 'ENTERPRISE', customer_id: 'cust-real', subscription_status: 'active' }).env);
  assert.deepEqual(principal, { sub: 'cust-real', tier: 'ENTERPRISE', source: 'api_key' });
});

function jwtFor(payload, secret) {
  const enc = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = enc({ alg: 'HS256', typ: 'JWT' });
  const body = enc(payload);
  const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

test('billing refund deny marker invalidates an already-issued mesh JWT immediately', async () => {
  const secret = 'j'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const token = jwtFor({ iss: 'SENTINEL-APEX', sub: 'cust-refunded', tier: 'PRO',
    iat: now - 30, exp: now + 3600 }, secret);
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, 'X-Request-ID': 'jwt-refund-deny' },
    body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
  });
  const env = {
    CDB_JWT_SECRET: secret,
    SECURITY_HUB_KV: { async get() { return null; } },
    API_KEYS_KV: { async get(key) { return key === 'jwt_deny:cust-refunded' ? '{"reason":"refunded"}' : null; } },
  };
  await assert.rejects(() => __test.resolveMeshPrincipal(req, env), (err) => err?.code === 'mesh_subscription_denied' && err?.status === 403);
});


test('Mesh accepts canonical unexpired audience-free login JWTs', async () => {
  const secret = 'j'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: 'SENTINEL-APEX', sub: 'cust-real', tier: 'PRO',
    iat: now - 60, exp: now + 3600 };
  const token = jwtFor(payload, secret);
  assert.deepEqual(await __test.verifyJwtHs256(token, secret), payload);
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ioc_value: '8.8.8.8' }),
  });
  const env = {
    CDB_JWT_SECRET: secret,
    SECURITY_HUB_KV: { async get() { return null; } },
    API_KEYS_KV: { async get() { return null; } },
  };
  assert.deepEqual(await __test.resolveMeshPrincipal(req, env),
    { sub: 'cust-real', tier: 'PRO', source: 'jwt' });
});

test('Mesh rejects non-general-audience, unbounded and malformed JWTs before admission', async () => {
  const secret = 'j'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const base = { iss: 'SENTINEL-APEX', sub: 'cust-real', tier: 'PRO',
    iat: now - 60, exp: now + 3600 };
  const invalid = [
    { ...base, aud: 'cdb-watchdog' },
    { ...base, aud: ['some-other-app'] },
    { ...base, iss: 'cdb-apex-mesh' },
    { ...base, iss: 'evil' },
    { ...base, iss: undefined },
    { ...base, exp: undefined },
    { ...base, exp: now - 1 },
    { ...base, exp: now },
    { ...base, exp: String(now + 3600) },
    { ...base, iat: undefined },
    { ...base, iat: now + 120 },
    { ...base, exp: now + 86402 },
  ];
  for (const payload of invalid) {
    const token = jwtFor(payload, secret);
    assert.equal(await __test.verifyJwtHs256(token, secret), null, JSON.stringify(payload));
  }
  assert.equal(await __test.verifyJwtHs256('x'.repeat(8193), secret), null);
  const token = jwtFor({ ...base, aud: 'cdb-watchdog' }, secret);
  let reads = 0;
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ioc_value: '8.8.8.8' }),
  });
  const env = {
    CDB_JWT_SECRET: secret,
    SECURITY_HUB_KV: { async get() { reads++; return null; } },
    API_KEYS_KV: { async get() { reads++; return null; } },
  };
  const result = await beginApexMeshBoundary(req, env);
  assert.equal(result.blockedResponse.status, 401);
  assert.equal(reads, 0, 'invalid token must not spend a remote key-value read');
});

test('Mesh JWT fails closed when revocation or billing authority is unavailable', async () => {
  const secret = 'j'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const token = jwtFor({ iss: 'SENTINEL-APEX', sub: 'cust-real', tier: 'PRO',
    iat: now - 30, exp: now + 3600 }, secret);
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ioc_value: '8.8.8.8' }),
  });
  for (const env of [
    { CDB_JWT_SECRET: secret, API_KEYS_KV: { async get() { return null; } } },
    { CDB_JWT_SECRET: secret, SECURITY_HUB_KV: { async get() { return null; } } },
  ]) {
    await assert.rejects(() => __test.resolveMeshPrincipal(req, env),
      err => err?.code === 'mesh_auth_service_unavailable' && err?.status === 503);
  }
});

function strongAuthAuthority(status = 'active', unavailable = false) {
  let reads = 0;
  const binding = {
    idFromName(name) { return name; },
    get() {
      return {
        async fetch() {
          reads++;
          if (unavailable) throw new Error('strong authority unavailable');
          return Response.json({ ok: true, state: { status } });
        },
      };
    },
  };
  return { binding, get reads() { return reads; } };
}

test('strongly suspended customer JWT is rejected before private Mesh compute', async () => {
  const secret = 'j'.repeat(64);
  const now = Math.floor(Date.now() / 1000);
  const token = jwtFor({ iss: 'SENTINEL-APEX', sub: 'cust-suspended',
    tier: 'PRO', iat: now - 30, exp: now + 3600 }, secret);
  const authority = strongAuthAuthority('suspended');
  const fixture = envFor();
  fixture.env.CDB_JWT_SECRET = secret;
  fixture.env.AUTH_STRONG_CONSISTENCY_ENABLED = 'true';
  fixture.env.GUMROAD_PROVISIONING_LOCK = authority.binding;
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` },
    body: JSON.stringify({ ioc_value: '8.8.8.8' }),
  });
  const result = await beginApexMeshBoundary(req, fixture.env);
  assert.equal(result.blockedResponse.status, 403);
  assert.equal((await result.blockedResponse.json()).error, 'mesh_subscription_denied');
  assert.equal(authority.reads, 1);
  assert.equal(fixture.calls.length, 0);
});

test('strongly revoked API key is rejected before Mesh admission', async () => {
  const fixture = envFor();
  const authority = strongAuthAuthority('revoked');
  fixture.env.AUTH_STRONG_CONSISTENCY_ENABLED = 'true';
  fixture.env.GUMROAD_PROVISIONING_LOCK = authority.binding;
  const result = await beginApexMeshBoundary(request('strong-deny'), fixture.env);
  assert.equal(result.blockedResponse.status, 403);
  assert.equal((await result.blockedResponse.json()).error, 'mesh_subscription_denied');
  assert.equal(authority.reads, 2);
  assert.equal(fixture.calls.length, 0);
});

test('strongly reactivated customer overrides eventually-consistent stale KV status', async () => {
  const fixture = envFor({ tier: 'PRO', customer_id: 'cust-1',
    subscription_status: 'suspended' });
  const authority = strongAuthAuthority('active');
  fixture.env.AUTH_STRONG_CONSISTENCY_ENABLED = 'true';
  fixture.env.GUMROAD_PROVISIONING_LOCK = authority.binding;
  const result = await beginApexMeshBoundary(request('strong-reactivated'), fixture.env);
  assert.ok(result.session, 'strong customer authority must override stale KV status');
  assert.equal(authority.reads, 2);
  assert.equal(fixture.calls.length, 1);
});

test('strong authority outage rejects admission rather than falling back to KV', async () => {
  const fixture = envFor();
  fixture.env.AUTH_STRONG_CONSISTENCY_ENABLED = 'true';
  fixture.env.GUMROAD_PROVISIONING_LOCK = strongAuthAuthority('active', true).binding;
  const result = await beginApexMeshBoundary(request('strong-unavailable'), fixture.env);
  assert.equal(result.blockedResponse.status, 503);
  assert.equal((await result.blockedResponse.json()).error, 'mesh_auth_service_unavailable');
  assert.equal(fixture.calls.length, 0);
});

test('strong authority remains zero-spend on default disabled flag', async () => {
  const fixture = envFor();
  const authority = strongAuthAuthority('suspended');
  fixture.env.AUTH_STRONG_CONSISTENCY_ENABLED = 'false';
  fixture.env.GUMROAD_PROVISIONING_LOCK = authority.binding;
  const result = await beginApexMeshBoundary(request('strong-off'), fixture.env);
  assert.ok(result.session);
  assert.equal(authority.reads, 0, 'disabled control must not make a paid Durable Object request');
});

test('FREE credentials are rejected before a mesh reservation', async () => {
  const fixture = envFor({ tier: 'FREE', customer_id: 'free-1', subscription_status: 'active' });
  const result = await beginApexMeshBoundary(request('free-denied'), fixture.env);
  assert.equal(result.blockedResponse.status, 403);
  assert.equal((await result.blockedResponse.json()).error, 'mesh_paid_tier_required');
  assert.equal(fixture.calls.length, 0);
});

test('cancelled and expired credentials are rejected before mesh admission', async () => {
  for (const status of ['cancelled', 'expired']) {
    const fixture = envFor({ tier: 'PRO', customer_id: 'cust-1', subscription_status: status });
    const result = await beginApexMeshBoundary(request(`deny-${status}`), fixture.env);
    assert.equal(result.blockedResponse.status, 403);
    assert.match((await result.blockedResponse.json()).error, /subscription_/);
    assert.equal(fixture.calls.length, 0);
  }
});

test('same logical request ID produces the same tenant and mission identity', async () => {
  const firstFixture = envFor();
  const secondFixture = envFor();
  const first = await beginApexMeshBoundary(request('retry-key'), firstFixture.env);
  const second = await beginApexMeshBoundary(request('retry-key'), secondFixture.env);
  assert.equal(first.session.missionId, second.session.missionId);
  assert.equal(first.session.tenantId, second.session.tenantId);
  assert.equal(firstFixture.calls[0].body.correlation_id, 'retry-key');
  assert.equal(firstFixture.calls[0].body.local_plan, 'PRO');
  assert.match(firstFixture.calls[0].body.input_sha256, /^[0-9a-f]{64}$/);
});

test('different idempotency keys cannot alias to one mission', async () => {
  const tenant = 'sentinel-' + 'a'.repeat(48);
  const one = await __test.missionIdFor(tenant, 'request-one', request(), 'intel.enrich');
  const two = await __test.missionIdFor(tenant, 'request-two', request(), 'intel.enrich');
  assert.notEqual(one, two);
});

test('malformed correlation input is rejected before auth/metering', async () => {
  const fixture = envFor();
  const result = await beginApexMeshBoundary(request('bad-input', { ioc_type: 'ipv4' }), fixture.env);
  assert.equal(result.blockedResponse.status, 400);
  assert.equal((await result.blockedResponse.json()).error, 'ioc_value_required');
  assert.equal(fixture.calls.length, 0);
});

test('admission metadata mismatch fails closed', async () => {
  const fixture = envFor(undefined, (kind, payload) => kind === 'admit' ? { ...payload, tenant_id: 'sentinel-wrong' } : payload);
  const result = await beginApexMeshBoundary(request('bad-admit'), fixture.env);
  assert.equal(result.blockedResponse.status, 503);
});

test('actual gateway response is hashed and certified server-side', async () => {
  const fixture = envFor();
  const begin = await beginApexMeshBoundary(request('certify-1'), fixture.env);
  const original = Response.json({ status: 'ok', verdict: 'malicious', match_count: 2 }, { status: 200 });
  const certified = await completeApexMeshBoundary(begin.session, original, fixture.env);

  assert.equal(certified.status, 200);
  assert.equal(certified.headers.get('X-CDB-Mesh-Certified'), 'true');
  assert.equal(certified.headers.get('X-CDB-Mesh-Execution'), 'e'.repeat(64));
  assert.equal(fixture.calls[1].path, '/v1/mesh/complete');
  assert.equal(fixture.calls[1].body.outcome, 'succeeded');
  assert.match(fixture.calls[1].body.output_sha256, /^[0-9a-f]{64}$/);
});

test('completion must bind to the admitted execution', async () => {
  const fixture = envFor(undefined, (kind, payload) => kind === 'complete' ? { ...payload, execution_id: 'f'.repeat(64) } : payload);
  const begin = await beginApexMeshBoundary(request('certify-2'), fixture.env);
  const result = await completeApexMeshBoundary(begin.session, Response.json({ status: 'ok' }), fixture.env);
  assert.equal(result.status, 503);
  assert.equal((await result.json()).error, 'agent_mesh_unavailable');
});

test('an admission missing a bounded execution identifier cannot reserve a Mesh mission', async () => {
  for (const badId of ['', 'x'.repeat(129), 'bad id', 'bad\\nidentifier']) {
    const fixture = envFor(undefined, (kind, payload) =>
      kind === 'admit' ? { ...payload, execution_id: badId } : payload);
    const begin = await beginApexMeshBoundary(request('admit-bad-id'), fixture.env);
    assert.equal(begin.blockedResponse.status, 503, JSON.stringify(badId));
    assert.equal((await begin.blockedResponse.json()).error, 'agent_mesh_unavailable');
    assert.equal(fixture.calls.length, 1, 'must not proceed to complete a rejected admission');
  }
});

test('Mesh completion acknowledgment cannot contradict a successful customer outcome', async () => {
  const fixture = envFor(undefined, (kind, payload) =>
    kind === 'complete' ? { ...payload, state: 'rejected' } : payload);
  const begin = await beginApexMeshBoundary(request('completion-denied'), fixture.env);
  const original = Response.json({ status: 'ok', verdict: 'malicious' }, { status: 200 });
  const result = await completeApexMeshBoundary(begin.session, original, fixture.env);
  assert.equal(result.status, 503);
  assert.equal(result.headers.get('X-CDB-Mesh-Certified'), null);
  assert.equal((await result.json()).error, 'agent_mesh_unavailable');
  assert.equal(fixture.calls[1].body.outcome, 'succeeded');
});

test('Mesh must certify a failed response only when its own completion agrees', async () => {
  const mismatch = envFor(undefined, (kind, payload) =>
    kind === 'complete' ? { ...payload, state: 'succeeded' } : payload);
  const beginMismatch = await beginApexMeshBoundary(request('failure-mismatch'), mismatch.env);
  const failed = Response.json({ error: 'not_authorized' }, { status: 403 });
  const rejected = await completeApexMeshBoundary(beginMismatch.session, failed, mismatch.env);
  assert.equal(rejected.status, 503);
  assert.equal(rejected.headers.get('X-CDB-Mesh-Certified'), null);
  assert.equal(mismatch.calls[1].body.outcome, 'failed');

  const accepted = envFor();
  const beginAccepted = await beginApexMeshBoundary(request('failure-matched'), accepted.env);
  const certified = await completeApexMeshBoundary(beginAccepted.session,
    Response.json({ error: 'not_authorized' }, { status: 403 }), accepted.env);
  assert.equal(certified.status, 403);
  assert.equal(certified.headers.get('X-CDB-Mesh-Certified'), 'true');
  assert.equal(accepted.calls[1].body.outcome, 'failed');
});

test('service token identifies only sentinel-apex with mesh.invoke scope', async () => {
  const token = await __test.issueServiceToken({ APEX_MESH_SERVICE_KEY: 's'.repeat(64) }, 'sentinel-' + '1'.repeat(48), 1000);
  const [encoded] = token.split('.');
  const raw = new TextDecoder().decode(Uint8Array.from(encoded.match(/../g).map(v => Number.parseInt(v, 16))));
  const payload = JSON.parse(raw);
  assert.equal(payload.iss, 'cdb-apex-mesh');
  assert.equal(payload.sub, 'sentinel-apex');
  assert.deepEqual(payload.scopes, ['mesh.invoke']);
  assert.equal(payload.exp - payload.iat, 300);
});
