import assert from 'node:assert/strict';
import { test } from 'node:test';
import { harness, PRO_KEY } from './watchdog-harness.js';
function privatePolicy(res) {
  assert.equal(res.headers.get('cache-control'), 'private, no-store');
  for (const name of ['CDN-Cache-Control','Cloudflare-CDN-Cache-Control','Surrogate-Control','Expires']) assert.equal(res.headers.has(name),false);
}
test('P0 real router: issuance, rotation, validation and denied admin response are private', async () => {
  const originalFetch=globalThis.fetch, originalCaches=globalThis.caches;
  try {
    const h=harness();
    const admin='admin-test-secret'; // synthetic, in-memory harness only
    const created=await h.call('POST','/api/admin/keys',{admin,body:{customer_id:'qa-cache-test-only',tier:'PRO',label:'synthetic',expires_in_days:1,managed_tenants:[]}});
    assert.equal(created.status,201); privatePolicy(created);
    assert.ok(/^cdb_pro_[0-9a-f]{40}$/.test(created.body?.key));
    const validated=await h.call('GET','/api/auth/validate',{key:created.body.key});
    assert.equal(validated.status,200); privatePolicy(validated);
    const rotated=await h.call('POST','/api/admin/keys/'+PRO_KEY+'/rotate',{admin});
    assert.equal(rotated.status,201); privatePolicy(rotated);
    assert.ok(/^cdb_pro_[0-9a-f]{40}$/.test(rotated.body?.new_key));
    const denied=await h.call('POST','/api/admin/keys',{body:{}});
    assert.ok([401,403].includes(denied.status)); privatePolicy(denied);
    assert.equal(h.net.posts.length,0);
  } finally { globalThis.fetch=originalFetch;globalThis.caches=originalCaches; }
});

test('P0 successful authenticated latest aliases explicitly private', async () => {
  const { feedObject, FEED_ITEMS } = await import('./watchdog-harness.js');
  const originalFetch=globalThis.fetch, originalCaches=globalThis.caches;
  try {
    const pub=feedObject(FEED_ITEMS);
    const paid={...pub,items:pub.items.map(item=>({...item,report_url:'https://example.invalid/reports/test'}))};
    const h=harness({feed:pub});
    const read=h.env.INTEL_R2.get;
    h.env.INTEL_R2.get=async key=>key==='api/v1/intel/latest_pro.json'?{text:async()=>JSON.stringify(paid),json:async()=>structuredClone(paid)}:read(key);
    for (const path of ['/api/v1/intel/latest.json','/latest.json']) {
      const response=await h.call('GET',path,{key:PRO_KEY});
      assert.equal(response.status,200); privatePolicy(response);
      assert.equal(response.body.items[0].report_url,'https://example.invalid/reports/test');
    }
    assert.equal(h.net.posts.length,0);
  } finally { globalThis.fetch=originalFetch;globalThis.caches=originalCaches; }
});
