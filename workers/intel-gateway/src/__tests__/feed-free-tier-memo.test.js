import assert from "node:assert/strict";
import { test, after } from "node:test";
import worker from "../index.js";
import { publicationEnvelope } from "../freshness-contract.js";
import { applyTierGateV2 } from "../revenue-enforcement.js";
import { liveFreshCacheControl } from "../stale-feed-policy.js";

// ---------------------------------------------------------------------------
// CPU guardrail for GET /feed.json | /api/feed | /api/feed.json (FREE tier).
//
// Context: Workers CPU is the binding constraint on the shared Cloudflare
// account (zero-overage mandate). A cache-miss on this route re-parsed,
// re-walked (TLP), re-projected and re-serialised the same ~700 KB stored
// document on every request. The FREE-tier items are a pure function of the
// stored bytes, so they are now computed once per R2 object version (etag)
// per isolate.
//
// Two groups of tests:
//   [behavior] must pass on BOTH the pre-change and the post-change handler.
//              They compare the HTTP response against an oracle that composes
//              the original steps from the same helper functions, so any
//              drift in bytes, status or Cache-Control fails the build.
//   [memo]     pin the optimisation itself and its safety invariants.
// ---------------------------------------------------------------------------

const NOW = Date.parse("2026-11-23T14:00:00Z");
const realNow = Date.now;
const clock = (t) => { Date.now = () => t; };
after(() => { Date.now = realNow; });

const KEY = "api/v1/intel/latest.json";
const iso = (t) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");

function item(n, extra = {}) {
  return {
    id: `intel--memo-${n}`, title: `Memo test advisory ${n}`, severity: n % 2 ? "HIGH" : "CRITICAL", cvss: 7.5 + (n % 3) / 10,
    tlp: "TLP:CLEAR", source: "unit-test", description: "synthetic advisory body ".repeat(20),
    iocs_by_type: { domain: [`example-${n}.invalid`], ip: [`192.0.2.${n % 250}`] }, ...extra,
  };
}
const doc = (n = 40, over = {}) => ({ schema_version: "1.0", generated_at: iso(NOW - 600_000), count: n, items: Array.from({ length: n }, (_, i) => item(i)), ...over });

function fakeKV(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    get: async (k, o) => { const v = m.get(k); if (v === undefined) return null; return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v; },
    put: async (k, v) => { m.set(k, v); }, delete: async (k) => { m.delete(k); }, list: async () => ({ keys: [], list_complete: true }),
  };
}

const PRO_KEY = "cdb_pro_test_feedmemo0123456789abcdef012345";
let ip = 0;
function gateway({ stored, etag = null, withHead = true }) {
  const counts = { get: 0, head: 0 };
  let current = { stored, etag };
  const r2 = {
    get: async (k) => {
      if (k !== KEY) return null;
      counts.get++;
      const text = typeof current.stored === "string" ? current.stored : JSON.stringify(current.stored);
      return current.etag ? { etag: current.etag, text: async () => text } : { text: async () => text };
    },
  };
  if (withHead) r2.head = async (k) => { counts.head++; if (withHead === "throws") throw new Error("head unavailable"); return k === KEY && current.etag ? { etag: current.etag } : null; };
  const env = {
    INTEL_R2: r2, RATE_LIMIT_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    API_KEYS_KV: fakeKV({ [PRO_KEY]: JSON.stringify({ tier: "PRO", customer_id: "cust_feed_memo", status: "active" }) }),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } }; // no edge cache: always reach the handler
  const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
  const call = async (path = "/feed.json", headers = {}) => {
    ip++;
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, { headers: { "cf-connecting-ip": `198.51.${(ip >> 8) & 255}.${ip & 255}`, ...headers } }), env, ctx);
    await Promise.allSettled(waits);
    return { status: res.status, text: await res.text(), cc: res.headers.get("cache-control"), ttl: res.headers.get("x-sentinel-edge-ttl"), ct: res.headers.get("content-type") };
  };
  return { call, counts, set: (next) => { current = next; } };
}

// Oracle: the original composition of the handler for an anonymous (FREE) caller, built from the same helpers.
function oracle(stored, nowMs) {
  const truth = publicationEnvelope(stored, nowMs, 120);
  let data = { ...stored, items: stored.items.map((i) => applyTierGateV2(i, "free", null)) };
  data = { ...data, ...truth.fields };
  return { body: JSON.stringify(data), cc: liveFreshCacheControl(data, 120) };
}

for (const path of ["/feed.json", "/api/feed.json", "/api/feed"]) {
  test(`[behavior] ${path}: FREE response is byte-identical to the original composition (miss and repeat)`, async () => {
    clock(NOW);
    const stored = doc();
    const { call } = gateway({ stored, etag: `etag-behavior-${path}` });
    const want = oracle(stored, NOW);
    for (let i = 0; i < 2; i++) {
      const r = await call(path);
      assert.equal(r.status, 200);
      assert.equal(r.text, want.body, `body bytes differ on request ${i + 1}`);
      assert.equal(r.cc, want.cc);
      assert.equal(r.ttl, null, "internal edge-TTL header must stay stripped");
      assert.equal(r.ct, "application/json; charset=utf-8");
    }
  });
}

test("[behavior] works with the legacy stub shape (no head(), no etag): identical bytes, no memo", async () => {
  clock(NOW);
  const stored = doc(12);
  const { call, counts } = gateway({ stored, etag: null, withHead: false });
  const want = oracle(stored, NOW);
  const a = await call(); const b = await call();
  assert.equal(a.text, want.body); assert.equal(b.text, want.body);
  assert.equal(counts.get, 2, "without head()/etag every request reads R2, exactly as before");
});

test("[behavior] a stale feed is refused (503) and never served from any memo", async () => {
  const stored = doc(10, { generated_at: iso(NOW - 40 * 3600 * 1000) });
  clock(NOW);
  const { call } = gateway({ stored, etag: "etag-stale-1" });
  const a = await call(); const b = await call();
  assert.equal(a.status, 503); assert.equal(b.status, 503);
  assert.ok(!a.text.includes("intel--memo-0"), "stale intelligence must not leak items");
});

test("[behavior] a TLP-restricted document is refused and is not memoized", async () => {
  clock(NOW);
  const stored = doc(5); stored.items[2] = item(2, { tlp: "TLP:RED", title: "RESTRICTED_FICTIONAL_CANARY" });
  const { call, counts } = gateway({ stored, etag: "etag-red-1" });
  for (let i = 0; i < 2; i++) {
    const r = await call();
    assert.equal(r.status, 503);
    assert.deepEqual(JSON.parse(r.text), { error: "verified_intelligence_unavailable" });
    assert.ok(!r.text.includes("RESTRICTED_FICTIONAL_CANARY"));
  }
  assert.equal(counts.get, 2, "a rejected document must be re-verified every time, never cached as good");
});

test("[behavior] stale AND malformed items: still the stale 503 (freshness verdict precedes projection)", async () => {
  clock(NOW);
  const stored = doc(3, { generated_at: iso(NOW - 40 * 3600 * 1000) }); stored.items[1] = null;
  const { call } = gateway({ stored, etag: "etag-stale-null-1" });
  assert.equal((await call()).status, 503);
});

test("[behavior] fresh AND malformed items: refused (503) exactly as before, nothing memoized", async () => {
  clock(NOW);
  const stored = doc(3); stored.items[1] = null;
  const { call, counts } = gateway({ stored, etag: "etag-fresh-null-1" });
  const a = await call(); const b = await call();
  assert.equal(a.status, 503); assert.equal(b.status, 503);
  assert.ok(!a.text.includes("intel--memo-0"), "a malformed document must not leak items");
  assert.equal(counts.get, 2, "a document that was refused is re-read every time, never cached as good");
});

test("[behavior] PRO callers get the unprojected, private body and never use the memo path", async () => {
  clock(NOW);
  const stored = doc(6);
  const { call, counts } = gateway({ stored, etag: "etag-pro-1" });
  const r = await call("/feed.json", { "X-API-Key": PRO_KEY });
  assert.equal(r.status, 200);
  assert.equal(r.cc, "private, no-store");
  const body = JSON.parse(r.text);
  assert.deepEqual(body.items, stored.items, "paid tier receives the stored items unchanged");
  assert.equal(counts.head, 0, "paid requests must not consult the FREE-tier memo");
});

test("[memo] second FREE request does not re-read or re-parse the stored document", async () => {
  clock(NOW);
  const stored = doc(30);
  const { call, counts } = gateway({ stored, etag: "etag-memo-hit-1" });
  const want = oracle(stored, NOW);
  const a = await call(); const b = await call(); const c = await call();
  assert.equal(a.text, want.body); assert.equal(b.text, want.body); assert.equal(c.text, want.body);
  assert.equal(counts.get, 1, "stored document is read once per etag per isolate");
  assert.equal(counts.head, 3, "one cheap head() per request validates the version");
});

test("[memo] a new R2 version (new etag) invalidates the memo immediately", async () => {
  clock(NOW);
  const v1 = doc(8); const v2 = doc(8, { items: Array.from({ length: 8 }, (_, i) => item(100 + i)) });
  const g = gateway({ stored: v1, etag: "etag-ver-1" });
  assert.equal((await g.call()).text, oracle(v1, NOW).body);
  g.set({ stored: v2, etag: "etag-ver-2" });
  const after2 = await g.call();
  assert.equal(after2.text, oracle(v2, NOW).body);
  assert.ok(after2.text.includes("intel--memo-100") && !after2.text.includes("intel--memo-0\""));
});

test("[memo] the freshness verdict is evaluated per request: a memo hit cannot outlive the freshness window", async () => {
  const stored = doc(10, { generated_at: iso(NOW - 600_000) });
  const { call } = gateway({ stored, etag: "etag-fresh-then-stale-1" });
  clock(NOW);
  assert.equal((await call()).status, 200);
  assert.equal((await call()).status, 200);
  clock(NOW + 40 * 3600 * 1000);
  const late = await call();
  assert.equal(late.status, 503, "same etag, same memo, but time moved: must fail closed");
  assert.ok(!late.text.includes("intel--memo-0"));
});

test("[memo] if head() throws the route still serves correct bytes via the full path", async () => {
  clock(NOW);
  const stored = doc(9);
  const { call, counts } = gateway({ stored, etag: "etag-head-throws-1", withHead: "throws" });
  const want = oracle(stored, NOW).body;
  const a = await call(); const b = await call();
  assert.equal(a.status, 200); assert.equal(a.text, want);
  assert.equal(b.status, 200); assert.equal(b.text, want);
  assert.equal(counts.get, 2, "a failing head() must never be trusted: every request re-reads R2");
});
