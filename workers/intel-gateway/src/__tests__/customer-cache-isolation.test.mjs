import assert from "node:assert/strict";
import { test } from "node:test";
import { harness, PRO_KEY, FEED_ITEMS, feedObject } from "./watchdog-harness.js";

// Real Worker and auth/tier routing; only cloud bindings and network are fake.
test("P0 customer cache isolation: warmed FREE then PRO then invalid then FREE", async () => {
  const originalCaches = globalThis.caches;
  const originalFetch = globalThis.fetch;
  try {
    const report = "https://example.invalid/reports/synthetic";
    const publicFeed = feedObject(FEED_ITEMS);
    const proFeed = { ...publicFeed, items: publicFeed.items.map(item => ({ ...item, report_url: report })) };
    const hx = harness({ feed: publicFeed });
    let proReads = 0;
    const read = hx.env.INTEL_R2.get;
    hx.env.INTEL_R2.get = async key => {
      if (key !== "api/v1/intel/latest_pro.json") return read(key);
      proReads++;
      const text = JSON.stringify(proFeed);
      return { text: async () => text, json: async () => JSON.parse(text) };
    };
    const cache = new Map();
    const matches = [], puts = [];
    globalThis.caches = { default: {
      match: async req => { matches.push(req.url); return cache.get(req.url)?.clone(); },
      put: async (req, res) => { puts.push(req.url); cache.set(req.url, res.clone()); },
    }};
    const canonical = "/api/v1/intel/latest.json";
    const alias = "/latest.json";
    for (const path of [canonical, alias]) {
      const url = "https://intel.cyberdudebivash.com" + path;
      const warm = await hx.call("GET", path);
      assert.equal(warm.status, 200);
      assert.equal(warm.body.items[0].report_url, undefined);
      const again = await hx.call("GET", path);
      assert.equal(again.status, 200);
      // Canonical public endpoint must retain its read-budget cache behavior.
      if (path === canonical) assert.ok(cache.has(url), "canonical FREE response must populate cache");
      const m = matches.filter(x => x === url).length;
      const p = puts.filter(x => x === url).length;
      const r = proReads;
      const paid = await hx.call("GET", path, { key: PRO_KEY });
      assert.equal(paid.status, 200);
      assert.equal(paid.body.items[0].report_url, report, "PRO must bypass a warmed anonymous cache");
      assert.ok(proReads > r, "PRO source was read");
      assert.match(paid.headers.get("cache-control") || "", /(?:^|,)\s*no-store\s*(?:,|$)/i);
      assert.equal(matches.filter(x => x === url).length, m, "credential-bearing cache lookup");
      assert.equal(puts.filter(x => x === url).length, p, "credential-bearing cache write");
      // Both public latest aliases must reject a presented invalid key.
      {
        const denied = await hx.call("GET", path, { key: "cdb_pro_synthetic_invalid" });
        assert.equal(denied.status, 401, "invalid key must not hit anonymous cache");
        assert.match(denied.headers.get("cache-control") || "", /(?:^|,)\s*no-store\s*(?:,|$)/i);
        assert.equal(matches.filter(x => x === url).length, m);
        assert.equal(puts.filter(x => x === url).length, p);
      }
      const after = await hx.call("GET", path);
      assert.equal(after.status, 200);
      assert.equal(after.body.items[0].report_url, undefined);
      assert.equal(proReads, r + 1, "anonymous read must not access paid source");
    }
    assert.equal(hx.net.posts.length, 0, "unexpected external network use");
  } finally {
    globalThis.caches = originalCaches;
    globalThis.fetch = originalFetch;
  }
});
