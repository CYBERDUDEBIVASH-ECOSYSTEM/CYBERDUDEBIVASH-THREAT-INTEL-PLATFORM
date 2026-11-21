import test from "node:test";
import assert from "node:assert/strict";
import { denyNonFreshLiveFeed, liveFreshCacheControl, denyNonFreshPremiumManifest, premiumLiveFreshCacheControl } from "../stale-feed-policy.js";

const NOW = Date.parse("2026-10-10T05:00:00Z");
const item = { id: "verified-1", title: "Original advisory", source_url: "https://publisher.example/advisory" };
const feed = (generated_at) => ({ generated_at, count: 1, items: [item] });

test("fresh authoritative feed is not denied", () => {
  assert.equal(denyNonFreshLiveFeed(feed("2026-10-10T04:59:00Z"), NOW), null);
});

test("stale feed is HTTP 503, no-store, and has zero exposed items", () => {
  const original = feed("2026-10-09T05:38:01Z");
  const before = JSON.stringify(original);
  const denial = denyNonFreshLiveFeed(original, NOW);
  assert.equal(denial.status, 503);
  assert.equal(denial.body.freshness_status, "STALE");
  assert.deepEqual(denial.body.items, []);
  assert.equal(denial.body.live_data_available, false);
  assert.match(denial.headers["Cache-Control"], /no-store/);
  assert.equal(JSON.stringify(original), before, "historical archive data must not be mutated");
});

test("missing, malformed, future, and empty input never exposes items", () => {
  for (const input of [null, { items: [item] }, { generated_at: "not-a-date", items: [item] }, feed("2026-10-11T05:00:00Z"), { generated_at: "2026-10-10T04:59:00Z", count: 0, items: [] }]) {
    const denial = denyNonFreshLiveFeed(input, NOW);
    assert.equal(denial.status, 503);
    assert.deepEqual(denial.body.items, []);
  }
});

test("inclusive freshness boundary does not cache stale intelligence", () => {
  assert.equal(denyNonFreshLiveFeed(feed("2026-10-09T23:00:00Z"), NOW), null);
  assert.equal(denyNonFreshLiveFeed(feed("2026-10-09T22:59:59Z"), NOW).status, 503);
});

test("fresh response cache expires strictly before the six-hour boundary", () => {
  const generated = "2026-10-09T23:00:00Z";
  const atNinetySec = Date.parse("2026-10-10T04:58:30.250Z");
  const ctl = liveFreshCacheControl(feed(generated), 120, atNinetySec);
  assert.equal(ctl, "public, max-age=89, must-revalidate");
  assert.equal(liveFreshCacheControl(feed(generated), 120, Date.parse("2026-10-10T04:59:59.750Z")),
    "public, max-age=0, must-revalidate");
  assert.equal(liveFreshCacheControl(feed(generated), 120, Date.parse("2026-10-10T05:00:00.001Z")), "no-store");
});


test("premium: stale canonical feed blocks newer AI summary without exposing the aggregate", () => {
  const canonical = feed("2026-10-09T22:00:00Z");
  const newerSummary = { generated_at: "2026-10-10T04:59:00Z", campaigns: [{ name: "private" }] };
  const denied = denyNonFreshPremiumManifest(canonical, newerSummary, NOW);
  assert.equal(denied.status, 503);
  assert.equal(denied.body.live_data_available, false);
  assert.deepEqual(denied.body.items, []);
  assert.equal(denied.body.campaigns, undefined);
  assert.match(denied.headers["Cache-Control"], /no-store/);
});

test("premium: fresh canonical feed never licenses stale APEX item manifest", () => {
  const newerCanonical = feed("2026-10-10T04:59:00Z");
  const staleApex = feed("2026-10-09T22:59:59Z");
  const denied = denyNonFreshPremiumManifest(newerCanonical, staleApex, NOW);
  assert.equal(denied.status, 503);
  assert.equal(denied.body.reason, "premium_manifest_stale");
  assert.deepEqual(denied.body.items, []);
});

test("premium: missing, invalid and far-future timestamps fail closed", () => {
  const canonical = feed("2026-10-10T04:59:00Z");
  for (const premium of [
    {}, { generated_at: "garbage" },
    { generated_at: "2026-10-11T05:00:00Z" }, null,
  ]) {
    const denied = denyNonFreshPremiumManifest(canonical, premium, NOW);
    assert.equal(denied.status, 503);
    assert.deepEqual(denied.body.items, []);
    assert.equal(premiumLiveFreshCacheControl(canonical, premium, 120, NOW), "no-store");
  }
});

test("premium: both APEX and aggregate AI summary pass only with fresh source", () => {
  const canonical = feed("2026-10-10T04:59:00Z");
  assert.equal(denyNonFreshPremiumManifest(canonical, feed("2026-10-10T04:55:00Z"), NOW), null);
  assert.equal(denyNonFreshPremiumManifest(
    canonical, { generated_at: "2026-10-10T04:54:00Z", campaigns: [] }, NOW), null);
});

test("premium: cache cannot outlive earlier of canonical and derived publication", () => {
  const canonical = feed("2026-10-09T23:00:30Z"); // expires in 30 sec
  const premium = { generated_at: "2026-10-09T23:00:50Z", campaigns: [] };
  assert.equal(premiumLiveFreshCacheControl(canonical, premium, 120, NOW),
    "public, max-age=30, must-revalidate");
  const canonicalLonger = feed("2026-10-09T23:02:00Z");
  const premiumShorter = { generated_at: "2026-10-09T23:00:10Z" }; // expires in 10 sec
  assert.equal(premiumLiveFreshCacheControl(canonicalLonger, premiumShorter, 120, NOW),
    "public, max-age=10, must-revalidate");
});
