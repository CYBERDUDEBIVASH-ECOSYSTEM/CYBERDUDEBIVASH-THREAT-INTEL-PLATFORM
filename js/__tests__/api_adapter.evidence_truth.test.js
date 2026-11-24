import assert from "node:assert/strict";
import { test } from "node:test";
import Adapter from "../api_adapter.js";

// P0 customer trust: SOC rank is not proof of exploitation or compromise.
test("P0 priority without incident evidence does not invent active exploitation", () => {
  const v = Adapter.buildAiVerdict("", "CRITICAL", "P0", "Vulnerability", 95);
  assert.match(v, /P0 PRIORITY REVIEW/);
  assert.match(v, /verify current CISA KEV/i);
  assert.doesNotMatch(v, /confirmed active exploitation|compromise confirmed|activate incident response immediately/i);
  assert.doesNotMatch(v, /patch within \d+|within \d+ hours/i);
  assert.doesNotMatch(v, /High-confidence intelligence basis/);
});

test("every SOC priority retains triage rank without default customer deadlines", () => {
  for (const priority of ["P0", "P1", "P2", "P3", "P4", "UNKNOWN"]) {
    const result = Adapter.buildAiVerdict("", "CRITICAL", priority, "default", 0);
    assert.match(result, /No source-grounded per-advisory AI narrative/);
    assert.match(result, /evidence|exposure|verification|review|monitor/i);
    assert.doesNotMatch(result, /confirmed active exploitation|within 4 hours|30-day SLA|no immediate action required/i);
    assert.doesNotMatch(result, /High-confidence intelligence basis/);
  }
});

test("preserves a real per-advisory summary and appends evidence caveat", () => {
  const summary = "Source report discusses a potentially affected product.";
  const v = Adapter.buildAiVerdict(summary, "HIGH", "P1", "Vulnerability", 84);
  assert.ok(v.startsWith(summary));
  assert.match(v, /Recorded model confidence indicator: 84\/100/);
  assert.match(v, /not independently verified/i);
  assert.match(v, /P1 URGENT REVIEW/);
});

test("paywall teaser marker remains exact and never appends operational assertions", () => {
  const summary = "Source facts [Full AI analysis requires Pro]";
  assert.equal(
    Adapter.buildAiVerdict(summary, "CRITICAL", "P0", "Ransomware", 95),
    summary,
  );
});

test("malformed object-valued text fields never display [object Object]", () => {
  const result = Adapter.normalizeIntelItem({
    id: "intel--trusted-test",
    severity: "HIGH",
    title: { nested: "not-a-title" },
    description: { structured: "not-a-string" },
    source: { name: "not-a-string" },
    source_url: { uri: "https://example.org" },
    report_url: { uri: "https://example.org/report" },
    apex_ai: {
      ai_summary: { body: "never stringify" },
      campaign_id: { id: "never stringify" },
      actor_fingerprint: { value: "never stringify" },
    },
  }, 1);
  assert.equal(result.id, "intel--trusted-test");
  assert.equal(result.title, "Untitled Intelligence Report");
  assert.equal(result.description, "");
  assert.equal(result.source, "");
  assert.equal(result.source_url, "");
  assert.equal(result.report_url, "");
  assert.equal(result.apex_ai.campaign_id, "");
  for (const text of [result.title, result.description, result.source,
    result.source_url, result.report_url, result.ai_verdict,
    result.apex_ai.ai_summary, result.apex_ai.campaign_id]) {
    assert.equal(typeof text, "string");
    assert.doesNotMatch(text, /\[object Object\]/);
  }
});

test("scalar zero, booleans and normal source text retain original representations", () => {
  const item = Adapter.normalizeIntelItem({
    id: "intel--0",
    title: "Ordinary source title",
    description: "Source text",
    source: "NVD",
    actor_tag: 0,
    severity: "LOW",
    apex_ai: { ai_summary: "Source-grounded model text" },
  }, 0);
  assert.equal(item.title, "Ordinary source title");
  assert.equal(item.description, "Source text");
  assert.equal(item.actor_tag, "0");
  assert.equal(item.source, "NVD");
  assert.ok(item.ai_verdict.startsWith("Source-grounded model text"));
});
