"use strict";
// Offline customer-trust contract. This test never reaches production or APIs.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const page = name => fs.readFileSync(path.join(root, name), "utf8");

test("actor marketing does not invent fixed population or universal TTP coverage", () => {
  const html = page("threat-actors.html");
  assert.doesNotMatch(html, /200\+.*?(?:actor|APT)|40\+.*?APT|60\+.*?ransomware/gi);
  assert.doesNotMatch(html, /complete TTP analysis|each SENTINEL APEX threat actor profile includes/gi);
  assert.match(html, /id="cdb-apt-tracked"/);
  assert.match(html, /id="cdb-apt-updated"/);
  assert.match(html, /source.linked|source.backed|source evidence/i);
});

test("threats hub presents measured live data rather than unverifiable headline totals", () => {
  const html = page("threats.html");
  assert.doesNotMatch(html, /200\+ detailed threat actor profiles|60\+ active ransomware group|1M\+.*?IOCs Correlated|15min.*?KEV\/CVE Update Latency/i);
  for (const selector of ["cdb-th-total", "cdb-th-critical", "cdb-th-high", "cdb-th-kev", "cdb-th-updated"])
    assert.ok(html.includes(`id="${selector}"`), `required live counter missing: ${selector}`);
  assert.match(html, /live advisory API/i);
});

test("compliance descriptions do not assert full coverage or obsolete TLP:WHITE", () => {
  const html = page("compliance.html");
  assert.doesNotMatch(html, /Every advisory in SENTINEL APEX is mapped|All threat intelligence published as OASIS STIX|TLP:WHITE/i);
  assert.match(html, /TLP:CLEAR/);
  assert.match(html, /Unmapped advisories remain explicitly unmapped/i);
  assert.match(html, /Validate object schemas/i);
});

test("customer-facing pages keep valid document and navigation structure", () => {
  for (const name of ["threat-actors.html", "threats.html", "compliance.html"]) {
    const html = page(name);
    assert.match(html, /<!doctype html>/i, name);
    assert.match(html, /<html\b/i, name);
    assert.match(html, /<\/html>/i, name);
    assert.match(html, /<main\b|<div class="wrap"|<div class="hero"/i, name);
  }
});
