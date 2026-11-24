"use strict";
/* P0 dashboard truth: an advisory is not customer financial loss evidence. */
const test = require("node:test");
const assert = require("node:assert/strict");
const adapter = require("../js/api_adapter.js");

const categories = [
  "Remote Code Execution", "Supply Chain Attack", "Ransomware",
  "Phishing", "Vulnerability", "Malware", "Threat Intelligence", "Unknown",
];

test("every legacy category and severity keeps a stable non-fabricated impact shape", () => {
  for (const category of categories) {
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      const result = adapter.buildBusinessImpact(category, category, severity);
      assert.deepEqual(Object.keys(result).sort(), [
        "compliance_exposure", "customer_impact", "financial_risk",
        "infrastructure_risk", "operational_impact", "severity",
      ].sort());
      assert.equal(result.severity, severity);
      assert.match(result.financial_risk, /NOT ASSESSED/);
      assert.match(result.customer_impact, /UNKNOWN/);
      assert.match(result.compliance_exposure, /NOT DETERMINED/);
      assert.match(result.operational_impact, /POTENTIAL IMPACT ONLY/);
      for (const val of Object.values(result)) {
        assert.doesNotMatch(val, /\$[0-9]|\d+M\+|breach notification obligations triggered|customers .*compromised/i);
      }
    }
  }
});

test("financial or customer exposure cannot be inferred from only severity", () => {
  const critical = adapter.buildBusinessImpact("default", "Threat Intelligence", "CRITICAL");
  const medium = adapter.buildBusinessImpact("default", "Threat Intelligence", "MEDIUM");
  assert.equal(critical.financial_risk, medium.financial_risk);
  assert.equal(critical.customer_impact, medium.customer_impact);
  assert.notEqual(critical.severity, medium.severity);
});

test("financial impact fields remain plain strings, not serialized objects", () => {
  const impact = adapter.buildBusinessImpact(null, null, null);
  for (const key of ["financial_risk", "operational_impact", "compliance_exposure",
                     "customer_impact", "infrastructure_risk"]) {
    assert.equal(typeof impact[key], "string");
    assert.doesNotMatch(impact[key], /\[object Object\]/);
  }
});
