// =============================================================================
// SENTINEL APEX -- Customer-facing metric truth boundary
// =============================================================================
// CVSS and SENTINEL APEX risk_score are different metrics. This module exists
// to prevent report/UI/decision code from silently substituting one for the
// other. A missing CVSS remains unknown; it is never manufactured from risk.
// =============================================================================

function finiteInRange(value, min, max) {
  if (value === null || value === undefined || value === '') return null;
  // Number(" "), Number(false) and Number([]) all become 0. That silently
  // turns a missing/invalid CVSS or risk score into a measured zero.
  // Accept only finite numeric inputs or explicit decimal numeric strings.
  if (typeof value !== "number" && typeof value !== "string") return null;
  if (typeof value === "string" && !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim())) return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
}

export function explicitCvss(item = {}) {
  // Deliberately excludes _score_details.cvss: legacy governance code can
  // populate that field through a risk_score fallback. Only source-facing
  // CVSS fields are accepted here.
  const candidates = [
    item.cvss_score,
    item.cvss,
    item.cvss_v3,
    item.cvss3_score,
    item.cvss_base_score,
  ];
  for (const value of candidates) {
    const n = finiteInRange(value, 0, 10);
    if (n !== null) return n;
  }
  return null;
}

export function explicitRiskScore(item = {}) {
  const candidates = [item.risk_score, item.threat_score];
  for (const value of candidates) {
    const n = finiteInRange(value, 0, 10);
    if (n !== null) return n;
  }
  return null;
}

export function hasExplicitCvss(item = {}) {
  return explicitCvss(item) !== null;
}

export function metricTruth(item = {}) {
  return {
    cvss: explicitCvss(item),
    risk_score: explicitRiskScore(item),
    cvss_is_explicit: hasExplicitCvss(item),
    risk_is_cvss: false,
  };
}

// Canonical producer contract: severity_epss_truth.py publishes percentage
// points (0..100), never a fractional probability. Undefined means a legacy
// item with no canonical evidence; null means explicit evidence is invalid or
// unknown. Do not fall back to a stale derived value when evidence is present.
export function canonicalEpssPercent(item = {}) {
  const marked = ['epss_pct', 'epss_source', 'epss_cve', 'epss_date'].some(k => Object.hasOwn(item, k)) ||
    (typeof item.epss === 'string' && item.epss.includes('%'));
  if (!marked) return undefined;
  const pct = finiteInRange(item.epss_pct, 0, 100);
  const match = typeof item.epss === 'string' ? item.epss.trim().match(/^(\d{1,3}(?:\.\d+)?)\s*%$/) : null;
  const text = match ? finiteInRange(match[1], 0, 100) : null;
  const score = finiteInRange(item.epss_score, 0, 100);
  const agrees = (a, b) => Math.abs(a - b) <= 0.010000000001;
  if (item.epss_source === 'FIRST.org') {
    if (pct === null) return null;
    if (item.epss_score != null && (score === null || !agrees(score, pct))) return null;
    if (item.epss != null && (text === null || !agrees(text, pct))) return null;
    if (item.epss_cve != null) {
      const ids = [item.cve_id, ...(Array.isArray(item.cve_ids) ? item.cve_ids : [item.cve_ids])];
      if (typeof item.epss_cve !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(item.epss_cve) || !ids.includes(item.epss_cve)) return null;
    }
    if (item.epss_date != null) {
      if (typeof item.epss_date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(item.epss_date)) return null;
      const t = Date.parse(item.epss_date+'T00:00:00Z');
      if (!Number.isFinite(t) || new Date(t).toISOString().slice(0,10) !== item.epss_date) return null;
    }
    return pct;
  }
  if (item.epss_source != null || text === null) return null;
  if (item.epss_score != null && (score === null || !agrees(score, text))) return null;
  if (item.epss_pct != null && (pct === null || !agrees(pct, text))) return null;
  return text;
}
