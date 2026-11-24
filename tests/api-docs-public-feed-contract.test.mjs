import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const html = readFileSync(new URL('../api-docs.html', import.meta.url), 'utf8');

function panel(document, id) {
  const start = document.indexOf('<pre id="' + id + '"');
  assert.ok(start >= 0, 'missing quick-start panel: ' + id);
  const bodyStart = document.indexOf('>', start) + 1;
  const end = document.indexOf('</pre>', bodyStart);
  assert.ok(bodyStart > start && end > bodyStart, 'malformed panel: ' + id);
  return document.slice(bodyStart, end);
}

function contractErrors(document) {
  const errors = [];
  const curl = panel(document, 'qs-curl');
  const python = panel(document, 'qs-python');
  const javascript = panel(document, 'qs-js');
  const go = panel(document, 'qs-go');
  const powershell = panel(document, 'qs-ps');

  if (curl.includes('X-API-Key: YOUR_API_KEY')) errors.push('public cURL asks for a fake key');
  if (!curl.includes('curl -fsS') ||
      !curl.includes('https://intel.cyberdudebivash.com/api/feed?limit=5&severity=CRITICAL')) {
    errors.push('public cURL must call the real keyless feed');
  }
  if (python.includes('headers=headers') || python.includes('headers = {"X-API-Key"')) {
    errors.push('public Python feed sends an API key');
  }
  const publicJs = javascript.split('// Register SIEM webhook')[0];
  if (publicJs.includes("headers: { 'X-API-Key'")) errors.push('public JavaScript feed sends an API key');
  if (go.includes('req.Header.Set("X-API-Key"')) errors.push('public Go feed sends an API key');
  const publicPs = powershell.split('# Pro+ Sigma export')[0];
  if (publicPs.includes('-Headers')) errors.push('public PowerShell feed sends an API key');
  if (!document.includes('Returns a JSON object containing an <code>items</code> array')) {
    errors.push('public response shape incorrectly described');
  }
  if (curl.includes('JSON array of critical advisories with CVSS, EPSS, IOCs, Sigma rules')) {
    errors.push('free response promises paid exports');
  }
  if (python.includes('/feed/sigma') || powershell.includes('/feed/sigma')) {
    errors.push('quick start uses legacy Sigma route');
  }
  if (!python.includes('GET /api/sigma/bulk') || !powershell.includes('GET /api/sigma/bulk')) errors.push('paid Sigma route not documented in both quick starts');
  if (document.includes('/api/v1/export/sigma')) errors.push('unsupported Sigma route documented');
  const sigmaStart = document.indexOf('<h2 id="export-sigma">');
  const sigmaEnd = document.indexOf('<h2 id="export-yara">', sigmaStart);
  const sigma = sigmaStart >= 0 && sigmaEnd > sigmaStart ? document.slice(sigmaStart, sigmaEnd) : '';
  if (!sigma.includes('<strong>/api/sigma/bulk</strong>') ||
      !sigma.includes('/api/sigma/bulk?format=yaml') ||
      !sigma.includes('<td>ndjson</td>') ||
      !sigma.includes('<td>severity</td>') ||
      sigma.includes('<td>limit</td>') ||
      !sigma.includes('up to 50 rules for PRO or up to 2,000 for Enterprise and MSSP')) {
    errors.push('Sigma export contract mismatch');
  }
  return errors;
}

test('all five public quick starts use the verified keyless feed contract', () => {
  assert.deepEqual(contractErrors(html), []);
});

test('a fake public API key or wrong JSON-array claim fails the documentation gate', () => {
  const fakeKey = html.replace('curl -fsS', 'curl -fsS -H "X-API-Key: YOUR_API_KEY"');
  assert.ok(contractErrors(fakeKey).length > 0, 'negative control: fake key');
  const badShape = html.replace('Returns a JSON object containing an <code>items</code> array',
    'Returns a JSON array of advisories');
  assert.ok(contractErrors(badShape).length > 0, 'negative control: wrong envelope');
});

function authenticationErrors(document) {
  const visible = document.replace(/<!--[\s\S]*?-->/g, '');
  const start = visible.indexOf('<h2 id="authentication">');
  const end = visible.indexOf('<h2 id="rate-limits">', start);
  if (start < 0 || end <= start) return ['missing authentication section'];
  const section = visible.slice(start, end);
  const errors = [];
  if (!section.includes('For authenticated API-key routes, pass your key in the <code>X-API-Key</code> header.')) errors.push('API-key header not documented');
  if (!section.includes('Routes that document Bearer-session authentication use the documented session flow.')) errors.push('documented session authentication missing');
  if (!section.includes('Access remains subject to the endpoint-specific subscription and authorization requirements.')) errors.push('entitlement boundary missing');
  if (section.includes('All authenticated endpoints require an API key')) errors.push('universal API-key claim');
  if (!section.includes('https://intel.cyberdudebivash.com/api/account/usage')) errors.push('authenticated example must use the account usage route');
  if (section.includes('https://intel.cyberdudebivash.com/api/feed')) errors.push('keyless feed used as authenticated example');
  return errors;
}

test('authenticated endpoints remain documented separately from Community', () => {
  assert.deepEqual(authenticationErrors(html), []);
  assert.ok(html.includes('Enterprise webhook operations'));
  assert.ok(html.includes('Pro+ Sigma export'));
});

test('authentication gate rejects universal key claims, missing authorization boundaries and keyless examples', () => {
  for (const [before, after] of [
    ['For authenticated API-key routes, pass your key in the <code>X-API-Key</code> header.', 'All authenticated endpoints require an API key'],
    ['Routes that document Bearer-session authentication use the documented session flow.', ''],
    ['Access remains subject to the endpoint-specific subscription and authorization requirements.', ''],
    ['https://intel.cyberdudebivash.com/api/account/usage', 'https://intel.cyberdudebivash.com/api/feed'],
  ]) {
    const mutated = html.replace(before, after);
    assert.notEqual(mutated, html, 'negative control must mutate the document');
    assert.ok(authenticationErrors(mutated).length > 0, before);
  }
});

test('Sigma documentation rejects nonexistent route, unsupported limit and incorrect format defaults', () => {
  for (const [before, after] of [
    ['<strong>/api/sigma/bulk</strong>', '<strong>/api/v1/export/sigma</strong>'],
    ['<td>severity</td>', '<td>limit</td>'],
    ['<td>ndjson</td>', '<td>yaml</td>'],
    ['up to 50 rules for PRO or up to 2,000 for Enterprise and MSSP', 'unlimited rules'],
  ]) {
    const mutated = html.replace(before, after);
    assert.notEqual(mutated, html, 'negative control must mutate the document');
    assert.ok(contractErrors(mutated).length > 0, before);
  }
});
