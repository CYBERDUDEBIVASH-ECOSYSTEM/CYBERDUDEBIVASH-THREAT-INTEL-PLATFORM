'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'dashboard/enterprise_dashboard.html'), 'utf8');
function pureDashboardFunctions() {
  const start = html.indexOf('function parseManifest(d){');
  const end = html.indexOf('async function fetchWithTimeout(', start);
  assert.ok(start >= 0 && end > start, 'Dashboard parser must be discoverable');
  const ctx = {};
  vm.runInNewContext(html.slice(start, end) + ';this.parseManifest=parseManifest;this.resolveActor=resolveActor;', ctx);
  return ctx;
}
test('real /api/preview response preview.items is correctly recognized', () => {
  const {parseManifest} = pureDashboardFunctions();
  assert.equal(parseManifest({status:'ok',preview:{items:[{id:'intel--1'},{id:'intel--2'}]}}).length, 2);
});
test('authenticated flat feed, malformed preview and absent feed are safe', () => {
  const {parseManifest} = pureDashboardFunctions();
  assert.equal(parseManifest({items:[{id:'full'}]}).length, 1);
  assert.equal(parseManifest({data:{items:[{id:'wrapped'}]}}).length, 1);
  for(const bad of [null, '', {}, {preview:{}}, {preview:{items:{bad:true}}}])
    assert.equal(parseManifest(bad).length, 0);
});
test('no heuristic actor attribution from titles, threat types, or paywalled data', () => {
  const {resolveActor} = pureDashboardFunctions();
  assert.equal(resolveActor({title:'APT29 suspected in bulletin',threat_type:'nation-state'}), 'Unattributed');
  assert.equal(resolveActor({actor_tag:'UNC-CDB-99'}), 'Unattributed');
  assert.equal(resolveActor({actor_tag:'APT29',actor_paywall:{allowed:false}}), 'Unattributed');
  assert.equal(resolveActor({actor_display_name:'APT29',actor_tag:'UNC-UNKNOWN'}), 'APT29');
});
test('no stale raw GitHub fallback and no unconditional CONNECTED claim', () => {
  assert.doesNotMatch(html, /raw\.githubusercontent\.com/i);
  assert.doesNotMatch(html, /310\+ advisories/i);
  assert.doesNotMatch(html, /CONNECTED &#8212; CYBERDUDEBIVASH SENTINEL APEX/);
  assert.match(html, /LIVE FEED UNAVAILABLE/);
  assert.match(html, /STATE\.manifest=\[\];STATE\.feedLoaded=false/);
});
test('paid actor registry uses credential headers and fails closed on access denial', () => {
  assert.match(html, /BASE\+'\/api\/actors\?limit=100'/);
  assert.match(html, /resp\.status===401\|\|resp\.status===403/);
  assert.match(html, /read:actors/);
  assert.match(html, /authHeaders\(\)/);
  assert.doesNotMatch(html, /consoleApiKey'\)\.value=STATE\.apiKey/);
  assert.match(html, /esc\(x\.name\)/);
});
