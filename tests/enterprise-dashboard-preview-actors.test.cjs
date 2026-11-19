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


test('saved search containing shell-like quotes is never compiled into onclick JavaScript',()=>{
  const start=html.indexOf('function renderSavedSearches(){');
  const end=html.indexOf('function loadSearch(q,f){',start);
  assert.ok(start>=0 && end>start);
  const row={id:123,query:"');alert('XSS');//",filter:"all",results:1,saved:"2026-11-19T00:00:00Z"};
  const host={innerHTML:'',onclick:null};
  const ctx={STATE:{savedSearches:[row]},document:{getElementById:()=>host},
    esc:s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'),
    loadSearch:()=>{},deleteSearch:()=>{}};
  vm.runInNewContext(html.slice(start,end)+';this.renderSavedSearches=renderSavedSearches;',ctx);
  ctx.renderSavedSearches();
  assert.doesNotMatch(host.innerHTML,/onclick=/i);
  assert.ok(host.innerHTML.includes("');alert('XSS');//"),'search text remains readable');
  assert.ok(host.innerHTML.includes('data-search-index="0"'));
  assert.equal(typeof host.onclick,'function');
});
test('live preview loads nested results and API failure clears stale previously visible rows',async()=>{
  const from=html.indexOf('async function loadManifest(){'),to=html.indexOf('function setLoading(on){',from);
  assert.ok(from>=0 && to>from);
  const {parseManifest,resolveActor}=pureDashboardFunctions();
  const ids=['feedSource','lastSync','feedTier'];
  const elements=Object.fromEntries(ids.map(k=>[k,{textContent:''}]));
  let fetched=0,metricUpdates=0;
  const ctx={STATE:{jwtToken:'',apiKey:'',manifest:[{id:'old'}],feedLoaded:true},
    document:{getElementById:k=>elements[k]||{textContent:''}},
    BASE:'https://intel.cyberdudebivash.com',parseManifest,resolveActor,
    fetchWithTimeout:async()=>{fetched++;return {ok:true,json:async()=>({status:'ok',preview:{items:[{id:'fresh',title:'Example',actor_tag:'UNC-UNKNOWN'}],generated_at:'2026-11-19T00:00:00Z'}})};},
    setLoading:()=>{},updateConnectionStatus:()=>{},showMetricsUnavailable:()=>{},
    applyFilters:()=>{},updateMetrics:()=>{metricUpdates++},checkWatchlistAlerts:()=>{},console,Date};
  vm.runInNewContext(html.slice(from,to)+';this.loadManifest=loadManifest;',ctx);
  await ctx.loadManifest();
  assert.equal(ctx.STATE.feedLoaded,true);
  assert.equal(ctx.STATE.manifest.length,1);
  assert.equal(ctx.STATE.manifest[0].id,'fresh');
  assert.equal(ctx.STATE.manifest[0].actor_tag,'Unattributed');
  assert.equal(elements.feedTier.textContent,'Free Preview');
  assert.equal(fetched,1);
  assert.equal(metricUpdates,1);
  ctx.fetchWithTimeout=async()=>{throw new Error('simulated offline');};
  let hidden=0;ctx.showMetricsUnavailable=()=>{hidden++};
  await ctx.loadManifest();
  assert.equal(ctx.STATE.feedLoaded,false);
  assert.equal(ctx.STATE.manifest.length,0);
  assert.equal(hidden,1);
  assert.equal(metricUpdates,1,'unavailable feed must not rewrite zero into numeric KPIs');
});
