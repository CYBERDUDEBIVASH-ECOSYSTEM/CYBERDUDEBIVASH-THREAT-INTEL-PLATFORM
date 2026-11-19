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
  assert.match(html, /BASE\+'\/api\/actors\?limit=200'/);
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
    fetchWithTimeout:async()=>{fetched++;return {ok:true,json:async()=>({status:'ok',preview:{items:[{id:'fresh',title:'Example',actor_tag:'UNC-UNKNOWN',actor_display_name:'Unknown Threat Actor',published_at:'2026-11-18T08:00:00Z'}],generated_at:'2026-11-19T00:00:00Z',freshness_status:'FRESH',publication_state:'fresh',age_seconds:100,max_age_seconds:21600}})};},
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


test('gateway login contract uses implemented /api/auth/login, not missing /api/auth/token',()=>{
  const begin=html.indexOf('async function authenticateKey(){');
  const end=html.indexOf('function clearAuth(){',begin);
  assert.ok(begin>=0&&end>begin);
  const code=html.slice(begin,end);
  assert.match(code,/fetchWithTimeout\(BASE\+'\/api\/auth\/login'/);
  assert.doesNotMatch(code,/\/api\/auth\/token/);
  assert.match(code,/STATE\.jwtToken = d\.token/);
});
test('paid STIX export is server-issued from authenticated TAXII collection only',async()=>{
  const start=html.indexOf('function csvCell(value){');
  const end=html.indexOf('// ── Watchlists ──',start);
  assert.ok(start>=0&&end>start);
  const section=html.slice(start,end);
  assert.doesNotMatch(section,/\[ipv4-addr:value = '0\.0\.0\.0'\]/);
  const files=[],alerts=[],requests=[];
  const payload={type:'bundle',spec_version:'2.1',
    id:'bundle--22e6b438-3d3f-4ea0-8dba-61a9e043e148',
    objects:[{type:'indicator',spec_version:'2.1',id:'indicator--22e6b438-3d3f-4ea0-8dba-61a9e043e148'}]};
  const ctx={
    STATE:{apiKey:'',jwtToken:'',filtered:[{title:'test'}],feedLoaded:true},
    document:{createElement:()=>({click(){}})},
    BASE:'https://intel.cyberdudebivash.com',
    fetchWithTimeout:async(...args)=>{requests.push(args);return {ok:true,status:200,json:async()=>payload}},
    authHeaders:()=>({Authorization:'Bearer fixture'}),
    toast:(message,kind)=>alerts.push({message,kind}),
    URL:{createObjectURL:blob=>{files.push(blob);return 'blob:fixture'},revokeObjectURL:()=>{}},
    Blob:class {constructor(data,opts){this.data=data;this.opts=opts}},
    setTimeout:()=>0,console:{warn:()=>{}}
  };
  vm.runInNewContext(section+';this.exportData=exportData;',ctx);
  await ctx.exportData('stix');
  assert.equal(files.length,0,'no anonymous STIX file should be generated');
  assert.equal(requests.length,0,'anonymous requests should not hit paid TAXII');
  ctx.STATE.jwtToken='signed';
  await ctx.exportData('stix');
  assert.equal(requests.length,1);
  assert.ok(requests[0][0].endsWith('/taxii/collections/sentinel-apex-main/objects/'));
  assert.equal(requests[0][1].headers.Authorization,'Bearer fixture');
  assert.equal(files.length,1);
  assert.equal(JSON.parse(files[0].data[0]).objects.length,1);
  ctx.fetchWithTimeout=async()=>({ok:false,status:403});
  await ctx.exportData('stix');
  assert.equal(files.length,1,'403 must not emit a file');
  ctx.fetchWithTimeout=async()=>({ok:true,status:200,json:async()=>({...payload,objects:[{id:'indicator--invalid',type:'indicator',spec_version:'2.1'}]})});
  await ctx.exportData('stix');
  assert.equal(files.length,1,'invalid server STIX must not emit a file');
});
test('untrusted third-party advisories never trigger CSV formulas or incorrect record separators',()=>{
  const start=html.indexOf('function csvCell(value){');
  const end=html.indexOf('function triggerExportDownload(',start);
  assert.ok(start>=0&&end>start);
  const ctx={};
  vm.runInNewContext(html.slice(start,end)+';this.csvCell=csvCell;',ctx);
  for(const dangerous of ['=SUM(1,2)','+cmd','-2+3','@IMPORTXML','   =SUM(2,4)'])
    assert.ok(ctx.csvCell(dangerous).startsWith('"'+String.fromCharCode(39)));
  assert.equal(ctx.csvCell('Safe advisory'),'"Safe advisory"');
  assert.equal(ctx.csvCell('one\n=2'),'\"one =2\"');
  assert.match(html,/rows\.join\('\\r\\n'\)/,'CSV records must use actual CRLF delimiters');
});
test('watchlist items never enter inline event handlers, and dangerous text stays escaped',()=>{
  const start=html.indexOf('function renderWatchlists(){');
  const end=html.indexOf('// ── Alerts ──',start);
  assert.ok(start>=0&&end>start);
  const widget={innerHTML:'',onclick:null,onkeydown:null};
  const payload="');alert('IOC_XSS');//";
  const state={watchlists:[{id:123,name:'<img src=x onerror=alert(1)>',
    created:'2026-11-19T00:00:00Z',items:[payload]}]};
  const ctx={STATE:state,document:{getElementById:()=>widget},
    esc:value=>String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'),
    addWatchlistItem:()=>{},removeWatchlistItem:()=>{},deleteWatchlist:()=>{}};
  vm.runInNewContext(html.slice(start,end)+';this.renderWatchlists=renderWatchlists;',ctx);
  ctx.renderWatchlists();
  assert.doesNotMatch(widget.innerHTML,/onclick=|onkeydown=/i);
  assert.doesNotMatch(widget.innerHTML,/<img/i);
  assert.match(widget.innerHTML,/&lt;img/);
  assert.ok(widget.innerHTML.includes("');alert('IOC_XSS');//"));
  assert.equal(typeof widget.onclick,'function');
  assert.equal(typeof widget.onkeydown,'function');
});


test('older concurrent feed response cannot replace newer verified source',async()=>{
  const start=html.indexOf('async function loadManifest(){'),end=html.indexOf('function setLoading(on){',start);
  const {parseManifest,resolveActor}=pureDashboardFunctions();
  const state={authEpoch:0,feedRequestId:0,manifest:[],apiKey:'',jwtToken:'',feedLoaded:false};
  let resolveOld,calls=0;
  const old=new Promise(resolve=>{resolveOld=resolve});
  const document={getElementById:()=>({textContent:''})};
  const ctx={STATE:state,document,BASE:'https://intel.cyberdudebivash.com',
    fetchWithTimeout:async()=>++calls===1?old:{ok:true,json:async()=>({preview:{items:[{id:'new'}],generated_at:'2026-11-19T02:22:17Z',freshness_status:'FRESH',publication_state:'fresh',age_seconds:100,max_age_seconds:21600}})},
    authHeaders:()=>({}),parseManifest,resolveActor,setLoading:()=>{},
    updateConnectionStatus:()=>{},showMetricsUnavailable:()=>{},
    applyFilters:()=>{},updateMetrics:()=>{},checkWatchlistAlerts:()=>{},console,Date};
  vm.runInNewContext(html.slice(start,end)+';this.loadManifest=loadManifest;',ctx);
  const first=ctx.loadManifest();
  await Promise.resolve();
  await ctx.loadManifest();
  resolveOld({ok:true,json:async()=>({preview:{items:[{id:'old'}],generated_at:'2026-11-19T02:22:17Z',freshness_status:'FRESH',publication_state:'fresh',age_seconds:100,max_age_seconds:21600}})});
  await first;
  assert.equal(state.manifest.length,1);
  assert.equal(state.manifest[0].id,'new');
});
test('logout invalidates pending token exchange before it can resurrect paid access',async()=>{
  const start=html.indexOf('async function authenticateKey(){'),end=html.indexOf('function authHeaders(){',start);
  assert.ok(start>=0&&end>start);
  const state={apiKey:'',jwtToken:'',authEpoch:0,authAttemptId:0,feedRequestId:0,actorRequestId:0,actorRows:[]};
  const elements=Object.fromEntries(['apiKeyInput','authStatus','clearAuthBtn','feedTier',
    'consoleApiKey','actorRegistryStatus','actorRegistryBody','panel-actors'].map(id=>
    [id,{value:'',textContent:'',innerHTML:'',style:{},classList:{contains:()=>false}}]));
  elements.apiKeyInput.value='cdb_live_test_good_key_123456';
  let resolveLogin;
  const deferred=new Promise(resolve=>{resolveLogin=resolve});
  const ctx={STATE:state,document:{getElementById:k=>elements[k]},BASE:'https://intel.cyberdudebivash.com',
    fetchWithTimeout:async()=>deferred,toast:()=>{},refreshData:()=>{},loadActorRegistry:()=>{}};
  vm.runInNewContext(html.slice(start,end)+';this.authenticateKey=authenticateKey;this.clearAuth=clearAuth;',ctx);
  const login=ctx.authenticateKey();
  await Promise.resolve();
  ctx.clearAuth();
  resolveLogin({ok:true,json:async()=>({token:'old.jwt',tier:'enterprise'})});
  await login;
  assert.equal(state.jwtToken,'');
  assert.equal(state.apiKey,'');
  assert.equal(state.authEpoch,1);
});
test('actor query denies late privileged rows after session generation changes',async()=>{
  const start=html.indexOf('async function loadActorRegistry(){'),end=html.indexOf('// ── Data Loading ──',start);
  const state={apiKey:'',jwtToken:'signed.jwt',authEpoch:0,actorRequestId:0,actorRows:[]};
  const elements={actorRegistryStatus:{textContent:''},actorRegistryBody:{innerHTML:''}};
  let resolveActorQuery;
  const deferred=new Promise(resolve=>{resolveActorQuery=resolve});
  const ctx={STATE:state,document:{getElementById:k=>elements[k]},BASE:'https://intel.cyberdudebivash.com',
    fetchWithTimeout:async()=>deferred,authHeaders:()=>({Authorization:'Bearer signed.jwt'}),esc:String};
  vm.runInNewContext(html.slice(start,end)+';this.loadActorRegistry=loadActorRegistry;',ctx);
  const request=ctx.loadActorRegistry();
  await Promise.resolve();
  state.jwtToken='';state.authEpoch++;state.actorRequestId++;
  elements.actorRegistryBody.innerHTML='Session cleared';
  resolveActorQuery({ok:true,status:200,json:async()=>({data:{actors:[{name:'PRIVATE ACTOR'}]}})});
  await request;
  assert.equal(state.actorRows.length,0);
  assert.doesNotMatch(elements.actorRegistryBody.innerHTML,/PRIVATE ACTOR/);
});

test('production preview placeholder must not be counted as named actor',()=>{
  const {resolveActor}=pureDashboardFunctions();
  assert.equal(resolveActor({actor_display_name:'Unknown Threat Actor'}),'Unattributed');
  assert.equal(resolveActor({actor_display_name:'Unknown Threat Actor',actor_tag:'APT29'}),'APT29');
});
test('stale and unverified previews cannot be displayed as live',async()=>{
  const from=html.indexOf('async function loadManifest(){'),to=html.indexOf('function setLoading(on){',from);
  const {parseManifest,resolveActor}=pureDashboardFunctions();
  const elements=Object.fromEntries(['feedSource','lastSync','feedTier'].map(k=>[k,{textContent:''}]));
  const state={apiKey:'',jwtToken:'',authEpoch:0,feedRequestId:0,feedLoaded:true,manifest:[{id:'old'}]};
  let phase='STALE',unavailable=0,verified=0;
  const ctx={STATE:state,document:{getElementById:k=>elements[k]||{textContent:''}},
    BASE:'https://intel.cyberdudebivash.com',parseManifest,resolveActor,
    fetchWithTimeout:async()=>({ok:true,status:200,json:async()=>({status:'ok',preview:{
      items:[{id:'intel1',actor_display_name:'Unknown Threat Actor',published_at:'2026-11-18T00:00:00Z'}],
      generated_at:'2026-11-19T02:22:17Z',publication_state:phase==='FRESH'?'fresh':'stale',
      freshness_status:phase,age_seconds:phase==='FRESH'?100:21601,max_age_seconds:21600
    }})}),setLoading:()=>{},updateConnectionStatus:()=>{},
    showMetricsUnavailable:()=>{unavailable++},applyFilters:()=>{},updateMetrics:()=>{verified++},
    checkWatchlistAlerts:()=>{},console:{warn:()=>{}},Date};
  vm.runInNewContext(html.slice(from,to)+';this.loadManifest=loadManifest;',ctx);
  await ctx.loadManifest();
  assert.equal(state.feedLoaded,false);
  assert.equal(state.manifest.length,0);
  assert.equal(unavailable,1);
  assert.equal(verified,0);
  phase='FRESH';
  await ctx.loadManifest();
  assert.equal(state.feedLoaded,true);
  assert.equal(state.manifest[0].actor_tag,'Unattributed');
  assert.equal(verified,1);
});

test('paid 401/403 feed denial is never disguised by anonymous preview fallback',async()=>{
  const from=html.indexOf('async function loadManifest(){'),to=html.indexOf('function setLoading(on){',from);
  const {parseManifest,resolveActor}=pureDashboardFunctions();
  for(const status of [401,403]){
    const state={apiKey:'',jwtToken:'signed.jwt',authEpoch:0,feedRequestId:0,feedLoaded:true,manifest:[{id:'paid-old'}]};
    const elements=Object.fromEntries(['feedSource','feedTier','lastSync'].map(k=>[k,{textContent:''}]));
    const requests=[];
    const ctx={STATE:state,document:{getElementById:k=>elements[k]||{}},
      BASE:'https://intel.cyberdudebivash.com',authHeaders:()=>({Authorization:'Bearer test'}),
      parseManifest,resolveActor,
      fetchWithTimeout:async url=>{requests.push(url);return {ok:false,status}},
      setLoading:()=>{},updateConnectionStatus:()=>{},showMetricsUnavailable:()=>{},
      applyFilters:()=>{},updateMetrics:()=>{throw new Error('No paid metrics may be shown')},
      checkWatchlistAlerts:()=>{},console:{warn:()=>{}},Date};
    vm.runInNewContext(html.slice(from,to)+';this.loadManifest=loadManifest;',ctx);
    await ctx.loadManifest();
    assert.equal(requests.length,1);
    assert.match(requests[0],/\/api\/feed$/);
    assert.equal(state.feedLoaded,false);
    assert.deepEqual(Array.from(state.manifest),[]);
    assert.match(elements.feedSource.textContent,/Authorized feed access denied/);
    assert.equal(elements.feedTier.textContent,'Access unverified');
  }
});

test('SLA component fields are escaped and invalid uptime is not certified',()=>{
  const block=html.slice(html.indexOf('// Components table'),html.indexOf('// Credit policy',html.indexOf('// Components table')));
  assert.match(block,/esc\(name\)/);
  assert.match(block,/esc\(c\.status\|\|'—'\)/);
  assert.match(block,/Number\.isFinite\(c\.uptime\)/);
  assert.match(block,/c\.uptime<=100/);
  assert.doesNotMatch(block,/\$\{name\}/);
});
