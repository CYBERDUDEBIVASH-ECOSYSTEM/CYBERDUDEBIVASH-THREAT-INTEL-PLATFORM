'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.join(__dirname,'..');
const script=fs.readFileSync(path.join(root,'js/homepage-dashboard-engine.js'),'utf8');
const scan=JSON.parse(fs.readFileSync(path.join(root,'data/bughunter/bughunter_output.json'),'utf8'));
const history=JSON.parse(fs.readFileSync(path.join(root,'data/bughunter/scan_history/scan_20261119T012259.json'),'utf8'));

test('Bug Hunter uses official main reviewed source and never the unreviewed run branch',()=>{
 assert.match(script,/REVIEWED_RECON_BASE = 'https:\/\/raw\.githubusercontent\.com\/CYBERDUDEBIVASH-ECOSYSTEM\/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\/main\/'/);
 assert.match(script,/bughunter:\s*REVIEWED_RECON_BASE \+ 'data\/bughunter\/bughunter_output\.json'/);
 assert.doesNotMatch(script,/bughunter:\s*RAW_BASE/);
 assert.doesNotMatch(script,/bughunter:\s*[^\n]*sentinel-generated\//);
});
test('candidate snapshot retains actual scanner provenance, not a freshened historical scan',()=>{
 assert.equal(scan.scan_id,'BH-1795051361');
 assert.equal(scan.domain,'cyberdudebivash.com');
 assert.equal(scan.status,'COMPLETED');
 assert.equal(scan.timestamp,'2026-11-19T01:22:59.615311+00:00');
 assert.equal(scan.metrics.subdomains,4);
 assert.equal(scan.metrics.live_hosts,3);
 assert.equal(scan.metrics.total_findings,1);
 assert.equal(scan.metrics.critical_findings,0);
 assert.equal(scan.findings_summary[0].severity,'MEDIUM');
 assert.equal(history.scan_id,scan.scan_id);
 assert.equal(history.timestamp,scan.timestamp);
 assert.equal(scan.engines.find(e=>e.id==='subdomain_engine').status,'FALLBACK');
});
test('saved scan observations are explicitly labelled historic when older than 24h',()=>{
 assert.match(script,/age <= 86400000/);
 assert.match(script,/HISTORICAL SCAN/);
 assert.match(script,/NOT CURRENT/);
 assert.match(script,/Re-scan required/);
});
