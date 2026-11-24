#!/usr/bin/env python3
"""
SENTINEL APEX v150.0 -- IMMUTABLE API MANIFEST VALIDATOR
=========================================================
DEPLOYMENT GATE -- Verifies all api/v1/intel/*.json bundles are
valid, populated, and internally consistent before git commit proceeds.

This replaces the old embedded_intel_gate.py (which checked that
window.EMBEDDED_INTEL in index.html was non-empty).

Checks:
  1. api/v1/intel/latest.json  -- exists, valid JSON, count >= 1
  2. api/v1/intel/top10.json   -- exists, valid JSON, count >= 1
  3. api/v1/intel/apex.json    -- exists, valid JSON, count >= 1
  4. api/v1/intel/manifest.json -- exists, valid JSON, all bundle refs present
  5. Four bundle digests, counts, generation metadata and registry paths
  6. index.html NOT mutated     -- EMBEDDED_INTEL must be [] (empty stub)

Exit 0 = PASS (deployment allowed)
Exit 1 = FAIL (deployment blocked)
"""

import sys
import os
import json
import hashlib
import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import homepage_source as _homepage_source  # index.html + extracted assets (2026-09-26)  # noqa: E402

REPO     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR  = os.path.join(REPO, 'api', 'v1', 'intel')
INDEX    = os.path.join(REPO, 'index.html')
VERSION  = 'v150.0'

violations = []
passed     = 0
total      = 0


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return hashlib.sha256(f.read().encode('utf-8')).hexdigest()


def check(name, ok, msg_pass='', msg_fail=''):
    global passed, total
    total += 1
    if ok:
        passed += 1
        print(f'  [PASS] {name}{": " + msg_pass if msg_pass else ""}', flush=True)
    else:
        violations.append(f'{name}: {msg_fail}')
        print(f'  [FAIL] {name}: {msg_fail}', flush=True)


print('=' * 68, flush=True)
print(f'SENTINEL APEX {VERSION} -- API MANIFEST VALIDATOR', flush=True)
print(f'Timestamp : {now_iso()}', flush=True)
print('=' * 68, flush=True)

# ── Check 1: latest.json ─────────────────────────────────────────────────────
print('\n[1] api/v1/intel/latest.json', flush=True)
latest_path = os.path.join(OUT_DIR, 'latest.json')
try:
    with open(latest_path, 'r', encoding='utf-8') as f:
        latest = json.load(f)
    count = latest.get('count', 0) or len(latest.get('items', []))
    check('latest.json valid + populated', count >= 1,
          f'{count} items', f'count={count} < 1')
except (FileNotFoundError, json.JSONDecodeError) as e:
    check('latest.json valid + populated', False, msg_fail=str(e))
    latest = None

# ── Check 2: top10.json ──────────────────────────────────────────────────────
print('\n[2] api/v1/intel/top10.json', flush=True)
top10_path = os.path.join(OUT_DIR, 'top10.json')
try:
    with open(top10_path, 'r', encoding='utf-8') as f:
        top10 = json.load(f)
    count = top10.get('count', 0) or len(top10.get('items', []))
    check('top10.json valid + populated', count >= 1,
          f'{count} items', f'count={count} < 1')
except (FileNotFoundError, json.JSONDecodeError) as e:
    check('top10.json valid + populated', False, msg_fail=str(e))

# ── Check 3: apex.json ───────────────────────────────────────────────────────
print('\n[3] api/v1/intel/apex.json', flush=True)
apex_path = os.path.join(OUT_DIR, 'apex.json')
try:
    with open(apex_path, 'r', encoding='utf-8') as f:
        apex = json.load(f)
    count = apex.get('count', 0) or len(apex.get('items', []))
    check('apex.json valid + populated', count >= 1,
          f'{count} items', f'count={count} < 1')
except (FileNotFoundError, json.JSONDecodeError) as e:
    check('apex.json valid + populated', False, msg_fail=str(e))

# ── Check 4: manifest.json (registry) ───────────────────────────────────────
print('\n[4] api/v1/intel/manifest.json', flush=True)
manifest_path = os.path.join(OUT_DIR, 'manifest.json')
try:
    with open(manifest_path, 'r', encoding='utf-8') as f:
        registry = json.load(f)
    bundles = registry.get('bundles', {})
    required = {'latest', 'top10', 'apex', 'latest_pro'}
    present  = set(bundles.keys())
    missing  = required - present
    check('manifest.json all bundle refs present', len(missing) == 0,
          f'bundles={list(present)}', f'missing: {list(missing)}')
except (FileNotFoundError, json.JSONDecodeError) as e:
    check('manifest.json all bundle refs present', False, msg_fail=str(e))
    registry = None

# ── Check 5: Checksum consistency ────────────────────────────────────────────
print('\n[5] Checksum consistency (registry == embedded == unsigned payload SHA-256)', flush=True)
# Check each generated artifact against its own registry entry. Never
# follow a registry-supplied path; only the four producer-owned names are read.
bundle_errors = []
for key in ('latest', 'top10', 'apex', 'latest_pro'):
    path = os.path.join(OUT_DIR, key + '.json')
    try:
        if not registry:
            raise ValueError('registry unavailable')
        entry = registry['bundles'][key]
        with open(path, 'r', encoding='utf-8') as f:
            signed = json.load(f)
        unsigned = dict(signed)
        embedded = unsigned.pop('sha256', None)
        actual_sha = hashlib.sha256(json.dumps(
            unsigned, ensure_ascii=False, separators=(',', ':')
        ).encode('utf-8')).hexdigest()
        if not (os.path.getsize(path) > 100
                and embedded == entry.get('sha256') == actual_sha):
            raise ValueError('digest mismatch')
        items = signed.get('items')
        count = signed.get('count')
        if (not isinstance(items, list) or not items
                or type(count) is not int or count != len(items)
                or type(entry.get('count')) is not int
                or entry['count'] != count):
            raise ValueError('count mismatch')
        generated = signed.get('generated_at')
        if (not isinstance(generated, str) or not generated.strip()
                or generated != entry.get('generated_at')
                or generated != registry.get('generated_at')):
            raise ValueError('generation mismatch')
        if entry.get('path') != 'api/v1/intel/' + key + '.json':
            raise ValueError('registry path mismatch')
        if key == 'latest_pro' and signed.get('tier') != 'PRO':
            raise ValueError('tier mismatch')
        print(f'  [INFO] {key}.json integrity verified', flush=True)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        # Never print untrusted payloads or paid intelligence into CI logs.
        bundle_errors.append(key)
check('all generated bundle checksums and metadata valid', not bundle_errors,
      '4/4 bundles verified',
      'bundle digest mismatch or metadata mismatch: ' + ', '.join(bundle_errors))

# ── Check 5.5: ai_summary.json (AI Brain endpoint — non-blocking) ────────────
print('\n[5.5] api/v1/intel/ai_summary.json (AI Brain endpoint)', flush=True)
ai_summary_path = os.path.join(OUT_DIR, 'ai_summary.json')
if os.path.exists(ai_summary_path):
    try:
        with open(ai_summary_path, 'r', encoding='utf-8') as f:
            ai_data = json.load(f)
        cam_count  = len(ai_data.get('campaigns', []))
        anom_count = len(ai_data.get('anomalies', []))
        fore_count = len(ai_data.get('forecasts', []))
        has_summary = bool(ai_data.get('apex_summary', ''))
        ok = cam_count > 0 or anom_count > 0 or fore_count > 0
        check('ai_summary.json valid + populated',
              ok,
              f'campaigns={cam_count} anomalies={anom_count} forecasts={fore_count} apex_summary={has_summary}',
              f'ai_summary.json exists but is empty (campaigns={cam_count} anomalies={anom_count})')
    except Exception as e:
        # Non-blocking: AI Brain publisher may not have run yet
        print(f'  [WARN] ai_summary.json parse error: {e} (non-blocking)', flush=True)
else:
    print('  [INFO] ai_summary.json not yet generated (AI Brain publisher pending)', flush=True)

# ── Check 6: index.html is NOT mutated (EMBEDDED_INTEL must be []) ──────────
print('\n[6] index.html immutability (EMBEDDED_INTEL must be static [])', flush=True)
try:
    import re
    html = _homepage_source.read_text_for_inspection(INDEX)
    m = re.search(r'window\.EMBEDDED_INTEL\s*=\s*(\[.*?\]);', html, re.DOTALL)
    if m:
        val = m.group(1).strip()
        is_empty = val == '[]'
        check('index.html EMBEDDED_INTEL is static []', is_empty,
              'confirmed static empty stub (immutable architecture active)',
              f'EMBEDDED_INTEL is NOT empty ({len(val):,} chars) — HTML was mutated!')
    else:
        check('index.html EMBEDDED_INTEL is static []', False,
              msg_fail='EMBEDDED_INTEL declaration not found in index.html')
except Exception as e:
    check('index.html EMBEDDED_INTEL is static []', False, msg_fail=str(e))

# ── FINAL VERDICT ─────────────────────────────────────────────────────────────
print()
print('=' * 68, flush=True)
print(f'CHECKS PASSED: {passed}/{total}', flush=True)
if violations:
    print(f'VIOLATIONS ({len(violations)}):', flush=True)
    for v in violations:
        print(f'  FAIL: {v}', flush=True)
    print()
    print('RESULT: FAIL -- API manifest validation failed', flush=True)
    print('DEPLOYMENT BLOCKED until all violations are resolved', flush=True)
    print('=' * 68, flush=True)
    sys.exit(1)
else:
    print()
    print('RESULT: PASS -- All API manifests valid and populated', flush=True)
    print('DEPLOYMENT ALLOWED -- Immutable architecture integrity confirmed', flush=True)
    print('=' * 68, flush=True)
    sys.exit(0)
