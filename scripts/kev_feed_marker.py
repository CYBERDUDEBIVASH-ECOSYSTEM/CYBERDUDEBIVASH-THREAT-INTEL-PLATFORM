#!/usr/bin/env python3
"""
scripts/kev_feed_marker.py  — SENTINEL APEX v184.0 CISA KEV Feed Marker
P0-FIX v184.0:
  - _extract_cve() now checks cve_id/cve_ids/cves fields (was only 'cve')
  - _is_kev_true() replaces bare `if item.get('kev'):`  — handles kev="NO"
  - De-inflation pass: kev=True items whose CVE is NOT in catalog get cleared
  - write-back triggers on deflated>0 as well as marked>0
"""
from __future__ import annotations
import http.client
import json, logging, os, re, sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [kev-marker] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S", stream=sys.stdout)
log = logging.getLogger("kev_marker")

REPO        = Path(__file__).resolve().parent.parent
FEED_PATH   = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
REPORT_PATH = REPO / "data" / "health" / "kev_marker_report.json"
KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DRY_RUN     = os.environ.get("DRY_RUN", "false").lower() == "true"
TIMEOUT     = int(os.environ.get("KEV_TIMEOUT", "20"))
_CVE_RE     = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


_CISA_KEV_HOST = "www.cisa.gov"
_CISA_KEV_PATH = "/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_MAX_CISA_KEV_BYTES = 16 * 1024 * 1024


def _fetch_kev_catalog() -> dict:
    """Read the official catalog only over verified HTTPS, never a redirect.

    A fixed origin/path prevents URL substitution and unintended redirects.
    The bounded response protects publisher memory from oversized payloads.
    Failure leaves the existing catalog-unavailable behavior intact.
    """
    log.info("Fetching CISA KEV catalog from %s", KEV_URL)
    if KEV_URL != f"https://{_CISA_KEV_HOST}{_CISA_KEV_PATH}":
        log.error("Rejected unapproved CISA KEV source URL")
        return {}

    connection = None
    try:
        # http.client.HTTPSConnection validates the server certificate by default.
        # No generic file:/ftp: handlers or automatic cross-origin redirects.
        connection = http.client.HTTPSConnection(
            _CISA_KEV_HOST, port=443, timeout=TIMEOUT
        )
        connection.request(
            "GET", _CISA_KEV_PATH,
            headers={"User-Agent": "SentinelApex/175.1", "Accept": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"unexpected CISA KEV HTTP status: {response.status}")
        raw = response.read(_MAX_CISA_KEV_BYTES + 1)
        if len(raw) > _MAX_CISA_KEV_BYTES:
            raise ValueError("CISA KEV response exceeds bounded size")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("CISA KEV response has invalid catalog structure")
    except Exception as exc:
        log.error("KEV fetch failed: %s", exc)
        return {}
    finally:
        if connection is not None:
            connection.close()

    catalog = {}
    for v in data["vulnerabilities"]:
        if not isinstance(v, dict):
            log.error("CISA KEV catalog contains a non-object vulnerability")
            return {}
        cid = v.get("cveID") or ""
        if not isinstance(cid, str):
            log.error("CISA KEV catalog contains a non-string CVE ID")
            return {}
        cid = cid.upper().strip()
        if cid:
            catalog[cid] = {
                "date_added":         v.get("dateAdded", ""),
                "vendor_project":     v.get("vendorProject", ""),
                "product":            v.get("product", ""),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "required_action":    v.get("requiredAction", ""),
                "due_date":           v.get("dueDate", ""),
            }
    log.info("KEV catalog loaded: %d entries", len(catalog))
    return catalog


def _is_kev_true(val) -> bool:
    """Only True for genuinely-truthy KEV values; kev='NO' returns False."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1", "confirmed")
    return bool(val)


def _extract_cve(item: dict) -> list:
    """Extract CVE IDs from all canonical fields + text fallback.
    P0-FIX: Added cve_id/cve_ids/cves — prior code only checked 'cve'.
    """
    cves = []
    # Structured fields first (most reliable)
    for field in ("cve_id", "cve_ids", "cves", "cve"):
        val = item.get(field)
        if val is None:
            continue
        if isinstance(val, str):
            cid = val.upper().strip()
            if _CVE_RE.match(cid) and cid not in cves:
                cves.append(cid)
        elif isinstance(val, list):
            for c in val:
                cid = str(c).upper().strip()
                if _CVE_RE.match(cid) and cid not in cves:
                    cves.append(cid)
    # Text fallback
    # P1-FIX (audit finding F1, run #1551 / STAGE 3.93.15 false HARD_FAIL):
    # Added 'headline' and 'name' for parity with intelligence_integrity_gate
    # ._title(), which falls back through title -> headline -> name. Without
    # this, items whose CVE text lives in `headline`/`name` (a real, populated
    # field pattern elsewhere in this codebase — see manifest_repair.py,
    # ocios_campaign_correlation_engine.py, auto_blog_publisher.py, etc.) were
    # returned as cves=[], fell through `if not cves: continue` below, and their
    # kev flag was never re-validated against the live catalog — surviving as an
    # unverified true/false positive that the Integrity Gate then (correctly,
    # from its own wider view) flagged as "inflated". This made the gate look
    # wrong when it was actually catching what THIS function missed.
    for field in ("title", "headline", "name", "id", "source_url", "description"):
        val = item.get(field) or ""
        for m in _CVE_RE.finditer(str(val)):
            c = m.group(0).upper()
            if c not in cves:
                cves.append(c)
    return cves


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — CISA KEV Feed Marker v184.0")
    log.info("Feed : %s | DryRun: %s", FEED_PATH, DRY_RUN)
    log.info("=" * 60)

    if not FEED_PATH.exists():
        log.error("Feed not found: %s", FEED_PATH)
        return 1

    try:
        feed_data = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Feed parse error: %s", e)
        return 1

    items = feed_data if isinstance(feed_data, list) else (feed_data.get("items") or [])
    if not items:
        log.warning("Feed empty — nothing to mark")
        return 0

    catalog = _fetch_kev_catalog()
    if not catalog:
        log.warning("KEV catalog unavailable — skipping (non-fatal)")
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "kev_catalog_size": 0, "items_marked": 0, "items_deflated": 0,
            "status": "CATALOG_UNAVAILABLE"}, indent=2), encoding="utf-8")
        return 0

    marked = already_kev = deflated = reconciled = 0
    kev_items = []
    kev_meta_fields = (
        "kev_date", "kev_product", "kev_name", "kev_action", "kev_due",
        "kev_cve", "kev_cve_ids", "_kev_marked_at", "_kev_source",
    )
    verified_at = datetime.now(timezone.utc).isoformat()

    for item in items:
        if not isinstance(item, dict):
            # Never report PASS on malformed input or partially publish rows.
            # The feed is not written before this validation succeeds.
            log.error("Malformed non-object feed row; blocking KEV publication")
            return 1

        cves = _extract_cve(item)
        # Check fields independently: kev="NO" must never shadow a valid
        # kev_present=True on a different legacy source field.
        currently_kev = any(
            _is_kev_true(item.get(key))
            for key in ("kev", "kev_confirmed", "kev_present")
        )
        matched_cves = sorted(c for c in set(cves) if c in catalog)

        if matched_cves:
            # Record-level kev_present means AT LEAST ONE referenced CVE is in
            # CISA KEV. Exact per-CVE membership is retained separately so a
            # multi-CVE news report never implies that every CVE is exploited.
            matched_cve = matched_cves[0]
            matched_entry = catalog[matched_cve]
            product = (
                str(matched_entry.get("vendor_project") or "") + " "
                + str(matched_entry.get("product") or "")
            ).strip()
            canonical = {
                "kev": True,
                "kev_confirmed": True,
                "kev_present": True,
                "kev_cve": matched_cve,
                "kev_cve_ids": matched_cves,
                "kev_date": matched_entry.get("date_added", ""),
                "kev_product": product,
                "kev_name": matched_entry.get("vulnerability_name", ""),
                "kev_action": matched_entry.get("required_action", ""),
                "kev_due": matched_entry.get("due_date", ""),
                "_kev_source": "CISA-KEV-v2",
                "_kev_marked_at": item.get("_kev_marked_at") or verified_at,
            }
            changed = any(item.get(k) != v for k, v in canonical.items())
            if currently_kev:
                already_kev += 1
                if changed:
                    reconciled += 1
            else:
                marked += 1
                kev_items.append({
                    "cve": matched_cve,
                    "matched_cves": matched_cves,
                    "title": str(item.get("title") or "")[:80],
                    "kev_date": canonical["kev_date"],
                    "kev_product": product,
                })
            if changed:
                item.update(canonical)
                log.info("[KEV-VERIFIED] %s (matched=%d; newly=%s)",
                         matched_cve, len(matched_cves), not currently_kev)
            # Do NOT manufacture CVSS severity, APEX risk or a confidence
            # score. KEV is an independent exploitation/prioritisation signal.
        else:
            # An unverified pre-existing KEV flag MUST NOT survive just because
            # no CVE was parsed, or because stale metadata was attached.
            stale = any(item.get(k) not in (None, "", []) for k in kev_meta_fields)
            if currently_kev or stale:
                item["kev"] = False
                item["kev_confirmed"] = False
                item["kev_present"] = False
                for key in kev_meta_fields:
                    item.pop(key, None)
                deflated += 1
                log.warning("[KEV-DEFLATE] no catalog match (%d parsed CVEs): %s",
                            len(cves), str(item.get("title") or "")[:65])

    log.info("─" * 60)
    log.info("KEV marking complete: %d marked, %d already, %d reconciled, %d deflated, %d total",
             marked, already_kev, reconciled, deflated, len(items))

    total_kev = marked + already_kev
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps({
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "kev_catalog_size":  len(catalog),
        "feed_items":        len(items),
        "items_marked":      marked,
        "items_deflated":    deflated,
        "items_reconciled":  reconciled,
        "already_kev":       already_kev,
        "total_kev_in_feed": total_kev,
        "kev_items":         kev_items,
        "status":            "PASS",
        "dry_run":           DRY_RUN,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Report written: %s", REPORT_PATH)

    if DRY_RUN:
        log.info("[DRY RUN] Would write %d marked, %d reconciled, %d deflated", marked, reconciled, deflated)
        return 0

    if marked == 0 and reconciled == 0 and deflated == 0:
        log.info("No KEV changes — feed unchanged")
        return 0

    tmp = FEED_PATH.with_suffix(".kev_tmp")
    try:
        out = items if isinstance(feed_data, list) else {**feed_data, "items": items}
        tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(FEED_PATH)
        log.info("Feed updated: %s (%d items, %d KEV, %d deflated)",
                 FEED_PATH, len(items), total_kev, deflated)
    except Exception as e:
        log.error("Feed write failed: %s", e)
        tmp.unlink(missing_ok=True)
        return 1

    log.info("=" * 60)
    log.info("KEV Feed Marker complete — %d marked CRITICAL, %d deflated", marked, deflated)
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
