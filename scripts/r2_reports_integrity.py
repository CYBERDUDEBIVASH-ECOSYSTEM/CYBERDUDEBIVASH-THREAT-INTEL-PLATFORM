#!/usr/bin/env python3
"""
scripts/r2_reports_integrity.py
CYBERDUDEBIVASH(R) SENTINEL APEX v1.0 -- R2 Reports Index Integrity Gate
=========================================================================
STAGE 3.5.1: Executed immediately after r2_upload.py (Stage 3.5).

PURPOSE:
  1. Verifies that current-run HTML reports were successfully uploaded to
     the sentinel-apex-reports R2 bucket.
  2. Purges stale entries from api/reports/index.json (entries that exist
     in the index but have no corresponding HTML in R2 sentinel-apex-reports).
  3. Re-uploads the cleaned api/reports/index.json to R2 sentinel-apex-data.

ROOT CAUSE FIX:
  r2_upload.py (Stage 3.5) treats HTML report upload as non-fatal -- it exits 0
  even when the upload to sentinel-apex-reports fails (credential issue, timeout,
  network error). The api/reports/index.json therefore accumulates ghost entries
  pointing to report URLs that do not exist in R2. Users who click these links
  receive a 404 JSON error from the Cloudflare Worker.

  This script detects and eliminates ghost entries, ensuring every entry in the
  published index points to an HTML file that actually exists in R2.

HARD FAIL condition:
  ALL current-run report URLs (derived from api/feed.json report_url fields) are
  missing from sentinel-apex-reports. This indicates the upload mechanism itself
  is broken (wrong credentials, missing bucket, permission denied). The pipeline
  must not publish a report index filled with 404 links.

NON-FATAL condition:
  Some historical index entries are missing from R2 (older runs with silent upload
  failures). These are purged and the pipeline continues cleanly.

EXIT CODES:
  0 -- OK (index is clean, or stale entries were purged and index re-uploaded)
  1 -- HARD FAIL (current-run reports ALL missing from R2 -- upload broken)

ENVIRONMENT (consumed):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  CF_R2_REPORTS_KEY_ID     -- Dedicated R2 token for sentinel-apex-reports bucket
  CF_R2_REPORTS_SECRET_KEY -- Dedicated R2 secret for sentinel-apex-reports bucket
  AWS_ACCESS_KEY_ID        -- Job-level R2 key (sentinel-apex-data re-upload)
  AWS_SECRET_ACCESS_KEY    -- Job-level R2 secret (sentinel-apex-data re-upload)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2-integrity] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_integrity")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO            = Path(__file__).resolve().parent.parent
INDEX_PATH      = REPO / "api" / "reports" / "index.json"
LATEST_PATH     = REPO / "api" / "reports" / "latest.json"
FEED_PATH       = REPO / "api" / "feed.json"
BUCKET_REPORTS  = "sentinel-apex-reports"
BUCKET_DATA     = "sentinel-apex-data"
MAX_WORKERS     = 20          # Parallel S3 head-object workers
MAX_CHECK       = 200         # Max index entries to verify (limits runtime)
CHECK_TIMEOUT   = 15          # Per-request timeout (seconds)
R2_S3_REGION   = "auto"      # Cloudflare R2-only; never inherit global AWS region


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_github_env(key: str, value: str) -> None:
    gh_env = os.environ.get("GITHUB_ENV", "/dev/null")
    try:
        with open(gh_env, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")
    except Exception:
        pass


def _get_credentials() -> Tuple[str, str, str, str, str]:
    """
    Returns (cf_account, reports_key_id, reports_secret, data_key_id, data_secret).
    Falls back reports credentials to job-level if dedicated ones are absent.
    """
    cf_account  = os.environ.get("CF_ACCOUNT_ID", "").strip()
    reports_key = os.environ.get("CF_R2_REPORTS_KEY_ID", "").strip()
    reports_sec = os.environ.get("CF_R2_REPORTS_SECRET_KEY", "").strip()
    data_key    = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    data_sec    = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()

    if reports_key and reports_sec:
        log.info("Reports bucket check: using dedicated CF_R2_REPORTS_KEY_ID credentials")
    else:
        log.info("CF_R2_REPORTS_KEY_ID not set -- using job-level credentials for reports bucket check")
        reports_key = data_key
        reports_sec = data_sec

    return cf_account, reports_key, reports_sec, data_key, data_sec


def _path_to_r2_key(path_or_url: str) -> Optional[str]:
    """
    Convert a report path (/reports/2026/06/intel--xxx.html) or full URL to
    the R2 key used in sentinel-apex-reports (reports/2026/06/intel--xxx.html).
    """
    if not path_or_url:
        return None
    if path_or_url.startswith("http"):
        parsed = urlparse(path_or_url)
        path_or_url = parsed.path
    key = path_or_url.lstrip("/")
    return key if key.startswith("reports/") else None


def _r2_object_exists(
    key: str,
    bucket: str,
    endpoint: str,
    key_id: str,
    secret: str,
) -> Optional[bool]:
    """Tri-state S3 HEAD: present=True, proven 404=False, unknown=None.

    A credential, signing-region or network failure is *not* proof that an
    object is absent.  Never permit such failures to delete customer catalog
    entries.  Use R2's explicit auto signing region without mutating AWS
    account configuration globally.
    """
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = key_id
    env["AWS_SECRET_ACCESS_KEY"] = secret
    try:
        result = subprocess.run(
            [
                "aws", "s3api", "head-object",
                "--bucket", bucket,
                "--key", key,
                "--endpoint-url", endpoint,
                "--region", R2_S3_REGION,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=CHECK_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode == 0:
        return True
    # Only an explicit S3 HeadObject not-found is a confirmed absent object.
    # Do not mistake 400 InvalidRegionName, 403 AccessDenied or other errors
    # for 404, or expose the raw AWS CLI stderr in CI logs.
    detail = result.stderr or ""
    if ("HeadObject operation" in detail and
            any(marker in detail for marker in ("(404)", "(NoSuchKey)", "(NotFound)"))):
        return False
    return None


def _s3_cp(
    local_path: str,
    bucket: str,
    key: str,
    endpoint: str,
    key_id: str,
    secret: str,
) -> bool:
    """Upload a single file to R2. Returns True on success."""
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = key_id
    env["AWS_SECRET_ACCESS_KEY"] = secret

    result = subprocess.run(
        [
            "aws", "s3", "cp", local_path,
            f"s3://{bucket}/{key}",
            "--endpoint-url",  endpoint,
            "--region",        R2_S3_REGION,
            "--content-type",  "application/json",
            "--cache-control", "no-cache, no-store, must-revalidate",
            "--only-show-errors",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    if result.returncode == 0:
        log.info("OK: uploaded %s -> s3://%s/%s", local_path, bucket, key)
        return True
    # Do not reflect AWS CLI stderr (which may contain request metadata,
    # authentication material, or presigned URLs) in shared Actions logs.
    log.error("R2 catalog upload failed (nonzero exit)")
    return False


def _remote_catalog_matches(local_path: str, bucket: str, key: str,
                            endpoint: str, key_id: str, secret: str) -> bool:
    """Bounded read-after-write proof; a successful CLI upload is insufficient.

    Verify actual customer bucket bytes rather than relying on an ETag:
    multipart upload and encryption can make ETags non-MD5 identifiers.
    Called only for catalogs changed in this run (at most two objects).
    """
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = key_id
    env["AWS_SECRET_ACCESS_KEY"] = secret
    try:
        with tempfile.TemporaryDirectory(prefix="cdb-r2-catalog-") as folder:
            remote = Path(folder) / "catalog.json"
            result = subprocess.run(
                ["aws", "s3api", "get-object", "--bucket", bucket,
                 "--key", key, "--endpoint-url", endpoint,
                 "--region", R2_S3_REGION, str(remote)],
                capture_output=True, text=True, env=env, timeout=60,
            )
            if result.returncode != 0 or not remote.is_file():
                return False
            def digest(path: Path) -> str:
                h = hashlib.sha256()
                with path.open("rb") as stream:
                    while chunk := stream.read(128 * 1024):
                        h.update(chunk)
                return h.hexdigest()
            return digest(Path(local_path)) == digest(remote)
    except (OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("=" * 70)
    log.info("R2 REPORTS INDEX INTEGRITY GATE v1.0  --  STAGE 3.5.1")
    log.info("=" * 70)

    # --- Credentials ---
    cf_account, reports_key, reports_sec, data_key, data_sec = _get_credentials()

    if not cf_account:
        log.error("R2 required integrity proof unavailable: no Cloudflare account")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_NO_ACCOUNT_ID")
        return 2

    if not reports_key or not reports_sec:
        log.error("R2 required integrity proof unavailable: missing reports credentials")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_NO_CREDENTIALS")
        return 2

    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    log.info("R2 endpoint : %s", endpoint)
    log.info("Reports bucket : %s", BUCKET_REPORTS)

    # --- Load index ---
    if not INDEX_PATH.exists():
        log.error("R2 required integrity proof unavailable: missing customer catalog")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_NO_INDEX")
        return 2

    try:
        index_data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        log.error("R2 required integrity proof unavailable: invalid customer catalog")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_READ_INDEX")
        return 2

    if not isinstance(index_data, dict) or not isinstance(index_data.get("reports"), list):
        log.error("R2 catalog schema invalid; no customer delivery verification possible")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_CATALOG_SCHEMA")
        return 2
    all_entries: List[dict] = index_data["reports"]
    if not all_entries or any(not isinstance(e, dict) for e in all_entries):
        log.error("R2 customer catalog empty or contains invalid entries")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_EMPTY_OR_INVALID_INDEX")
        return 2

    log.info("Index entries: %d total", len(all_entries))

    # --- Identify current-run report keys from api/feed.json ---
    current_run_keys: Set[str] = set()
    try:
        feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
        items = feed if isinstance(feed, list) else (
            feed.get("items") if isinstance(feed, dict) else None
        )
        if not isinstance(items, list) or not items or any(not isinstance(i, dict) for i in items):
            raise ValueError("invalid feed schema")
        for item in items:
            ru = item.get("report_url") or item.get("internal_report_url")
            if ru:
                key = _path_to_r2_key(ru) if isinstance(ru, str) else None
                if not key:
                    raise ValueError("invalid report path in feed")
                current_run_keys.add(key)
        if not current_run_keys:
            raise ValueError("no current report URLs")
    except (OSError, ValueError, TypeError):
        log.error("R2 required integrity proof unavailable: feed or report URL evidence invalid")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_CURRENT_FEED_EVIDENCE")
        return 2
    log.info("Current-run report URLs: %d (from api/feed.json)", len(current_run_keys))

    # --- Load latest.json up front (needed both to build the check set below
    #     and to purge it later) so its own entries -- which are not
    #     guaranteed to be a strict subset of index.json's checked window --
    #     are actually verified, not just carried along for the ride. v1.1
    #     FIX: previously latest.json's entries were never added to the
    #     checked key set at all, so a staleness unique to latest.json
    #     (e.g. after independent drift between the two files) could never
    #     be detected or purged by this gate.
    latest_data: Optional[dict] = None
    latest_reports_raw: List[dict] = []
    if not LATEST_PATH.is_file():
        log.error("Required latest customer catalog is absent")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_NO_LATEST")
        return 2
    try:
        latest_data = json.loads(LATEST_PATH.read_text(encoding="utf-8"))
        if not isinstance(latest_data, dict) or not isinstance(latest_data.get("reports"), list):
            raise ValueError("invalid latest report catalog")
        latest_reports_raw = latest_data["reports"]
        if any(not isinstance(e, dict) for e in latest_reports_raw):
            raise ValueError("invalid latest report entries")
    except (OSError, ValueError, TypeError):
        log.error("Required latest customer catalog is unreadable or invalid")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LATEST_SCHEMA")
        return 2

    # --- Select entries to check (most recent MAX_CHECK + all current-run) ---
    entries_to_check = all_entries[:MAX_CHECK]
    skipped = len(all_entries) - len(entries_to_check)
    if skipped > 0:
        log.info("Checking %d entries (oldest %d skipped to respect runtime budget)",
                 len(entries_to_check), skipped)
    else:
        log.info("Checking all %d entries", len(entries_to_check))

    # Build the key list for the entries to check
    entry_key_map: Dict[str, dict] = {}   # r2_key -> entry
    for entry in entries_to_check:
        r2_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if r2_key:
            entry_key_map[r2_key] = entry

    # Also include any current-run keys not already in the checked set
    indexed_keys = {
        key for entry in all_entries
        if (key := _path_to_r2_key(entry.get("path", "") or entry.get("url", "")))
    }
    unindexed_current = current_run_keys - indexed_keys
    for ck in current_run_keys:
        # Never omit a feed-referenced object from authenticated HEAD simply
        # because the customer catalog has no corresponding entry.
        entry_key_map.setdefault(ck, {"path": "/" + ck})

    # Also include latest.json's own entries, even if absent from index.json's
    # checked window (see v1.1 FIX note above).
    for entry in latest_reports_raw:
        lk = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if lk and lk not in entry_key_map:
            entry_key_map[lk] = entry

    all_keys_to_check = list(entry_key_map.keys())
    if len(all_keys_to_check) > 500:
        log.error("Required R2 HEAD count exceeds bounded gate budget; no catalog mutation")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_HEAD_BUDGET")
        return 2
    log.info("Dispatching %d parallel R2 head-object checks (workers=%d)...",
             len(all_keys_to_check), MAX_WORKERS)

    # --- Parallel R2 existence checks ---
    key_exists: Dict[str, Optional[bool]] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_key = {
            pool.submit(
                _r2_object_exists, k, BUCKET_REPORTS, endpoint, reports_key, reports_sec
            ): k
            for k in all_keys_to_check
        }
        for future in as_completed(future_to_key):
            k = future_to_key[future]
            try:
                exists = future.result()
            except Exception:
                # An exception cannot establish either presence or absence.
                exists = None
            key_exists[k] = exists

    # --- Tally results ---
    # Stop *before any local catalog mutation* if any HEAD could not be
    # authenticated or completed.  UNKNOWN must never become MISSING.
    unverifiable_keys: Set[str] = {k for k, v in key_exists.items() if v is None}
    if unverifiable_keys:
        log.error("R2 integrity verification blocked: %d unverifiable HEAD result(s); catalog unchanged",
                  len(unverifiable_keys))
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS",
                          f"BLOCKED_UNVERIFIABLE_HEAD_{len(unverifiable_keys)}")
        return 2
    missing_keys: Set[str] = {k for k, v in key_exists.items() if v is False}
    present_keys: Set[str] = {k for k, v in key_exists.items() if v is True}

    log.info("R2 check results: %d present / %d missing (of %d checked)",
             len(present_keys), len(missing_keys), len(key_exists))

    # --- Assess current-run upload health ---
    current_missing = current_run_keys & missing_keys
    current_present = current_run_keys & present_keys
    log.info("Current-run reports: %d in R2 / %d missing from R2",
             len(current_present), len(current_missing))

    if current_missing:
        log.warning("Missing current-run reports from R2:")
        for mk in sorted(current_missing)[:10]:
            log.warning("  MISSING: %s", mk)

    # All current-run reports provably absent: fail without wiping the
    # catalog to zero.  The independent release gate remains red.
    if current_run_keys and not current_present and current_missing:
        log.error("HARD FAIL: all %d checked current-run reports confirmed absent; catalog unchanged",
                  len(current_missing))
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS",
                          f"HARD_FAIL_all_{len(current_missing)}_current_run_reports_missing")
        return 1

    # Current-run delivery requires ALL reports, not merely one success.
    # A feed-only key also means the customer catalog lacks a required URL.
    # Both conditions block before any local or remote catalog mutation.
    if current_missing or unindexed_current:
        log.error("BLOCKED: %d missing current-run R2 objects; %d unindexed current-run objects; catalogs unchanged",
                  len(current_missing), len(unindexed_current))
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS",
                          f"BLOCKED_CURRENT_REPORTS_missing_{len(current_missing)}_unindexed_{len(unindexed_current)}")
        return 1

    # --- Purge stale entries from index ---
    # Cache original bytes for rollback if any local write or R2 upload fails.
    original_index = INDEX_PATH.read_bytes()
    original_latest = LATEST_PATH.read_bytes() if LATEST_PATH.exists() else None
    clean_entries: List[dict] = []
    purged_count = 0

    for entry in all_entries:
        r2_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if r2_key and key_exists.get(r2_key) is False:
            # Confirmed missing from R2 -- purge
            purged_count += 1
        else:
            clean_entries.append(entry)

    index_changed  = False
    latest_changed = False

    if purged_count > 0:
        log.info("Purged %d stale entries from api/reports/index.json "
                 "(had no HTML in R2 sentinel-apex-reports)", purged_count)
        log.info("Index: %d entries before -> %d entries after purge",
                 len(all_entries), len(clean_entries))

        # Write back cleaned index. v1.1 FIX: total_reports is reduced by
        # exactly the purged count so it stays consistent with reports_listed/
        # reports -- previously it was left untouched after a purge, so a
        # customer-visible count could silently diverge from what the index
        # actually lists (F-02 root cause register item).
        index_data["reports"]         = clean_entries
        index_data["reports_listed"]  = len(clean_entries)
        index_data["total_reports"]   = max(0, int(index_data.get("total_reports", 0)) - purged_count)
        index_data["generated_at"]    = _utc_now()

        try:
            tmp = INDEX_PATH.with_suffix(".integrity_tmp")
            tmp.write_text(
                json.dumps(index_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            os.replace(tmp, INDEX_PATH)
            log.info("OK: api/reports/index.json written with %d clean entries", len(clean_entries))
            index_changed = True
        except Exception as exc:
            log.error("BLOCKED: local report index write failed (%s)", type(exc).__name__)
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LOCAL_INDEX_WRITE")
            return 2
    else:
        log.info("Index is clean -- no stale entries detected in checked range (%d entries)",
                 len(entries_to_check))

    # v1.1 FIX: latest.json is checked/purged independently of index.json's
    # purge_count. This used to be nested inside `if purged_count > 0`, so a
    # run that purged 0 index.json entries never checked latest.json at all --
    # even when latest.json (the newest-first top-50 subset, most likely to
    # contain this run's own reports) had its own stale entries missing from
    # R2. That asymmetry was the direct cause of index.json and latest.json
    # showing different report counts from the same pipeline run (F-02).
    if latest_data is not None:
        try:
            latest_reports = latest_reports_raw
            clean_latest = [
                e for e in latest_reports
                if _path_to_r2_key(e.get("path", "") or e.get("url", "")) not in missing_keys
            ]
            latest_purged = len(latest_reports) - len(clean_latest)
            if latest_purged > 0:
                latest_data["reports"]        = clean_latest
                latest_data["reports_listed"] = len(clean_latest)
                latest_data["total_reports"]  = max(0, int(latest_data.get("total_reports", 0)) - latest_purged)
                latest_data["generated_at"]   = _utc_now()
                tmp2 = LATEST_PATH.with_suffix(".integrity_tmp")
                tmp2.write_text(
                    json.dumps(latest_data, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                os.replace(tmp2, LATEST_PATH)
                log.info("OK: api/reports/latest.json purged %d stale entries", latest_purged)
                latest_changed = True
        except Exception as exc:
            log.error("BLOCKED: local latest report catalog write failed (%s)", type(exc).__name__)
            # An index update may have succeeded before the latest update
            # failed. Restore *both* local files before any cloud upload;
            # downstream stages must never see half-published catalog state.
            rollback_ok = True
            for original_path, original_bytes in (
                (INDEX_PATH, original_index), (LATEST_PATH, original_latest)
            ):
                try:
                    if original_bytes is not None:
                        original_path.write_bytes(original_bytes)
                except OSError:
                    rollback_ok = False
                    log.error("BLOCKED: local catalog rollback failed (%s)", original_path.name)
            _write_github_env(
                "R2_REPORTS_INTEGRITY_STATUS",
                "BLOCKED_LOCAL_LATEST_WRITE" if rollback_ok else "BLOCKED_LOCAL_ROLLBACK",
            )
            return 2

    # A successful local catalog cleanup is not proof of successful remote
    # customer publication. Roll back local bytes on any upload failure.
    publication_failed = False
    if index_changed or latest_changed:
        if not (data_key and data_sec):
            publication_failed = True
        else:
            for rel, local_p, changed in [
                ("api/reports/index.json", INDEX_PATH, index_changed),
                ("api/reports/latest.json", LATEST_PATH, latest_changed),
            ]:
                if changed:
                    try:
                        if not _s3_cp(str(local_p), BUCKET_DATA, rel, endpoint, data_key, data_sec):
                            publication_failed = True
                        elif not _remote_catalog_matches(str(local_p), BUCKET_DATA, rel, endpoint, data_key, data_sec):
                            publication_failed = True
                    except (OSError, subprocess.TimeoutExpired):
                        publication_failed = True
        if publication_failed:
            log.error("BLOCKED: cleaned customer catalog upload not confirmed; local catalog rollback required")
            try:
                if index_changed:
                    INDEX_PATH.write_bytes(original_index)
                if latest_changed and original_latest is not None:
                    LATEST_PATH.write_bytes(original_latest)
            except OSError:
                log.error("BLOCKED: local catalog rollback failed; manual recovery required")
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_CATALOG_PUBLICATION")
            return 2

    # --- Determine exit status ---
    # HARD FAIL only when ALL current-run reports are missing from R2.
    # This means the upload mechanism itself is broken (credentials, bucket, etc.).
    # A partial failure (some historical entries missing) is non-fatal after purge.
    # Partial current-run failure (some missing, some present) -- warn but continue
    if current_missing:
        log.warning("WARN: %d/%d current-run reports missing from R2 (partial upload failure)",
                    len(current_missing), len(current_run_keys))

    status = (
        f"OK_purged={purged_count}"
        f"_checked={len(key_exists)}"
        f"_clean={len(clean_entries)}"
    )
    _write_github_env("R2_REPORTS_INTEGRITY_STATUS", status)

    log.info("=" * 70)
    log.info("INTEGRITY GATE COMPLETE")
    log.info("  Entries checked  : %d", len(key_exists))
    log.info("  Present in R2    : %d", len(present_keys))
    log.info("  Missing (purged) : %d", purged_count)
    log.info("  Index remaining  : %d", len(clean_entries))
    log.info("  Status           : %s", status)
    log.info("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
