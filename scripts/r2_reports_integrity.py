#!/usr/bin/env python3
"""
scripts/r2_reports_integrity.py
CYBERDUDEBIVASH(R) SENTINEL APEX v1.0 -- R2 Reports Index Integrity Gate
=========================================================================
STAGE 3.5.1: Executed immediately after r2_upload.py (Stage 3.5).

PURPOSE:
  Read-only, bounded, fail-closed HEAD verification of customer report URLs.
  No customer catalog mutation or R2 PUT/DELETE occurs in main().

EXIT CODES:
  0 -- All checked report objects confirmed present (not a full-history audit).
  1 -- At least one checked object confirmed missing.
  2 -- Missing/invalid catalog, invalid credentials, exhausted HEAD budget,
       or indeterminate R2 request. Never represent unknown as 404.

ENVIRONMENT (consumed):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  CF_R2_REPORTS_KEY_ID     -- Dedicated R2 token for sentinel-apex-reports bucket
  CF_R2_REPORTS_SECRET_KEY -- Dedicated R2 secret for sentinel-apex-reports bucket
  AWS_ACCESS_KEY_ID        -- Job-level R2 key (sentinel-apex-data re-upload)
  AWS_SECRET_ACCESS_KEY    -- Job-level R2 secret (sentinel-apex-data re-upload)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
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
MAX_CHECK       = 200         # Max recent index entries to verify
MAX_TOTAL_HEAD  = 400         # Max total unique keys, including feed/latest
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
    """Return an owned, normalized report object key or None.

    A third-party URL with a matching /reports/... path is NOT evidence of a
    first-party customer report.  Reject malformed, encoded, traversal, or
    non-HTML references instead of sending HEAD to an unintended object key.
    """
    if not isinstance(path_or_url, str) or not path_or_url:
        return None
    if path_or_url.startswith("https://"):
        try:
            parsed = urlparse(path_or_url)
            if (parsed.scheme != "https"
                    or parsed.hostname != "intel.cyberdudebivash.com"
                    or parsed.port not in (None, 443)
                    or parsed.username or parsed.password
                    or parsed.query or parsed.fragment):
                return None
        except ValueError:
            return None
        path_or_url = parsed.path
    elif ("://" in path_or_url or path_or_url.startswith("//")
          or "?" in path_or_url or "#" in path_or_url):
        return None

    key = path_or_url.lstrip("/")
    parts = key.split("/")
    if (len(parts) < 3 or parts[0] != "reports"
            or not key.endswith(".html")
            or any(p in ("", ".", "..") for p in parts)
            or any(c in key for c in ("\\", "%"))
            or any(ord(c) < 32 or ord(c) == 127 for c in key)):
        return None
    return key


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
    log.warning("WARN: upload failed (%d): %s", result.returncode, result.stderr.strip()[:300])
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("=" * 70)
    log.info("R2 REPORTS INDEX INTEGRITY GATE v1.0  --  STAGE 3.5.1")
    log.info("=" * 70)

    # Production integrity is mandatory; missing configuration is never success.
    # --- Credentials ---
    cf_account, reports_key, reports_sec, data_key, data_sec = _get_credentials()

    if not cf_account:
        log.warning("CF_ACCOUNT_ID not set -- skipping R2 integrity check (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_ACCOUNT_ID")
        return 2

    if not reports_key or not reports_sec:
        log.warning("No R2 credentials available -- skipping integrity check (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_CREDENTIALS")
        return 2

    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    log.info("R2 endpoint : %s", endpoint)
    log.info("Reports bucket : %s", BUCKET_REPORTS)

    # --- Load index ---
    if not INDEX_PATH.exists():
        log.warning("api/reports/index.json not found -- skipping (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_INDEX")
        return 2

    try:
        index_data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to read api/reports/index.json: %s (non-fatal)", exc)
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "ERROR_READ_INDEX")
        return 2

    if (not isinstance(index_data, dict)
            or not isinstance(index_data.get("reports"), list)
            or any(not isinstance(e, dict) for e in index_data["reports"])):
        log.error("Index schema invalid: expected reports array of objects")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_INDEX_SCHEMA")
        return 2
    all_entries: List[dict] = index_data["reports"]
    if not all_entries:
        log.info("Index has no entries -- nothing to verify")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "OK_EMPTY_INDEX")
        return 2

    log.info("Index entries: %d total", len(all_entries))

    # --- Canonical feed is mandatory; no silent empty fallback ---
    if not FEED_PATH.exists():
        log.error("Required feed missing")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_MISSING_FEED")
        return 2
    try:
        feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        log.error("Required feed unreadable or malformed")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_INVALID_FEED")
        return 2
    if not isinstance(feed, list) or any(not isinstance(e, dict) for e in feed):
        log.error("Required feed schema invalid")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_FEED_SCHEMA")
        return 2
    current_run_keys: Set[str] = set()
    for item in feed:
        ru = item.get("report_url")
        if ru in (None, ""):
            continue
        if not isinstance(ru, str):
            log.error("Feed report_url is not a string")
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_REPORT_URL_SCHEMA")
            return 2
        key = _path_to_r2_key(ru)
        if not key:
            log.error("Feed report_url cannot be mapped to a report object")
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_REPORT_URL_SCHEMA")
            return 2
        current_run_keys.add(key)
    log.info("Current-run report URLs: %d", len(current_run_keys))

    # --- Load latest.json up front (needed both to build the check set below
    #     and to purge it later) so its own entries -- which are not
    #     guaranteed to be a strict subset of index.json's checked window --
    #     are actually verified, not just carried along for the ride. v1.1
    #     FIX: previously latest.json's entries were never added to the
    #     checked key set at all, so a staleness unique to latest.json
    #     (e.g. after independent drift between the two files) could never
    #     be detected or purged by this gate.
    if not LATEST_PATH.exists():
        log.error("Required latest catalog missing")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_MISSING_LATEST")
        return 2
    try:
        latest_data = json.loads(LATEST_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        log.error("Required latest catalog unreadable or malformed")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_INVALID_LATEST")
        return 2
    if (not isinstance(latest_data, dict)
            or not isinstance(latest_data.get("reports"), list)
            or any(not isinstance(e, dict) for e in latest_data["reports"])):
        log.error("Required latest catalog schema invalid")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LATEST_SCHEMA")
        return 2
    latest_reports_raw = latest_data["reports"]

    # Every customer-facing catalog entry must map to a report object.
    # Local mapping checks are cheap and avoid an unnecessary paid R2 HEAD.
    indexed_keys: Set[str] = set()
    for entry in all_entries:
        raw = entry.get("path") or entry.get("url")
        key = _path_to_r2_key(raw) if isinstance(raw, str) else None
        if not key:
            log.error("Index contains a report with no valid R2 object mapping")
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_INDEX_REPORT_URL")
            return 2
        indexed_keys.add(key)
    for entry in latest_reports_raw:
        raw = entry.get("path") or entry.get("url")
        key = _path_to_r2_key(raw) if isinstance(raw, str) else None
        if not key:
            log.error("Latest catalog contains invalid R2 report mapping")
            _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LATEST_REPORT_URL")
            return 2
    feed_only = current_run_keys - indexed_keys
    if feed_only:
        log.error("Index is missing %d report(s) referenced by canonical feed; catalogs unchanged", len(feed_only))
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_FEED_INDEX_PARITY")
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
    for ck in current_run_keys:
        if ck not in entry_key_map:
            # Find from all_entries by key
            for entry in all_entries:
                candidate_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
                if candidate_key == ck:
                    entry_key_map[ck] = entry
                    break

    # Also include latest.json's own entries, even if absent from index.json's
    # checked window (see v1.1 FIX note above).
    for entry in latest_reports_raw:
        lk = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if lk and lk not in entry_key_map:
            entry_key_map[lk] = entry

    # Required feed URLs are independently authoritative inputs to the
    # customer delivery gate: verify them even if catalogs are inconsistent.
    all_keys_to_check = sorted(set(entry_key_map) | current_run_keys)
    if not all_keys_to_check or len(all_keys_to_check) > MAX_TOTAL_HEAD:
        log.error("HEAD coverage cannot fit budget (%d keys, max %d)", len(all_keys_to_check), MAX_TOTAL_HEAD)
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_HEAD_BUDGET_OR_EMPTY")
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

    # P0 release safety: do not remove live customer catalog entries in an
    # integrity gate. Any confirmed missing report requires an operator-led
    # reconciliation with backup and remote read-back. This stage performs
    # read-only HEAD verification; it never mutates/publishes catalog files.
    if missing_keys:
        log.error("BLOCKED: %d confirmed missing R2 report(s); catalogs preserved", len(missing_keys))
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", f"BLOCKED_MISSING_REPORTS_{len(missing_keys)}")
        return 1

    # Verification is deliberately read-only. Missing/unverifiable keys
    # have already caused a nonzero return; never silently rewrite catalogs.
    unchecked_index = max(0, len(all_entries) - len(entries_to_check))
    status = f"OK_checked={len(key_exists)}_unchecked_history={unchecked_index}"
    _write_github_env("R2_REPORTS_INTEGRITY_STATUS", status)
    log.info("READ-ONLY integrity gate complete: %d present; %d historical index entries not checked",
             len(present_keys), unchecked_index)
    return 0

if __name__ == "__main__":
    sys.exit(main())
