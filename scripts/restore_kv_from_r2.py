#!/usr/bin/env python3
"""
scripts/restore_kv_from_r2.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Cloudflare KV Namespace Restore from R2

Restores a KV namespace from a daily snapshot JSON file previously written by
scripts/backup_kv_to_r2.py (key schema: kv-snapshots/{YYYY-MM-DD}/{namespace_name}.json).
Companion to that script, which has no restore counterpart.

Env vars required:
  CF_API_TOKEN            - CF token with KV:Write permission
  CF_ACCOUNT_ID           - Cloudflare account ID
  CF_R2_ACCESS_KEY_ID     - R2 S3-compatible access key
  CF_R2_SECRET_ACCESS_KEY - R2 S3-compatible secret key
  CF_R2_ENDPOINT          - https://<account_id>.r2.cloudflarestorage.com
  CF_R2_BUCKET            - source bucket (default: sentinel-apex-data)

Usage:
  python3 scripts/restore_kv_from_r2.py --namespace API_KEYS_KV --date 2026-07-28 [--dry-run]
"""
import os
import sys
import json
import time
import hashlib
import hmac
import argparse
import datetime
import re
import urllib.request
import urllib.error
import urllib.parse

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    # Keep offline validation importable without cloud SDKs. Live R2 access
    # still fails closed inside download_snapshot() if boto3 is unavailable.
    boto3 = None
    class ClientError(Exception):
        pass

CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_R2_ACCESS_KEY = os.environ.get("CF_R2_ACCESS_KEY_ID", "")
CF_R2_SECRET_KEY = os.environ.get("CF_R2_SECRET_ACCESS_KEY", "")
CF_R2_ENDPOINT = os.environ.get("CF_R2_ENDPOINT", "")
CF_R2_BUCKET = os.environ.get("CF_R2_BUCKET", "sentinel-apex-data")

KV_NAMESPACES = {
    "API_KEYS_KV":      "ca786702c6df47b7a95d9777536c7cfb",
    "RATE_LIMIT_KV":    "647efdda28dc4a2db91378931cfa02dc",
    "ANALYTICS_KV":     "baa66e510f7247d4b268af943bfb7213",
    "SECURITY_HUB_KV":  "95faae90943f43afa26d552b8385d339",
}


MAX_RESTORE_KEYS = 500
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
_KV_WRITE_PATH = re.compile(
    r"^/accounts/([0-9a-fA-F]{32})/storage/kv/namespaces/([0-9a-fA-F]{32})/values/[^/?#]+$"
)


class _NoCloudflareBearerRedirect(urllib.request.HTTPRedirectHandler):
    """Reject all redirects, including same-origin redirects carrying a token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cf_put(path, body_bytes):
    """Write only to an approved Cloudflare KV namespace and exact account."""
    match = _KV_WRITE_PATH.fullmatch(path) if isinstance(path, str) else None
    if (not CF_API_TOKEN or not re.fullmatch(r"[0-9a-fA-F]{32}", CF_ACCOUNT_ID)
            or not match or match.group(1).lower() != CF_ACCOUNT_ID.lower()
            or match.group(2).lower() not in {v.lower() for v in KV_NAMESPACES.values()}
            or not isinstance(body_bytes, bytes)):
        raise ValueError("CF_KV_RESTORE_WRITE_DESTINATION_REJECTED")
    url = f"{CF_API_BASE}{path}"
    req = urllib.request.Request(
        url,
        data=body_bytes,
        method="PUT",
        headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
    )
    try:
        opener = urllib.request.build_opener(_NoCloudflareBearerRedirect)
        with opener.open(req, timeout=30) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("success") is not True:
                raise RuntimeError("CF_KV_RESTORE_WRITE_NOT_ACKNOWLEDGED")
            return doc
    except urllib.error.HTTPError as e:
        # Do not echo URL path (which contains a customer KV key), response
        # body, Authorization header, or the transport exception itself.
        raise RuntimeError(f"CF_KV_RESTORE_WRITE_HTTP_{e.code}") from None
    except Exception as e:
        raise RuntimeError(f"CF_KV_RESTORE_TRANSPORT_{type(e).__name__}") from None


def put_kv_value(ns_id, key, value):
    path = f"/accounts/{CF_ACCOUNT_ID}/storage/kv/namespaces/{ns_id}/values/{urllib.parse.quote(key, safe='')}"
    return cf_put(path, value.encode("utf-8"))


def validate_date(date: str) -> None:
    try:
        parsed = datetime.date.fromisoformat(date)
        if parsed.isoformat() != date:
            raise ValueError("noncanonical")
    except (TypeError, ValueError):
        raise ValueError("KV_RESTORE_INVALID_DATE") from None


def validate_r2_endpoint(endpoint: str) -> None:
    """Prevent S3 credentials reaching HTTP, userinfo, or another R2 account."""
    target = urllib.parse.urlsplit(endpoint)
    account = target.hostname or ""
    if (target.scheme != "https" or target.netloc != account
            or target.path not in {"", "/"} or target.query or target.fragment
            or not re.fullmatch(r"[0-9a-f]{32}\.r2\.cloudflarestorage\.com", account)
            or (CF_ACCOUNT_ID and account != f"{CF_ACCOUNT_ID.lower()}.r2.cloudflarestorage.com")):
        raise ValueError("KV_RESTORE_UNTRUSTED_R2_ENDPOINT")


def download_snapshot(ns_name, date):
    validate_date(date)
    if ns_name not in KV_NAMESPACES:
        raise ValueError("KV_RESTORE_INVALID_NAMESPACE")
    validate_r2_endpoint(CF_R2_ENDPOINT)
    if not all([CF_R2_ACCESS_KEY, CF_R2_SECRET_KEY, CF_R2_ENDPOINT]) or boto3 is None:
        raise RuntimeError("KV_RESTORE_R2_CREDENTIALS_OR_SDK_UNAVAILABLE")
    s3 = boto3.client(
        "s3",
        endpoint_url=CF_R2_ENDPOINT,
        aws_access_key_id=CF_R2_ACCESS_KEY,
        aws_secret_access_key=CF_R2_SECRET_KEY,
        region_name="auto",
    )
    key = f"kv-snapshots/{date}/{ns_name}.json"
    try:
        obj = s3.get_object(Bucket=CF_R2_BUCKET, Key=key)
        raw = obj["Body"].read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise ValueError("KV_RESTORE_SNAPSHOT_TOO_LARGE")
        return json.loads(raw.decode("utf-8"))
    except ClientError:
        raise RuntimeError("KV_RESTORE_R2_SNAPSHOT_UNAVAILABLE") from None


def verify_checksum(snapshot):
    entries = snapshot.get("entries", {})
    expected = snapshot.get("checksum_sha256", "")
    actual = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    return (isinstance(expected, str) and hmac.compare_digest(actual, expected),
            expected, actual)


def validate_snapshot(ns_name, ns_id, snapshot):
    """Validate every entry and all ownership metadata BEFORE the first write.

    SHA-256 protects against accidental corruption, NOT against a malicious
    actor who can alter both the snapshot and checksum. Restore remains a
    separately authorized DR action, never an unattended CI operation.
    """
    if (not isinstance(snapshot, dict) or snapshot.get("namespace") != ns_name
            or snapshot.get("namespace_id") != ns_id
            or snapshot.get("errors") != 0):
        raise ValueError("KV_RESTORE_SNAPSHOT_OWNERSHIP_OR_EXPORT_INVALID")
    entries = snapshot.get("entries")
    if (not isinstance(entries, dict) or len(entries) > MAX_RESTORE_KEYS
            or snapshot.get("count") != len(entries)):
        raise ValueError("KV_RESTORE_SNAPSHOT_INCOMPLETE_OR_OVERSIZED")
    if any(not isinstance(k, str) or not k or not isinstance(v, str)
           for k, v in entries.items()):
        raise ValueError("KV_RESTORE_SNAPSHOT_KEY_VALUE_INVALID")
    ok, _, _ = verify_checksum(snapshot)
    if not ok:
        raise ValueError("KV_RESTORE_SNAPSHOT_CHECKSUM_INVALID")
    return entries


def restore_namespace(ns_name, ns_id, snapshot, dry_run):
    try:
        entries = validate_snapshot(ns_name, ns_id, snapshot)
    except (ValueError, TypeError):
        print("  BLOCK: snapshot ownership, schema, completeness or checksum invalid")
        return False
    print(f"  Snapshot exported_at={snapshot.get('exported_at')} count={len(entries)}")

    restored, errors = 0, 0
    for i, (key, value) in enumerate(entries.items()):
        if value is None:
            continue
        if dry_run:
            restored += 1
            continue
        try:
            put_kv_value(ns_id, key, value)
            restored += 1
        except Exception as e:
            # Neither customer KV key names nor transport errors are safe logs.
            print(f"    WARN: KV restore entry {i + 1} failed ({type(e).__name__})")
            errors += 1
        if i > 0 and i % 100 == 0:
            print(f"    Progress: {i}/{len(entries)} keys restored...")
            time.sleep(0.05)

    verb = "Would restore" if dry_run else "Restored"
    print(f"  [{'DRY RUN' if dry_run else 'LIVE'}] {verb} {restored} keys ({errors} errors) to {ns_name}")
    return errors == 0


def main():
    parser = argparse.ArgumentParser(description="Restore a Cloudflare KV namespace from an R2 backup snapshot")
    parser.add_argument("--namespace", required=True, choices=sorted(KV_NAMESPACES), help="KV namespace to restore")
    parser.add_argument("--date", required=True, help="Snapshot date, YYYY-MM-DD (must match a date backup_kv_to_r2.py already ran for)")
    parser.add_argument("--dry-run", action="store_true", help="Verify and report only -- write nothing to KV")
    parser.add_argument(
        "--confirm-live-restore", default="",
        help="Required for LIVE writes: exact NAMESPACE:YYYY-MM-DD acknowledgement",
    )
    args = parser.parse_args()

    try:
        validate_date(args.date)
    except ValueError:
        print("FATAL: snapshot date must be canonical YYYY-MM-DD")
        sys.exit(2)
    if not args.dry_run and args.confirm_live_restore != f"{args.namespace}:{args.date}":
        print("FATAL: LIVE KV restore requires explicit --confirm-live-restore NAMESPACE:YYYY-MM-DD")
        sys.exit(2)

    if not args.dry_run and not CF_API_TOKEN:
        print("FATAL: CF_API_TOKEN not set")
        sys.exit(1)
    if not args.dry_run and not CF_ACCOUNT_ID:
        print("FATAL: CF_ACCOUNT_ID not set")
        sys.exit(1)

    ns_id = KV_NAMESPACES[args.namespace]
    print(f"=== SENTINEL APEX KV Restore <- R2 | Namespace: {args.namespace} | Date: {args.date} | dry_run={args.dry_run} ===")

    snapshot = download_snapshot(args.namespace, args.date)
    success = restore_namespace(args.namespace, ns_id, snapshot, args.dry_run)

    if not success:
        print("\nFATAL: restore completed with errors -- see warnings above.")
        sys.exit(1)

    print("\n=== KV restore complete. ===")


if __name__ == "__main__":
    main()
