"""P0 fail-closed P26 worldwide certificate provenance validation.

This validates evidence produced within the current CI run. It does not certify
customer delivery, R2, billing, or deployment.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone


_REQUIRED_AUDITS = tuple(f"A{i}" for i in range(1, 14))
_MAX_CERT_AGE_SECONDS = 4 * 60 * 60
_MAX_FUTURE_SKEW_SECONDS = 300


def validate_p26_worldwide_report(report, *, expected_items=None, now=None,
                                  current_run_id=None, current_sha=None):
    """Return (passes, opaque reason code); never emit feed IDs or report payloads."""
    if not isinstance(report, dict):
        return False, "INVALID_CERTIFICATE"

    if report.get("release_tier") != "WORLDWIDE_RELEASE":
        return False, "P26_NOT_WORLDWIDE"
    blockers = report.get("blocker_count")
    warnings = report.get("warning_count")
    if type(blockers) is not int or blockers != 0 or type(warnings) is not int or warnings != 0:
        return False, "P26_AUDIT_NOT_CLEAN"

    audits = report.get("audits")
    if not isinstance(audits, dict) or any(
        not isinstance(audits.get(code), dict)
        or audits[code].get("passed") is not True for code in _REQUIRED_AUDITS
    ):
        return False, "P26_AUDIT_NOT_CLEAN"

    count = report.get("feed_items")
    if type(count) is not int or count < 1:
        return False, "P26_FEED_COUNT_INVALID"
    if expected_items is not None and count != expected_items:
        return False, "P26_FEED_COUNT_MISMATCH"

    stamp = report.get("generated_at")
    if not isinstance(stamp, str):
        return False, "P26_TIMESTAMP_INVALID"
    try:
        generated = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return False, "P26_TIMESTAMP_INVALID"
    if generated.tzinfo is None:
        return False, "P26_TIMESTAMP_INVALID"
    generated = generated.astimezone(timezone.utc)
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ValueError("The verification clock must be timezone-aware")
    age = (clock.astimezone(timezone.utc) - generated).total_seconds()
    if age < -_MAX_FUTURE_SKEW_SECONDS or age > _MAX_CERT_AGE_SECONDS:
        return False, "P26_CERTIFICATE_STALE_OR_FUTURE"

    ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    if current_run_id is None and ci:
        current_run_id = os.environ.get("GITHUB_RUN_ID")
    if current_sha is None and ci:
        current_sha = os.environ.get("GITHUB_SHA")
    if ci and (not current_run_id or not current_sha):
        return False, "P26_RUN_ATTESTATION_MISSING"
    if current_run_id is not None and report.get("github_run_id") != str(current_run_id):
        return False, "P26_RUN_ID_MISMATCH"
    if current_sha is not None and report.get("github_sha") != current_sha:
        return False, "P26_SOURCE_SHA_MISMATCH"

    return True, "P26_CURRENT_RUN_WORLDWIDE_AUDITS_ONLY"
