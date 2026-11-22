"""Fail-closed historical probes from the canonical PUBLIC customer-ready catalog.

The local R2 build index (schema 1) contains report candidates including reports
properly withheld by the Worker publication gate. Its chronology alone can NEVER
establish public eligibility. A live schema-2 public ready-only snapshot, bounded
by validation timestamps and cross-checked against that local index, is required.

This module is pure: it performs no HTTP requests, R2 operations, or writes.
Actual successful public HEAD probes remain mandatory in deployment convergence.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from .report_chronology_integrity import audit_catalog, _utc
    from .strict_report_probe_selection import ReportSelectionBlocked, select_report_probes
except ImportError:
    from report_chronology_integrity import audit_catalog, _utc
    from strict_report_probe_selection import ReportSelectionBlocked, select_report_probes


MAX_CATALOG_AGE = timedelta(hours=24)
FUTURE_SKEW = timedelta(minutes=5)


def select_authorized_historical_probes(
    local_catalog: Any, public_catalog: Any, *, manifest_files: Any,
    latest_limit: int = 15, historical_limit: int = 5,
    now: datetime | None = None,
) -> list[str]:
    """Return public ready-only historical candidates, not delivery proof.

    Fail CLOSED on invalid counts, stale/invalid generation, inconsistent local
    provenance, missing historical cohort, TLP restrictions, or path anomalies.
    """
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ReportSelectionBlocked("Audit clock must be timezone-aware")
    if not isinstance(public_catalog, dict) or (
        public_catalog.get("schema_version") != "2.0.0"
        or public_catalog.get("feed_type") != "customer_ready_catalog"
    ):
        raise ReportSelectionBlocked("Live customer-ready catalog schema invalid")

    generated = _utc(public_catalog.get("generated_at"))
    validated = _utc(public_catalog.get("validated_at"))
    if (generated is None or validated is None
            or validated < generated or generated > clock + FUTURE_SKEW
            or validated > clock + FUTURE_SKEW
            or clock - generated > MAX_CATALOG_AGE
            or clock - validated > MAX_CATALOG_AGE):
        raise ReportSelectionBlocked("Live customer-ready catalog freshness unverified")
    if not isinstance(public_catalog.get("policy_version"), str) or not public_catalog["policy_version"].strip():
        raise ReportSelectionBlocked("Live customer-ready catalog policy missing")

    keys = ("total_candidates", "customer_ready_count", "withheld_count",
            "total_reports", "reports_listed")
    if any(type(public_catalog.get(k)) is not int or public_catalog[k] < 0 for k in keys):
        raise ReportSelectionBlocked("Live customer-ready catalog counts invalid")
    candidate_count = public_catalog["total_candidates"]
    ready_count = public_catalog["customer_ready_count"]
    withheld_count = public_catalog["withheld_count"]
    listed = public_catalog["reports_listed"]
    reports = public_catalog.get("reports")
    if (not isinstance(reports, list) or not candidate_count
            or ready_count + withheld_count != candidate_count
            or public_catalog["total_reports"] != candidate_count
            or listed != len(reports) or listed > ready_count
            or ready_count == 0 or listed == 0):
        raise ReportSelectionBlocked("Live customer-ready catalog counts inconsistent")

    # Local evidence may include legitimately withheld rows; preserve strict
    # chronology and Pages-manifest boundary for its candidate set.
    select_report_probes(
        local_catalog, manifest_files=manifest_files,
        latest_limit=latest_limit, historical_limit=historical_limit,
    )
    if not isinstance(local_catalog, dict):
        raise ReportSelectionBlocked("Local report candidate catalog invalid")
    local_by_path = {
        row["path"]: row for row in local_catalog.get("reports", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }

    public_chronology = audit_catalog(
        public_catalog, latest_limit=latest_limit, history_limit=historical_limit,
        at=clock, maximum_age_hours=24, historical_strategy="spread",
    )
    if public_chronology["verdict"] != "CHRONOLOGY_PRECHECK_ONLY":
        raise ReportSelectionBlocked(
            "Live customer-ready catalog chronology invalid: "
            + "; ".join(public_chronology.get("defects", []))
        )

    for row in reports:
        # The public Worker is already the eligibility authority. For extra
        # defense in depth, verify the TLP and that every public row comes
        # from this runner's canonical R2 candidate index with the same ID
        # and UTC publication time. Never invent or widen a report URL.
        if row.get("tlp") != "TLP:CLEAR":
            raise ReportSelectionBlocked("Non-public report in public-ready catalog")
        original = local_by_path.get(row["path"])
        if (original is None or original.get("id") != row["id"]
                or _utc(original.get("timestamp")) != _utc(row["timestamp"])):
            raise ReportSelectionBlocked("Public-ready report provenance disagrees with local R2 index")

    historical = public_chronology["historical"]
    if not historical:
        raise ReportSelectionBlocked("No historical ready-only cohort distinct from latest")
    if len(historical) > historical_limit:
        raise ReportSelectionBlocked("Historical probe budget exceeded")
    return historical
