"""P0: local report candidates must NOT masquerade as public-ready reports.

All inputs are synthetic. No Cloudflare calls, R2 writes or live publishing.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_ready_historical_selection as historical_selection  # noqa: E402
from customer_ready_historical_selection import (  # noqa: E402
    ReportSelectionBlocked, select_authorized_historical_probes,
)
from scripts import deployment_convergence_validator as validator  # noqa: E402


BASE = "https://intel.cyberdudebivash.com"
CLOCK = datetime(2026, 11, 22, 4, 0, 0, tzinfo=timezone.utc)


def fixture():
    # 51 local reports: 25 ready, 26 withheld. Same shape as observed in
    # live production, without using any actual customer data or report IDs.
    source = []
    for i in range(51):
        report_id = f"intel--{i:024x}"
        path = f"/reports/2026/11/{report_id}.html"
        timestamp = (CLOCK - timedelta(hours=10) + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
        source.append({
            "id": report_id, "path": path, "url": BASE + path,
            "timestamp": timestamp, "tlp": "TLP:CLEAR",
        })
    approved = source[::2][:25]
    local = {"schema_version": "1.0", "generated_at": "2026-11-22T03:00:00Z", "reports": source}
    public = {
        "schema_version": "2.0.0",
        "feed_type": "customer_ready_catalog",
        "generated_at": "2026-11-22T03:00:00Z",
        "validated_at": "2026-11-22T03:30:00Z",
        "policy_version": "1.0.0",
        "total_candidates": 51,
        "customer_ready_count": 25,
        "withheld_count": 26,
        "total_reports": 51,
        "reports_listed": 25,
        "reports": [dict(x) for x in approved],
    }
    return local, public


def selected(local, public):
    return select_authorized_historical_probes(
        local, public, manifest_files={}, latest_limit=15,
        historical_limit=5, now=CLOCK,
    )


def test_real_ready_cohort_five_only_not_withheld_local_candidates():
    local, public = fixture()
    got = selected(local, public)
    ready_urls = {r["url"] for r in public["reports"]}
    withheld_urls = {r["url"] for r in local["reports"] if r["url"] not in ready_urls}
    assert len(got) == len(set(got)) == 5
    assert all(url in ready_urls for url in got)
    assert set(got).isdisjoint(withheld_urls)
    expected = [public["reports"][i]["url"] for i in [0, 2, 5, 7, 9]]
    assert got == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.0"),
        ("feed_type", "raw_candidate_catalog"),
        ("total_candidates", 50),
        ("customer_ready_count", 0),
        ("reports_listed", 26),
        ("policy_version", ""),
        ("generated_at", "2026-11-20T00:00:00Z"),
        ("validated_at", "2026-11-22T05:00:00Z"),
        ("validated_at", "2026-11-22T02:00:00Z"),
    ],
)
def test_broken_schema_counts_and_freshness_fail_closed(field, value):
    local, public = fixture()
    public[field] = value
    with pytest.raises(ReportSelectionBlocked):
        selected(local, public)


def test_public_row_missing_from_local_index_rejected():
    local, public = fixture()
    local["reports"].pop(0)
    with pytest.raises(ReportSelectionBlocked, match="provenance"):
        selected(local, public)


def test_public_row_wrong_month_id_or_utc_is_blocked():
    local, public = fixture()
    public["reports"][0]["timestamp"] = "2026-11-21T15:01:00Z"
    with pytest.raises(ReportSelectionBlocked, match="provenance"):
        selected(local, public)


def test_tlp_amber_must_not_be_certified_as_ready():
    local, public = fixture()
    public["reports"][3]["tlp"] = "TLP:AMBER"
    with pytest.raises(ReportSelectionBlocked, match="Non-public"):
        selected(local, public)


def test_empty_historical_ready_cohort_must_fail():
    local, public = fixture()
    public["reports"] = public["reports"][:15]
    public["reports_listed"] = 15
    with pytest.raises(ReportSelectionBlocked, match="No historical"):
        selected(local, public)


def test_restricted_path_or_cross_origin_rejected():
    local, public = fixture()
    public["reports"][0]["url"] = "https://attacker.example/reports/2026/11/intel--aaaaaaaaaaaaaaaaaaaaaaaa.html"
    with pytest.raises(ReportSelectionBlocked, match="chronology"):
        selected(local, public)


def test_phase_five_uses_ready_only_cohort_and_requires_delivered_200(tmp_path, monkeypatch):
    local, public = fixture()
    path = tmp_path / "index.json"
    path.write_text(json.dumps(local), encoding="utf-8")
    monkeypatch.setattr(validator, "REPORTS_CATALOG_PATH", path)
    # The synthetic November 22 catalog must be evaluated at its synthetic
    # clock, not the real CI runner clock. Do not weaken production freshness.
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return CLOCK if tz is None else CLOCK.astimezone(tz)

    monkeypatch.setattr(historical_selection, "datetime", FrozenDateTime)
    # Existing strict local chronology precheck is left in place.
    monkeypatch.setattr(validator, "_fetch_live_customer_ready_catalog", lambda: public)
    expected = selected(local, public)
    seen = []

    def probe_batch(urls, label):
        seen.extend(urls)
        assert label == "Phase5-Historical"
        proofs = [
            validator.ProbeResult(url=u, status_code=200, latency_ms=1, success=True)
            for u in urls
        ]
        return proofs, len(proofs), 0

    monkeypatch.setattr(validator, "_probe_batch", probe_batch)
    phase = validator.phase5_historical_report_audit([], {"files": {}})
    assert phase.success is True
    assert seen == expected

    def no_real_deliveries(urls, label):
        proofs = [
            validator.ProbeResult(url=u, status_code=404, latency_ms=1,
                                  success=True, gate_rejected=True)
            for u in urls
        ]
        return proofs, len(proofs), 0

    monkeypatch.setattr(validator, "_probe_batch", no_real_deliveries)
    phase = validator.phase5_historical_report_audit([], {"files": {}})
    assert phase.success is False
    assert "HISTORICAL POSITIVE EVIDENCE MISSING" in phase.message


def test_phase_five_fails_closed_without_live_catalog(tmp_path, monkeypatch):
    local, _ = fixture()
    path = tmp_path / "index.json"
    path.write_text(json.dumps(local), encoding="utf-8")
    monkeypatch.setattr(validator, "REPORTS_CATALOG_PATH", path)
    monkeypatch.setattr(validator, "_fetch_live_customer_ready_catalog",
                        lambda: (_ for _ in ()).throw(OSError("synthetic network outage")))
    monkeypatch.setattr(
        validator, "_probe_batch",
        lambda *_args: pytest.fail("must never probe unverified historical URLs"),
    )
    phase = validator.phase5_historical_report_audit([], {"files": {}})
    assert phase.success is False
    assert phase.probes == []
    assert "READY-ONLY EVIDENCE MISSING" in phase.message


def test_public_catalog_fetch_is_one_bounded_canonical_get(monkeypatch):
    _, public = fixture()

    class Response(BytesIO):
        status = 200

    payload = json.dumps(public).encode("utf-8")
    observed = []

    def fake_open(request, *, timeout):
        observed.append((request.full_url, request.get_method(), timeout))
        return Response(payload)

    monkeypatch.setattr(validator, "_platform_open", fake_open)
    monkeypatch.setattr(validator, "_REQUESTS_USED", 0)
    monkeypatch.setattr(validator, "_PROTOCOL_STARTED", None)
    got = validator._fetch_live_customer_ready_catalog()
    assert got["customer_ready_count"] == 25
    assert observed[0][0] == BASE + "/api/reports/index.json"
    assert observed[0][1] == "GET"
    assert len(observed) == 1
    assert validator._REQUESTS_USED == 1


def test_public_catalog_fetch_rejects_oversized_response(monkeypatch):
    class Response(BytesIO):
        status = 200
    monkeypatch.setattr(validator, "_platform_open",
                        lambda request, *, timeout: Response(b"x" * 1_048_577))
    monkeypatch.setattr(validator, "_REQUESTS_USED", 0)
    monkeypatch.setattr(validator, "_PROTOCOL_STARTED", None)
    with pytest.raises(RuntimeError, match="byte budget"):
        validator._fetch_live_customer_ready_catalog()
