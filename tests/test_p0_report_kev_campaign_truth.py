"""P0 offline public-dossier provenance: uncertain KEV and campaign truth."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for d in (ROOT, ROOT / "scripts"):
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))

import generate_intel_reports as reports  # noqa: E402


def advisory(**updates):
    base = {
        "id": "intel--synthetic-campaign-kev",
        "title": "Synthetic CVE-2026-10001 and CVE-2026-10002 advisory",
        "description": "Offline test fixture; no verified exploitation or campaign.",
        "cve_id": "CVE-2026-10001",
        "cvss_score": 7.7,
        "severity": "HIGH",
        "risk_score": 2.0,
        "source_url": "https://example.org/advisory",
        "timestamp": "2026-11-24T12:00:00Z",
        "tlp": "TLP:CLEAR",
        "iocs": [],
        "ttps": [],
        "kev_present": False,
        "kev": False,
    }
    return {**base, **updates}


def test_empty_campaign_creates_truthful_section_12_and_no_false_attribution():
    html = reports.render_report(advisory(), "https://intel.cyberdudebivash.com")
    assert "href='#s12'" in html
    assert "id='s12'" in html
    assert "CAMPAIGN NOT ESTABLISHED" in html
    assert "Campaign correlation confirmed" not in html
    assert "tracked, multi-stage campaign" not in html


def test_source_campaign_label_must_not_leak_into_public_render():
    sentinel = "PRIVATE_CAMPAIGN_REFERENCE_TEST_ONLY"
    html = reports.render_report(
        advisory(campaign_id=sentinel, campaign_graph_intel={"private": sentinel}),
        "https://intel.cyberdudebivash.com",
    )
    assert "id='s12'" in html
    assert "CAMPAIGN REFERENCE PRESENT" in html
    assert sentinel not in html
    assert "Campaign correlation confirmed" not in html
    assert "APEX correlates" not in html


@pytest.mark.parametrize("kev_value", [False, "NO", "false"])
def test_negative_or_unverified_kev_never_claims_catalog_absence(kev_value):
    html = reports.build_report_sections(advisory(kev=kev_value, kev_present=kev_value))
    assert "CISA KEV membership was not verified" in html
    assert "no CISA KEV listing was found" not in html
    assert "Not presently on CISA KEV" not in html
    assert "Not verified in this record" in html


def test_no_apex_upgrade_fallback_still_retains_kev_uncertainty(monkeypatch):
    monkeypatch.setattr(reports, "_APEX_UPGRADE_AVAILABLE", False)
    html = reports.build_report_sections(advisory())
    assert "CISA KEV listing not verified in this advisory record" in html
    assert "Not presently on CISA KEV" not in html


def test_verifiable_kev_positive_survives_campaign_and_wording_hardening():
    html = reports.build_report_sections(advisory(kev=True, kev_present=True))
    assert "Actively exploited - CISA KEV confirmed" in html or "CISA KEV" in html
    assert "CAMPAIGN NOT ESTABLISHED" in html
