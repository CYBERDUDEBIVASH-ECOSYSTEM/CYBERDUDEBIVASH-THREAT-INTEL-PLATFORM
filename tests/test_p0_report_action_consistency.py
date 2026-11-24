"""P0 exact-head regression: same action in report banner and CISO executive row."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for parent in (ROOT, ROOT / "scripts"):
    if str(parent) not in sys.path:
        sys.path.insert(0, str(parent))

import generate_intel_reports as gir  # noqa: E402


@pytest.mark.parametrize(("severity", "cve", "kev", "prioritized", "label"), [
    ("CRITICAL", True, False, True, "URGENT PATCH ASSESSMENT"),
    ("CRITICAL", True, True, True, "PATCH IMMEDIATELY"),
    ("HIGH", True, False, True, "HIGH PRIORITY"),
    ("MEDIUM", True, False, True, "PATCH STANDARD"),
    ("LOW", True, False, True, "MONITOR"),
    ("HIGH", False, False, True, "URGENT REVIEW"),
    ("UNKNOWN", True, False, False, "TRIAGE REQUIRED"),
])
def test_one_authoritative_action_label(severity, cve, kev, prioritized, label):
    badge, action = gir._public_report_action_contract(severity, cve, kev, prioritized)
    assert badge == label
    assert action.startswith(label)
    assert "7 DAYS" not in action
    assert "14 DAYS" not in action
    assert "significant exploitation probability" not in action.lower()
    assert "customer compromised" not in action.lower()


def advisory(**kwargs):
    base = {
        "id": "intel--offline-risk-urgency",
        "title": "CVE-2026-119582 — synthetic SQL injection fixture",
        "description": "Fictional record for offline regression, no observed exploitation",
        "cve_id": "CVE-2026-119582",
        "cvss_score": 9.8,
        "risk_score": 0.38,
        "severity": "CRITICAL",
        "timestamp": "2026-11-24T12:00:00Z",
        "source_url": "https://example.org/advisory",
        "tlp": "TLP:CLEAR",
        "iocs": [], "ttps": [], "kev": False, "kev_present": False,
    }
    return {**base, **kwargs}


def test_critical_low_heuristic_report_banner_agrees_with_executive_row():
    html = gir.render_report(advisory(), "https://intel.cyberdudebivash.com")
    # Match the two human-visible surfaces without relying on their styling.
    assert re.search(r"urgency-badge[^>]*>.*?URGENT PATCH ASSESSMENT</span>", html, re.S)
    exec_fragment = html.split("WHAT TO DO TODAY?", 1)[1].split("</tr>", 1)[0]
    assert "URGENT PATCH ASSESSMENT" in exec_fragment
    assert "PATCH WITHIN 7 DAYS" not in exec_fragment
    assert "significant exploitation probability" not in exec_fragment.lower()
    assert "CUSTOMER EXPOSURE: UNKNOWN" in html


def test_confirmed_kev_action_not_downgraded_by_heuristic():
    label, msg = gir._public_report_action_contract("CRITICAL", True, True, True)
    assert label == "PATCH IMMEDIATELY"
    assert "CISA KEV" in msg
    assert "Customer compromise is not established" in msg


def test_without_authoritative_rating_do_not_assign_patch_timeline():
    label, msg = gir._public_report_action_contract("CRITICAL", True, False, False)
    assert label == "TRIAGE REQUIRED"
    assert "no authoritative CVSS" in msg


def test_unverified_kev_is_not_reported_as_authoritative_not_listed():
    html = gir.render_report(advisory(
        title="Two-CVE fictional news story CVE-2026-10001 and CVE-2026-10002",
        kev=False, kev_present=False,
    ), "https://intel.cyberdudebivash.com")
    assert "KEV: <strong>Not verified in this record</strong>" in html
    assert "KEV status not verified" in html
    assert "NOT VERIFIED — check each CVE against the current CISA catalog" in html
    assert "No KEV listing found" not in html
    assert "No KEV entry" not in html
