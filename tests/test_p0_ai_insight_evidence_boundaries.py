"""P0: customer-facing AI Insight must not invent exploitation forecasts.

Offline, source-backed report regression cases from the 2026-11-24 audit.
No live web requests, paid resources, R2 writes or production deployment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import apex_intelligence_upgrade as ai  # noqa: E402


def item(**overrides):
    base = {
        "id": "intel--fictional-regression",
        "title": "CVE-2026-119582 — fictional test of SQL injection",
        "description": "Synthetic only. No customer exposure or exploitation observed.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "risk_score": 0.38,
        "ttps": [],
        "iocs": [],
        "kev": False,
    }
    return {**base, **overrides}


@pytest.mark.parametrize(("severity", "risk"), [
    ("CRITICAL", 0.38),
    ("CRITICAL", 9.8),
    ("HIGH", 1.09),
    ("MEDIUM", 0.74),
])
def test_no_unsubstantiated_exploit_windows_at_any_heuristic_score(severity, risk):
    html = ai.generate_ai_insight_premium(item(severity=severity, risk_score=risk))
    assert "Evidence-led triage (no timeline forecast)" in html
    assert "not a probability or calibrated confidence" in html
    assert "LOW (30+ days)" not in html
    assert "LIKELY (72 hours" not in html
    assert "IMMINENT (24" not in html
    assert "statistically likely" not in html
    assert "high exploitation probability within the week" not in html.lower()
    assert "3–5×" not in html
    assert "APEX composite risk (not a forecast)" in html
    assert "AI analyst insight generation unavailable" not in html


def test_critical_cvss_with_low_composite_does_not_assert_low_exploit_likelihood():
    html = ai.generate_ai_insight_premium(item())
    assert "PRIORITY EXPOSURE REVIEW" in html
    assert "No exploitation timing or absence of targeting is established" not in html or "PRIORITY EXPOSURE REVIEW" in html
    assert "No signals indicate near-term targeting" not in html
    assert "0.4/10" in html
    assert "No exploit window or active exploitation" in html


def test_ep_ss_is_exactly_30_day_and_not_an_assumed_one_week_forecast(monkeypatch):
    monkeypatch.setattr(ai, "_epss_percent", lambda _: 3.664)
    html = ai.generate_ai_insight_premium(item())
    assert "3.664%" in html
    assert "next 30 days" in html
    assert "not a prediction of customer compromise" in html
    assert "within 7 days" not in html


def test_sector_risk_claims_are_questions_not_fake_ranked_exposure():
    html = ai.generate_ai_insight_premium(item())
    assert "customer asset inventory" in html
    assert "Retail &amp; E-Commerce (HIGH)" not in html
    assert "Healthcare (HIGH)" not in html
    assert "Sector-specific exposure questions (hypotheses)" in html


def test_technique_string_does_not_crash_insight_rendering():
    html = ai.generate_ai_insight_premium(item(ttps=["T1190"]))
    assert "AI analyst insight generation unavailable" not in html
    assert "Heuristic signal index" in html


def test_cisa_kev_never_asserts_a_customer_incident(monkeypatch):
    monkeypatch.setattr(ai, "_CANE_AVAILABLE", True)
    monkeypatch.setattr(ai, "_cane_kev_confirmed", lambda _: True)
    html = ai.generate_ai_insight_premium(item(kev=True))
    assert "CISA KEV LISTED" in html
    assert "That does not establish compromise of any customer environment" in html
    assert "underground markets" not in html
    assert "Expect exploitation volume to increase" not in html
