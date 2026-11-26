"""The report's header severity tile must show the whole severity label.

The tile used to print ``display[:5]``, so every MEDIUM report said "MEDIU", every CRITICAL one "CRITI" and every
UNRATED one "UNRAT". The label is a closed vocabulary (CVSS band or UNRATED), so the fix keeps a generous sanity
bound for feed-supplied strings and fits the text with CSS instead of cutting letters.

Fixtures are the same fictional records the other report tests use; nothing here is published.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import generate_intel_reports as gir  # noqa: E402

PREFIX = "https://intel.cyberdudebivash.com"
TILE = re.compile(r"exec-tile-label'>Severity</div>\s*<div class='([^']*)'>([^<]*)</div>")


def advisory(**kwargs):
    base = {
        "id": "intel--offline-severity-tile",
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


def tile(**kwargs):
    html = gir.render_report(advisory(**kwargs), PREFIX)
    m = TILE.search(html)
    assert m, "severity tile not found in the rendered report"
    return html, m.group(1), m.group(2)


@pytest.mark.parametrize("kwargs,label", [
    (dict(severity="CRITICAL", cvss_score=9.8), "CRITICAL"),
    (dict(severity="HIGH", cvss_score=8.1), "HIGH"),
    (dict(severity="MEDIUM", cvss_score=6.5), "MEDIUM"),
    (dict(severity="LOW", cvss_score=3.1), "LOW"),
    (dict(severity="UNKNOWN", cvss_score=None, risk_score=0.6), "UNRATED"),
])
def test_tile_shows_the_complete_label(kwargs, label):
    _, _, shown = tile(**kwargs)
    assert shown == label, f"tile shows {shown!r}, expected the whole label {label!r}"


def test_tile_text_agrees_with_the_severity_chip_in_the_header():
    html, _, shown = tile(severity="MEDIUM", cvss_score=6.5)
    assert shown == "MEDIUM"
    # the header chip next to the title carries the same word; the two must never disagree
    assert re.search(r"Severity:\s*<[^>]*>\s*MEDIUM\b", html) or "MEDIUM" in html.split("exec-card", 1)[0]


def test_overlong_feed_label_is_still_bounded():
    _, _, shown = tile(severity="X" * 80, cvss_score=None, risk_score=0.1)
    assert len(shown) <= 16


def test_tile_value_is_fitted_by_css_not_by_cutting_letters():
    html, cls, _ = tile(severity="CRITICAL", cvss_score=9.8)
    assert "sev-word" in cls.split()
    css = gir.CSS
    rule = re.search(r"\.exec-tile-val\.sev-word\{([^}]*)\}", css)
    assert rule, "fit rule for the severity word is missing"
    assert "clamp(" in rule.group(1) and "white-space:nowrap" in rule.group(1)
    assert ".exec-tile-val.sev-word" in html  # the rule ships inside every rendered page
