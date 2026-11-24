"""P0: report header and section count must share validated ATT&CK basis.

Offline, no production report overwrite, network calls or Cloudflare usage.
"""
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


def advisory(**changes):
    item = {
        "id": "intel--p0-ttp-count-fixture",
        "title": "Synthetic vulnerability advisory without observed attacker activity",
        "description": "Offline regression fixture. No active exploitation verified.",
        "timestamp": "2026-11-24T12:00:00Z",
        "source_url": "https://example.org/advisory",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "risk_score": 2.0,
        "tlp": "TLP:CLEAR",
        "iocs": [],
        "ttps": [],
        "mitre_tactics": [],
        "apex_ai": {},
    }
    item.update(changes)
    return item


def counts_from_report(html):
    # Customer-visible header and the risk section are intentionally separate
    # render surfaces. Their count must always be identical.
    header = re.search(r"TTPs:\s*<strong>(\d+)</strong>", html)
    section = re.search(
        r"TTP Count</div><div class='kv-val'>(\d+)</div>", html
    )
    assert header is not None, "missing dossier header count"
    assert section is not None, "missing validated technique count in section"
    return int(header.group(1)), int(section.group(1))


@pytest.mark.parametrize("data", [
    {},
    {"ttps": ["T1190", "T1190", "INVALID-NOT-A-TECHNIQUE"]},
    {"ttps": ["T1190.001", "T1190", "T9999.999"]},
    {"apex_ai": {"ttps": [{"id": "T1190"}, {"id": "T1059"}]}},
    {"ttps": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
     "apex_ai": {"ttps": [{"id": "T1059"}] * 10}},
])
def test_header_count_equals_section_after_filtering_and_enrichment(data):
    html = gir.render_report(advisory(**data), "https://intel.cyberdudebivash.com")
    header_count, section_count = counts_from_report(html)
    assert header_count == section_count
    assert 0 <= header_count < 100


def test_optional_metrics_parameter_keeps_previous_string_return_contract(monkeypatch):
    monkeypatch.setattr(gir, "_APEX_UPGRADE_AVAILABLE", False)
    src = advisory(ttps=["T1190", "T1190", "bogus"])
    original_html = gir.build_report_sections(dict(src))
    metrics = {}
    revised_html = gir.build_report_sections(dict(src), render_metrics=metrics)
    assert isinstance(original_html, str)
    assert original_html == revised_html
    assert isinstance(metrics["validated_ttp_count"], int)
    assert metrics["validated_ttp_count"] >= 0


def test_report_header_does_not_show_unvalidated_apex_ai_count(monkeypatch):
    monkeypatch.setattr(gir, "_APEX_UPGRADE_AVAILABLE", False)
    item = advisory(apex_ai={"ttps": [{"id": "FAKE_TTP"} for _ in range(19)]})
    html = gir.render_report(item, "https://intel.cyberdudebivash.com")
    header, section = counts_from_report(html)
    assert header == section == 0
    assert "TTPs: <strong>19</strong>" not in html
