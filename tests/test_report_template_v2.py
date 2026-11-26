"""Dossier template v2: the additive layer must add value without touching the contracts other code reads.

What v2 adds: a bottom-line panel built from fields the report already computes, structured data and share metadata,
a skip link and main landmark, phone/dark/print layouts, and legible colours where legacy dark-theme text colours were
left on light panels. What must NOT change: the section wrappers and ids the integrity checks parse, the S1 severity
chip, the executive-summary labels the P0 tests slice on, and the page's script surface.

Fixtures are the same fictional records the other report tests use; nothing here is published.
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import generate_intel_reports as gir  # noqa: E402

PREFIX = "https://intel.cyberdudebivash.com"


def advisory(**kwargs):
    base = {
        "id": "intel--offline-template-v2",
        "title": "CVE-2026-119582 — synthetic SQL injection fixture",
        "description": "Fictional record for offline regression, no observed exploitation",
        "cve_id": "CVE-2026-119582",
        "cvss_score": 6.5,
        "risk_score": 0.38,
        "severity": "MEDIUM",
        "timestamp": "2026-11-24T12:00:00Z",
        "source_url": "https://example.org/advisory",
        "tlp": "TLP:CLEAR",
        "iocs": [], "ttps": [], "kev": False, "kev_present": False,
    }
    return {**base, **kwargs}


def render(**kwargs):
    return gir.render_report(advisory(**kwargs), PREFIX)


def ld_json(html):
    m = re.search(r"<script type='application/ld\+json'>(.*?)</script>", html, re.S)
    assert m, "structured data block missing"
    return json.loads(m.group(1))


class TestContractsOtherCodeReads:
    @pytest.mark.parametrize("kwargs,label", [
        (dict(severity="CRITICAL", cvss_score=9.8), "CRITICAL"),
        (dict(severity="HIGH", cvss_score=8.1), "HIGH"),
        (dict(severity="MEDIUM", cvss_score=6.5), "MEDIUM"),
        (dict(severity="LOW", cvss_score=3.1), "LOW"),
    ])
    def test_integrity_check_can_still_read_the_s1_severity_chip(self, kwargs, label):
        # generate_intel_reports._dossier_severity_matches_value parses <div class='section' id='s1'> .. id='s2'>
        assert gir._dossier_severity_matches_value(render(**kwargs), label)

    def test_every_section_wrapper_and_id_is_still_there(self):
        html = render()
        for n in range(1, 21):
            assert f"<div class='section' id='s{n}'>" in html, f"section s{n} wrapper missing"

    def test_executive_summary_labels_the_p0_tests_slice_on_are_unchanged(self):
        html = render()
        assert html.count("WHAT TO DO TODAY?") == 1, "the bottom-line panel must not reuse the executive-summary labels"
        assert html.count("WHAT HAPPENED?") == 1 and html.count("EXECUTIVE INTELLIGENCE LAYER") == 1

    def test_meta_description_keeps_the_format_the_index_builder_parses(self):
        html = render()
        desc = re.search(r"<meta name='description' content='([^']*)'", html).group(1)
        assert re.search(r"Severity\s+\w+.*?Risk\s+[\d.]+/10", desc)
        # and it is the FIRST description-like meta in the page (the builder takes the first match)
        assert html.index("name='description'") < html.index("og:description")

    def test_the_only_script_is_the_non_executable_structured_data_block(self):
        html = render()
        scripts = re.findall(r"<script\b[^>]*>", html)
        assert scripts == ["<script type='application/ld+json'>"]


class TestBottomLine:
    def test_panel_is_present_once_above_the_stat_tiles_and_the_sections(self):
        html = render()
        assert html.count("class='glance ") == 1
        assert html.index("class='glance ") < html.index("<div class='exec-card'>") < html.index("id='s1'")

    def test_panel_uses_the_single_action_policy_and_does_not_repeat_the_label(self):
        html = render(severity="MEDIUM", cvss_score=6.5)
        pill = re.search(r"class='glance-pill'>([^<]*)<", html).group(1)
        action = re.search(r"class='glance-action'>([^<]*)<", html).group(1)
        assert pill == "PATCH STANDARD"
        assert not action.upper().startswith(pill), "the action sentence repeats the pill"
        assert action[:1].isupper() and "vendor fix" in action

    def test_panel_makes_no_claim_beyond_the_reports_own_caveat(self):
        html = render()
        panel = re.search(r"<aside class='glance.*?</aside>", html, re.S).group(0)
        text = re.sub(r"<[^>]+>", " ", panel)
        assert "No independent customer-specific compromise" in text
        # the words the index builder's severity/risk regex keys on never appear in the panel
        assert not re.search(r"\bSeverity\b|\bRisk\b", text)

    def test_unrated_record_is_never_styled_as_a_severity(self):
        html = render(severity="UNKNOWN", cvss_score=None, risk_score=0.6)
        assert "class='glance sev-neutral'" in html
        assert "Rating <strong>UNRATED</strong>" in html

    def test_reading_time_is_a_positive_whole_number(self):
        m = re.search(r"class='glance-read'>(\d+) min read<", render())
        assert m and int(m.group(1)) >= 1


class TestStructuredDataAndSharing:
    def test_json_ld_is_a_valid_article_with_only_known_facts(self):
        ld = ld_json(render())
        assert ld["@type"] == "TechArticle" and ld["isAccessibleForFree"] is True
        assert ld["url"] == ld["mainEntityOfPage"] and ld["url"].startswith(PREFIX)
        assert ld["datePublished"] == "2026-11-24T12:00:00Z"
        assert [a["identifier"] for a in ld["about"]] == ["CVE-2026-119582"]

    def test_json_ld_omits_dates_it_cannot_prove(self):
        ld = ld_json(render(timestamp="not-a-timestamp"))
        assert "datePublished" not in ld and "dateModified" not in ld

    def test_json_ld_cannot_break_out_of_its_script_element(self):
        html = render(title="</script><img src=x onerror=alert(1)>")
        block = re.search(r"<script type='application/ld\+json'>(.*?)</script>", html, re.S).group(1)
        assert "<" not in block and ">" not in block and "&" not in block, "raw markup characters reached the data block"
        assert json.loads(block)["headline"] == "</script><img src=x onerror=alert(1)>"   # still valid JSON, same text
        # the data block closes exactly once, where the template closes it
        assert html.count("<script type='application/ld+json'>") == 1 and re.findall(r"<script\b[^>]*>", html) == ["<script type='application/ld+json'>"]

    def test_share_metadata_is_complete(self):
        html = render()
        for needle in ("property='og:image'", "property='og:url'", "name='twitter:card' content='summary_large_image'",
                       "name='color-scheme' content='light dark'", "name='theme-color'"):
            assert needle in html, needle


class TestAccessibilityAndLayout:
    def test_skip_link_targets_a_focusable_main_landmark(self):
        html = render()
        assert "<a class='skip-link' href='#report-main'>" in html
        assert "<main id='report-main' tabindex='-1'>" in html

    def test_executive_layer_has_the_hook_the_phone_layout_needs(self):
        assert "class='exec-layer' style='background:#0a0a1a" in render()

    def test_template_v2_css_ships_in_every_page_and_covers_phone_dark_and_print(self):
        html = render()
        css = gir.CSS_V2
        assert css in html
        assert ".exec-layer td{" in css and "display:block!important" in css
        assert "@media(prefers-color-scheme:dark)" in css and "@media print" in css
        assert "minmax(0,1fr)" in css, "stat tiles must not blow out on narrow screens"
        assert "minmax(min(100%,280px),1fr)" in css

    def test_legacy_dark_theme_text_colours_are_overridden_on_light_panels(self):
        css = gir.CSS_V2
        assert ".step p,.reg-trigger,.plv2-feat{color:#292524}" in css
        assert "#c8d3e8" not in css
        assert ".dossier-ftr a[href*='plan=pro']{color:#92400e!important" in css

    def test_dark_rules_do_not_recolour_the_sidebar_call_to_action(self):
        # the contents-list rule must be scoped to in-page anchors, or the gold button text goes grey on gold
        css = gir.CSS_V2
        assert ".toc-aside a[href^='#']{color:var(--muted)!important" in css
        assert ".toc-aside a{color" not in css
