"""P0: customer catalog and dossier agree on source-backed same-CVE CVSS.

These fixtures remain offline; they do not publish reports or assume a
third-party CVSS value is independently verified.
"""
from scripts.build_reports_index import (
    _catalog_cvss_fallback_index as build,
    _catalog_resolved_cvss as resolve,
)


def test_same_cve_feed_fallback_matches_report_renderer():
    rows = [{"title": "CVE-2026-99998 vendor flaw"},
            {"title": "CVE-2026-99998 technical advisory", "cvss_score": 9.4}]
    assert resolve(rows[0], build(rows)) == 9.4


def test_no_cve_never_borrows_risk_score():
    rows = [{"title": "Malware telemetry", "risk_score": 9.9}]
    assert resolve(rows[0], build(rows)) is None


def test_different_cves_cannot_borrow_each_other_score():
    rows = [{"title": "CVE-2026-12345"}, {"title": "CVE-2026-12346", "cvss_score": 9.6}]
    assert resolve(rows[0], build(rows)) is None


def test_own_reported_cvss_takes_precedence():
    rows = [{"title": "CVE-2026-10001", "cvss_score": 4.4},
            {"title": "CVE-2026-10001", "cvss_score": 9.4}]
    assert resolve(rows[0], build(rows)) == 4.4


def test_explicit_cve_ids_supported_without_title():
    rows = [{"cve_id": "CVE-2026-10003"},
            {"cve_ids": ["CVE-2026-10003"], "cvss_score": 8.0}]
    assert resolve(rows[0], build(rows)) == 8.0


def test_epss_only_first_match_never_fabricates_a_cvss_rating():
    rows = [{"title": "CVE-2026-10004", "epss_score": 0.02},
            {"title": "CVE-2026-10004", "cvss_score": 9.0}]
    assert resolve(rows[0], build(rows)) is None


def test_malformed_feed_entries_are_ignored():
    rows = [None, "bad", {"title": "CVE-2026-10005"}]
    assert resolve(rows[-1], build(rows)) is None


def test_title_cve_identifiers_are_case_insensitive():
    rows = [{"title": "cve-2026-10006"},
            {"title": "CVE-2026-10006", "cvss_score": 7.8}]
    assert resolve(rows[0], build(rows)) == 7.8
