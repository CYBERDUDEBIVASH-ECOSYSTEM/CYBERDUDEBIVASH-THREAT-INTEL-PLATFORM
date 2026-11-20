"""
tests/test_report_registry_single_writer.py — CyberDudeBivash SENTINEL APEX

Regression tests for the F-02 fix (report-index dual-writer conflict).

Background: scripts/build_reports_index.py (sentinel-apex.yml STAGE 3.3.7)
is the sole authoritative writer of api/reports/index.json,
api/reports/latest.json, and api/reports/stats.json -- it scans the real
reports/ directory on disk and produces report_url values that resolve to
actual HTML files. scripts/generate_dashboard_feeds.py (run from a separate,
independently-scheduled workflow, dashboard-feeds-sync.yml) used to ALSO
write api/reports/index.json and api/reports/stats.json, derived from a
severity-filtered subset of feed items with fabricated /api/reports/{id}.json
URLs that never resolved to a real report file. Two writers racing on the
same R2 keys with incompatible schemas produced a flapping, internally
inconsistent report registry: live production was observed serving
index.json with total_reports=329 and latest.json with total_reports=0 from
what should have been the same authoritative source.

This file also verifies that scripts/r2_reports_integrity.py preserves
customer catalogs on any proven R2 object loss, including latest-only drift.
Automatic purging was retired as an unsafe response to delivery uncertainty.
"""
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import generate_dashboard_feeds  # noqa: E402
import r2_reports_integrity as integrity  # noqa: E402


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestGenerateDashboardFeedsDoesNotWriteReportRegistry:
    """generate_dashboard_feeds.py must never write api/reports/index.json or
    api/reports/stats.json -- that is build_reports_index.py's exclusive
    responsibility. Regression guard for the F-02 dual-writer conflict."""

    def test_does_not_create_reports_index_or_stats(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_json(tmp_path / "api" / "feed.json", [
            {
                "id": "intel--test1", "title": "Test Advisory", "severity": "CRITICAL",
                "risk_score": 9.0, "published_at": "2026-08-10T00:00:00Z",
                "cve_ids": ["CVE-2026-0001"],
            },
        ])

        generate_dashboard_feeds.main()

        assert not (tmp_path / "api" / "reports" / "index.json").exists(), (
            "generate_dashboard_feeds.py must not write api/reports/index.json "
            "-- build_reports_index.py is the sole authoritative writer (F-02)"
        )
        assert not (tmp_path / "api" / "reports" / "stats.json").exists(), (
            "generate_dashboard_feeds.py must not write api/reports/stats.json "
            "-- build_reports_index.py is the sole authoritative writer (F-02)"
        )
        # Positive control: the script still does its actual job.
        assert (tmp_path / "api" / "v1" / "intel" / "stats.json").exists()
        assert (tmp_path / "api" / "v1" / "intel" / "campaigns.json").exists()
        # Same single-writer rule for api/v1/intel/apex.json (P0 Phase 3C):
        # generate_api_manifests.py is its sole producer. This assertion used
        # to require the competing SUMMARY write that caused the schema drift.
        assert not (tmp_path / "api" / "v1" / "intel" / "apex.json").exists()


class TestR2ReportsIntegrityPreservesCatalogs:
    """P0: missing R2 objects block delivery without altering registry bytes.

    Historical F-02 coverage previously asserted destructive index/latest
    purges. The verified safety contract is now fail-closed preservation.
    The registry's sole authorized writer remains build_reports_index.py.
    """

    def _setup(self, tmp_path, monkeypatch, index, latest, missing_id):
        monkeypatch.setenv("CF_ACCOUNT_ID", "test-account")
        monkeypatch.setenv("CF_R2_REPORTS_KEY_ID", "test-key")
        monkeypatch.setenv("CF_R2_REPORTS_SECRET_KEY", "test-secret")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.setattr(integrity, "INDEX_PATH", tmp_path / "api" / "reports" / "index.json")
        monkeypatch.setattr(integrity, "LATEST_PATH", tmp_path / "api" / "reports" / "latest.json")
        monkeypatch.setattr(integrity, "FEED_PATH", tmp_path / "api" / "feed.json")
        _write_json(integrity.INDEX_PATH, index)
        _write_json(integrity.LATEST_PATH, latest)
        _write_json(integrity.FEED_PATH, [])
        before = (integrity.INDEX_PATH.read_bytes(), integrity.LATEST_PATH.read_bytes())
        monkeypatch.setattr(integrity, "_r2_object_exists",
                            lambda key, *a, **k: missing_id not in key)
        def forbid_upload(*args, **kwargs):
            raise AssertionError("Integrity verification must never write to R2")
        monkeypatch.setattr(integrity, "_s3_cp", forbid_upload)
        return before

    def test_missing_index_entry_blocks_without_purging_or_count_drift(self, tmp_path, monkeypatch):
        rows = [{"id": f"intel--{key}", "path": f"/reports/2026/08/intel--{key}.html"}
                for key in ("a", "b", "c")]
        index = {"total_reports": 3, "reports_listed": 3, "reports": rows}
        latest = {"total_reports": 3, "reports_listed": 2, "reports": rows[:2]}
        before = self._setup(tmp_path, monkeypatch, index, latest, "intel--b")
        assert integrity.main() == 1
        assert (integrity.INDEX_PATH.read_bytes(), integrity.LATEST_PATH.read_bytes()) == before
        assert json.loads(integrity.INDEX_PATH.read_text())["total_reports"] == 3
        assert json.loads(integrity.LATEST_PATH.read_text())["reports_listed"] == 2

    def test_latest_only_missing_entry_blocks_without_erasing_catalog(self, tmp_path, monkeypatch):
        index = {"total_reports": 1, "reports_listed": 1,
                 "reports": [{"id": "intel--a", "path": "/reports/2026/08/intel--a.html"}]}
        latest = {"total_reports": 1, "reports_listed": 1,
                  "reports": [{"id": "intel--z", "path": "/reports/2026/08/intel--z.html"}]}
        before = self._setup(tmp_path, monkeypatch, index, latest, "intel--z")
        assert integrity.main() == 1
        assert (integrity.INDEX_PATH.read_bytes(), integrity.LATEST_PATH.read_bytes()) == before
        assert json.loads(integrity.LATEST_PATH.read_text())["reports_listed"] == 1
