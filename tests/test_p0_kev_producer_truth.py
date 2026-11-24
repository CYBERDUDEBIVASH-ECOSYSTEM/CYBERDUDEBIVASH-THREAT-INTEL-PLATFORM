"""P0 CISA KEV producer truth — offline no network or production writes."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import kev_feed_marker as kev  # noqa: E402


CVE_A = "CVE-2026-11111"
CVE_B = "CVE-2026-22222"
CVE_C = "CVE-2026-33333"


def catalog():
    return {
        CVE_B: {
            "date_added": "2026-11-20",
            "vendor_project": "FictionalVendor",
            "product": "SyntheticSoftware",
            "vulnerability_name": "Synthetic",
            "required_action": "Review vendor guidance",
            "due_date": "2026-12-01",
        }
    }


@pytest.fixture
def feed_runner(tmp_path, monkeypatch):
    feed = tmp_path / "api" / "feed.json"
    report = tmp_path / "health" / "kev_marker_report.json"
    feed.parent.mkdir(parents=True)
    monkeypatch.setattr(kev, "FEED_PATH", feed)
    monkeypatch.setattr(kev, "REPORT_PATH", report)
    monkeypatch.setattr(kev, "DRY_RUN", False)
    monkeypatch.setattr(kev, "_fetch_kev_catalog", catalog)

    def run(items):
        feed.write_text(json.dumps({"items": items}), encoding="utf-8")
        assert kev.main() == 0
        return (
            json.loads(feed.read_text(encoding="utf-8"))["items"],
            json.loads(report.read_text(encoding="utf-8")),
        )

    return run, feed, report


def test_multi_cve_partial_kev_match_cannot_inflate_severity_or_confidence(feed_runner):
    run, _feed, _report = feed_runner
    rows, info = run([{
        "title": "Synthetic multi CVE advisory",
        "cve_ids": [CVE_A, CVE_B, CVE_C],
        "kev_present": False,
        "severity": "LOW",
        "risk_score": 0.38,
        "confidence": 11,
        "cvss_score": 3.1,
    }])
    row = rows[0]
    assert row["kev_present"] is True
    assert row["kev_cve"] == CVE_B
    assert row["kev_cve_ids"] == [CVE_B]
    assert row["kev_date"] == "2026-11-20"
    assert row["severity"] == "LOW"
    assert row["risk_score"] == 0.38
    assert row["cvss_score"] == 3.1
    assert row["confidence"] == 11
    assert info["items_marked"] == 1


def test_existing_true_flag_reconciles_stale_cve_metadata(feed_runner):
    run, _feed, _report = feed_runner
    rows, report = run([{
        "title": "Synthetic advisory",
        "cve_ids": [CVE_A, CVE_B],
        "kev": "NO",
        "kev_present": True,
        "kev_cve": CVE_A,
        "kev_date": "2026-01-01",
        "kev_product": "WrongProduct",
        "confidence": 17,
    }])
    row = rows[0]
    assert row["kev_present"] is True
    assert row["kev"] is True
    assert row["kev_cve"] == CVE_B
    assert row["kev_cve_ids"] == [CVE_B]
    assert row["kev_date"] == "2026-11-20"
    assert row["kev_product"] == "FictionalVendor SyntheticSoftware"
    assert row["confidence"] == 17
    assert report["already_kev"] == 1
    assert report["items_reconciled"] == 1


def test_preflagged_item_without_any_cve_is_unverified_not_kept_true(feed_runner):
    run, _feed, _report = feed_runner
    rows, report = run([{
        "title": "Synthetic report with no vulnerability IDs",
        "kev": True,
        "kev_present": True,
        "kev_date": "2025-01-01",
        "risk_score": 2.0,
    }])
    row = rows[0]
    assert row["kev_present"] is False
    assert row["kev"] is False
    assert row["kev_confirmed"] is False
    assert "kev_date" not in row
    assert row["risk_score"] == 2.0
    assert report["items_deflated"] == 1
    assert report["already_kev"] == 0


def test_multi_cve_reordered_fields_produce_stable_matched_identity(feed_runner):
    run, _feed, _report = feed_runner
    rows, report = run([{"cve_ids": [CVE_C, CVE_B, CVE_A]}])
    assert rows[0]["kev_cve_ids"] == [CVE_B]
    assert rows[0]["kev_cve"] == CVE_B
    assert report["total_kev_in_feed"] == 1


def test_official_catalog_unavailable_does_not_rewrite_existing_feed(tmp_path, monkeypatch):
    feed = tmp_path / "api" / "feed.json"
    report = tmp_path / "health" / "report.json"
    feed.parent.mkdir()
    feed.write_text(json.dumps({"items": [{"cve_ids": [CVE_B], "kev": True}]}))
    original = feed.read_bytes()
    monkeypatch.setattr(kev, "FEED_PATH", feed)
    monkeypatch.setattr(kev, "REPORT_PATH", report)
    monkeypatch.setattr(kev, "_fetch_kev_catalog", lambda: {})
    monkeypatch.setattr(kev, "DRY_RUN", False)
    assert kev.main() == 0
    assert feed.read_bytes() == original
    assert json.loads(report.read_text())["status"] == "CATALOG_UNAVAILABLE"


def test_verified_catalog_replay_is_idempotent_no_second_feed_write(feed_runner):
    run, feed, report = feed_runner
    rows, _ = run([{"cve_ids": [CVE_B], "kev": False}])
    first = feed.read_bytes()
    assert kev.main() == 0
    assert feed.read_bytes() == first
    summary = json.loads(report.read_text())
    assert summary["already_kev"] == 1
    assert summary["items_marked"] == 0
    assert summary["items_reconciled"] == 0


def test_dry_run_does_not_modify_feed(tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    report = tmp_path / "report.json"
    feed.write_text(json.dumps({"items": [{"cve_ids": [CVE_B], "kev": False}]}))
    baseline = feed.read_bytes()
    monkeypatch.setattr(kev, "FEED_PATH", feed)
    monkeypatch.setattr(kev, "REPORT_PATH", report)
    monkeypatch.setattr(kev, "_fetch_kev_catalog", catalog)
    monkeypatch.setattr(kev, "DRY_RUN", True)
    assert kev.main() == 0
    assert feed.read_bytes() == baseline
    assert json.loads(report.read_text())["dry_run"] is True


def test_malformed_row_fails_closed_before_any_feed_overwrite(tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    report = tmp_path / "report.json"
    # First record is a valid KEV hit; second corrupt record must block all writes.
    feed.write_text(json.dumps({"items": [{"cve_ids": [CVE_B]}, None]}))
    baseline = feed.read_bytes()
    monkeypatch.setattr(kev, "FEED_PATH", feed)
    monkeypatch.setattr(kev, "REPORT_PATH", report)
    monkeypatch.setattr(kev, "_fetch_kev_catalog", catalog)
    monkeypatch.setattr(kev, "DRY_RUN", False)
    assert kev.main() == 1
    assert feed.read_bytes() == baseline
    assert not report.exists()
