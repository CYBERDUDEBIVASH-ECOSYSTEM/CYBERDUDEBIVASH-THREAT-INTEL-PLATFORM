"""Offline regression for safe source retrieval and side-effect-free dry runs."""
import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import apex_feed_quality_v2 as quality


@pytest.mark.parametrize("cve", ["CVE-2026-1234&other=1", "CVE-2026-1234#x", "file:///etc/passwd", "CVE-2026-12"])
def test_invalid_cve_never_calls_source(monkeypatch, cve):
    monkeypatch.setattr(quality, "_source_open", lambda *a, **k: pytest.fail("unexpected source access"))
    assert quality.fetch_nvd_cve(cve) is None


def test_source_allowlist_and_cross_origin_redirect(monkeypatch):
    monkeypatch.setattr(urllib.request, "build_opener", lambda *a: pytest.fail("untrusted origin opened"))
    for url in ("http://services.nvd.nist.gov/", "https://example.com/", "https://www.cisa.gov.example.com/"):
        with pytest.raises(ValueError, match="Untrusted enrichment origin"):
            quality._source_open(urllib.request.Request(url), 1)
    handler = quality._SourceRedirectHandler()
    req = urllib.request.Request(quality.NVD_API_BASE, headers={"apiKey": "offline-test"})
    for dest in ("http://services.nvd.nist.gov/", "https://example.com/"):
        with pytest.raises(urllib.error.HTTPError, match="Untrusted source redirect"):
            handler.redirect_request(req, None, 302, "Found", {}, dest)


def test_feed_dry_run_preserves_files_and_does_not_write_cache(tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps([{"id": "test", "cve_ids": ["CVE-2026-1234"], "severity": "LOW"}]))
    output = tmp_path / "output.json"
    report_path = tmp_path / "quality.json"
    cache = tmp_path / "cache.json"
    output.write_text("prior output")
    report_path.write_text("prior report")
    original = feed.read_bytes()
    monkeypatch.setattr(quality, "QUALITY_REPORT", report_path)
    monkeypatch.setattr(quality, "KEV_CACHE_PATH", cache)
    monkeypatch.setattr(quality, "_kev_set", None)
    monkeypatch.setattr(quality, "_TA_ENGINE_AVAILABLE", False)
    monkeypatch.setattr(quality, "fetch_nvd_cve", lambda cve: None)
    monkeypatch.setattr(quality.time, "sleep", lambda n: None)
    monkeypatch.setattr(quality, "_source_open", lambda *a, **k: io.BytesIO(
        b'{"vulnerabilities":[{"cveID":"CVE-2026-1234"}]}'))
    result = quality.upgrade_feed(feed, output, dry_run=True)
    assert result["output_count"] == 1
    assert result["enrichment_stats"]["kev_confirmed"] == 1
    assert feed.read_bytes() == original
    assert output.read_text() == "prior output"
    assert report_path.read_text() == "prior report"
    assert not cache.exists()


def test_normal_run_preserves_output_contract(tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps([{"id": "test", "severity": "LOW"}]))
    output = tmp_path / "output.json"
    report = tmp_path / "report.json"
    monkeypatch.setattr(quality, "QUALITY_REPORT", report)
    monkeypatch.setattr(quality, "_TA_ENGINE_AVAILABLE", False)
    result = quality.upgrade_feed(feed, output, nvd_enabled=False)
    assert len(json.loads(output.read_text())) == 1
    assert json.loads(report.read_text()) == result
