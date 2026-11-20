"""P0: Cloudflare R2 HEAD failures must never purge report catalogs.

Network/R2 writes are replaced with deterministic subprocess mocks.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from scripts import r2_reports_integrity as gate


def _head(monkeypatch, *, code=0, stderr=""):
    commands = []
    def fake_run(command, **kwargs):
        commands.append((command, kwargs))
        return subprocess.CompletedProcess(command, code, "", stderr)
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    result = gate._r2_object_exists("reports/2026/11/id.html", "reports", "https://account.r2.cloudflarestorage.com", "key", "secret")
    assert len(commands) == 1
    command, kwargs = commands[0]
    assert command[command.index("--region") + 1] == "auto"
    assert command[command.index("--endpoint-url") + 1] == "https://account.r2.cloudflarestorage.com"
    assert kwargs["env"]["AWS_ACCESS_KEY_ID"] == "key"
    assert kwargs["env"]["AWS_SECRET_ACCESS_KEY"] == "secret"
    return result


def test_success_is_present(monkeypatch):
    assert _head(monkeypatch) is True


@pytest.mark.parametrize("stderr", [
    "An error occurred (404) when calling the HeadObject operation: Not Found",
    "An error occurred (NoSuchKey) when calling the HeadObject operation: The specified key does not exist",
])
def test_authenticated_head_not_found_is_absent(monkeypatch, stderr):
    assert _head(monkeypatch, code=255, stderr=stderr) is False


@pytest.mark.parametrize("stderr", [
    "An error occurred (InvalidRegionName) when calling the HeadObject operation: invalid region",
    "An error occurred (403) when calling the HeadObject operation: AccessDenied",
    "An error occurred (400) when calling the HeadObject operation: Bad Request",
    "network unavailable", "",
])
def test_head_failure_is_unknown_not_missing(monkeypatch, stderr):
    assert _head(monkeypatch, code=255, stderr=stderr) is None


def test_head_timeout_is_unknown(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("aws", 15)
    monkeypatch.setattr(gate.subprocess, "run", timeout)
    assert gate._r2_object_exists("reports/a.html", "reports", "https://test.r2.cloudflarestorage.com", "key", "secret") is None


def test_upload_command_uses_explicit_r2_region(monkeypatch, tmp_path):
    called = []
    def fake_run(command, **kwargs):
        called.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate._s3_cp(str(tmp_path / "file.json"), "bucket", "api/reports/index.json",
                       "https://test.r2.cloudflarestorage.com", "key", "secret") is True
    assert called[0][called[0].index("--region") + 1] == "auto"


def _catalogs(monkeypatch, tmp_path):
    index = tmp_path / "api" / "reports" / "index.json"
    latest = tmp_path / "api" / "reports" / "latest.json"
    feed = tmp_path / "api" / "feed.json"
    index.parent.mkdir(parents=True)
    feed.parent.mkdir(parents=True, exist_ok=True)
    key = "/reports/2026/11/intel--0123456789abcdef.html"
    payload = {"total_reports": 1, "reports_listed": 1,
               "reports": [{"id": "intel--0123456789abcdef", "path": key}]}
    index.write_text(json.dumps(payload))
    latest.write_text(json.dumps(payload))
    feed.write_text(json.dumps([{"id": "intel--0123456789abcdef", "report_url": key}]))
    monkeypatch.setattr(gate, "INDEX_PATH", index)
    monkeypatch.setattr(gate, "LATEST_PATH", latest)
    monkeypatch.setattr(gate, "FEED_PATH", feed)
    monkeypatch.setenv("CF_ACCOUNT_ID", "account")
    monkeypatch.setenv("CF_R2_REPORTS_KEY_ID", "key")
    monkeypatch.setenv("CF_R2_REPORTS_SECRET_KEY", "secret")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    def forbidden(*a, **k):
        raise AssertionError("No data bucket writes allowed on blocked verification")
    monkeypatch.setattr(gate, "_s3_cp", forbidden)
    return index, latest


def test_unverifiable_head_preserves_both_catalogs(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    before = (index.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: None)
    assert gate.main() == 2
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_confirmed_current_run_missing_fails_without_emptying_catalog(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    before = (index.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: False)
    assert gate.main() == 1
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_verified_present_keeps_catalog_intact(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    before = (index.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    assert gate.main() == 0
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_partial_current_run_missing_is_blocked_without_catalog_mutation(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    payload = json.loads(index.read_text())
    second = {"id": "intel--second", "path": "/reports/2026/11/intel--second.html"}
    payload["reports"].append(second)
    payload["reports_listed"] = payload["total_reports"] = 2
    index.write_text(json.dumps(payload))
    latest.write_text(json.dumps(payload))
    gate.FEED_PATH.write_text(json.dumps([
        {"report_url": payload["reports"][0]["path"]},
        {"report_url": second["path"]},
    ]))
    before = (index.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("intel--second.html"))
    assert gate.main() == 1
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_feed_only_report_url_is_verified_and_blocks_release(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    extra = "/reports/2026/11/not-in-index.html"
    gate.FEED_PATH.write_text(json.dumps([{"report_url": extra}]))
    before = (index.read_bytes(), latest.read_bytes())
    checked = []
    def head(key, *args):
        checked.append(key)
        return not key.endswith("not-in-index.html")
    monkeypatch.setattr(gate, "_r2_object_exists", head)
    assert gate.main() == 1
    assert "reports/2026/11/not-in-index.html" in checked
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_historical_missing_report_never_auto_purged(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    gate.FEED_PATH.write_text("[]")
    before = (index.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: False)
    assert gate.main() == 1
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_missing_account_configuration_fails_closed(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    monkeypatch.delenv("CF_ACCOUNT_ID")
    before = (index.read_bytes(), latest.read_bytes())
    assert gate.main() == 2
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_missing_reports_credentials_fails_closed(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    monkeypatch.delenv("CF_R2_REPORTS_KEY_ID")
    monkeypatch.delenv("CF_R2_REPORTS_SECRET_KEY")
    before = (index.read_bytes(), latest.read_bytes())
    assert gate.main() == 2
    assert (index.read_bytes(), latest.read_bytes()) == before


def test_corrupt_index_fails_closed(monkeypatch, tmp_path):
    index, latest = _catalogs(monkeypatch, tmp_path)
    index.write_text("{invalid")
    before = (index.read_bytes(), latest.read_bytes())
    assert gate.main() == 2
    assert (index.read_bytes(), latest.read_bytes()) == before
