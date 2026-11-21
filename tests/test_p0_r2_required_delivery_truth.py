"""P0 R2 report delivery integrity gate: negative controls, no external network."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from scripts import r2_reports_integrity as gate


def _fixture(monkeypatch, tmp_path):
    root = tmp_path / "api"
    (root / "reports").mkdir(parents=True)
    reports = [
        {"id": "intel--aaa", "path": "/reports/2026/11/intel--aaa.html"},
        {"id": "intel--bbb", "path": "/reports/2026/11/intel--bbb.html"},
    ]
    payload = {"reports": reports, "reports_listed": 2, "total_reports": 2}
    index, latest, feed = root / "reports" / "index.json", root / "reports" / "latest.json", root / "feed.json"
    index.write_text(json.dumps(payload))
    latest.write_text(json.dumps(payload))
    # These are deliberately fresh: the publisher only owes report delivery
    # for the canonical rolling window, never every historical feed row.
    fresh_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    feed.write_text(json.dumps([
        {"id": row["id"], "report_url": row["path"], "timestamp": fresh_ts}
        for row in reports
    ]))
    for name, p in [("INDEX_PATH", index), ("LATEST_PATH", latest), ("FEED_PATH", feed)]:
        monkeypatch.setattr(gate, name, p)
    monkeypatch.setenv("CF_ACCOUNT_ID", "testaccount")
    monkeypatch.setenv("CF_R2_REPORTS_KEY_ID", "local-test")
    monkeypatch.setenv("CF_R2_REPORTS_SECRET_KEY", "local-test")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    events = []
    monkeypatch.setattr(gate, "_write_github_env", lambda k, v: events.append((k, v)))
    before = (index.read_bytes(), latest.read_bytes())
    return index, latest, feed, reports, events, before


def _never_write(*args, **kwargs):
    raise AssertionError("blocked audit must not write to cloud")


def test_partial_current_run_loss_blocks_without_catalog_mutation(monkeypatch, tmp_path):
    idx, latest, _, rows, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    monkeypatch.setattr(gate, "_r2_object_exists", lambda key, *args: not key.endswith("bbb.html"))
    assert gate.main() == 1
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_REPORTS" in v for _, v in events)


def test_feed_only_key_is_head_checked_and_blocks_catalog(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    extra = "/reports/2026/11/intel--not-in-catalog.html"
    f = json.loads(feed.read_text())
    f.append({
        "id": "intel--new", "report_url": extra,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(f))
    checked = []
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    def head(key, *args):
        checked.append(key)
        return True
    monkeypatch.setattr(gate, "_r2_object_exists", head)
    assert gate.main() == 1
    assert extra.lstrip("/") in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("unindexed_1" in v for _, v in events)


def test_expired_feed_only_report_is_not_falsely_required_as_current(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    historical = "/reports/2026/11/intel--old-feed-only.html"
    items = json.loads(feed.read_text())
    items.append({
        "id": "intel--historical", "report_url": historical,
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=72))
                     .isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(items))
    heads = []
    def head(key, *args):
        heads.append(key)
        return True
    monkeypatch.setattr(gate, "_r2_object_exists", head)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert historical.lstrip("/") not in heads
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any(v.startswith("OK_purged=0") for _, v in events)


def test_in_window_feed_only_report_still_blocks_catalog(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    fresh_key = "/reports/2026/11/intel--not-indexed-new.html"
    items.append({
        "id": "intel--new", "report_url": fresh_key,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(items))
    checked = []
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: checked.append(key) or True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 1
    assert fresh_key.lstrip("/") in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("unindexed_1" in v for _, v in events)


def test_expired_only_feed_does_not_certify_empty_current_delivery(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    for item in items:
        item["timestamp"] = old
    feed.write_text(json.dumps(items))
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_FEED_EVIDENCE" in v for _, v in events)


@pytest.mark.parametrize("field", ["CF_ACCOUNT_ID", "CF_R2_REPORTS_KEY_ID", "CF_R2_REPORTS_SECRET_KEY"])
def test_missing_credentials_blocks_not_skips(monkeypatch, tmp_path, field):
    idx, latest, _, _, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.delenv(field)
    # Fallback to job-level credentials must not mask missing dedicated key.
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before


def test_invalid_index_fails_closed_without_r2_writes(monkeypatch, tmp_path):
    idx, _, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    idx.write_text("{corrupt")
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert any("BLOCKED_READ_INDEX" in v for _, v in events)


def test_invalid_feed_fails_closed_without_r2_writes(monkeypatch, tmp_path):
    idx, latest, feed, _, events, before = _fixture(monkeypatch, tmp_path)
    feed.write_text('{"items": [{"id": "no-report-url"}]}')
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before


def test_failed_historical_catalog_publication_rolls_back_local_bytes(monkeypatch, tmp_path):
    idx, latest, feed, _, events, before = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    payload["reports_listed"] = 3
    payload["total_reports"] = 3
    idx.write_text(json.dumps(payload))
    original = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test")
    monkeypatch.setattr(gate, "_s3_cp", lambda *args: False)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == original
    assert any("BLOCKED_CATALOG_PUBLICATION" in v for _, v in events)


def test_all_verified_current_run_reports_can_pass_without_mutation(monkeypatch, tmp_path):
    idx, latest, _, _, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any(v.startswith("OK_purged=0") for _, v in events)


def test_catalog_readback_mismatch_blocks_release_and_restores_local(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    idx.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test")
    calls = []
    monkeypatch.setattr(gate, "_s3_cp", lambda *args: calls.append("upload") or True)
    monkeypatch.setattr(gate, "_remote_catalog_matches", lambda *args: False)
    assert gate.main() == 2
    assert calls
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CATALOG_PUBLICATION" in v for _, v in events)


def test_unreadable_latest_catalog_blocks_before_any_r2_operation(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    latest.write_text("{invalid")
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert any("BLOCKED_LATEST_SCHEMA" in v for _, v in events)


def test_authenticated_catalog_readback_requires_exact_bytes(monkeypatch, tmp_path):
    local = tmp_path / "local.json"
    local.write_bytes(b'{"verified":true}')
    remote_bytes = b'{"verified":true}'
    commands = []
    def fake_run(command, **kwargs):
        import subprocess
        commands.append(command)
        # AWS 'get-object' writes the requested output file.
        output_path = command[-1]
        from pathlib import Path
        Path(output_path).write_bytes(remote_bytes)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    args = (str(local), "data", "api/reports/index.json",
            "https://test.r2.cloudflarestorage.com", "k", "s")
    assert gate._remote_catalog_matches(*args) is True
    remote_bytes = b'{"verified":false}'
    assert gate._remote_catalog_matches(*args) is False
    assert all("--region" in c and c[c.index("--region")+1] == "auto" for c in commands)


def test_index_write_failure_fails_closed_before_remote_catalog_mutation(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    idx.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)

    def fail_replace(*args):
        raise OSError("simulated read-only filesystem")

    monkeypatch.setattr(gate.os, "replace", fail_replace)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert ("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LOCAL_INDEX_WRITE") in events


def test_latest_write_failure_restores_prior_index_change(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    historical = {"id": "old", "path": "/reports/2025/01/intel--old.html"}
    for path in (idx, latest):
        payload = json.loads(path.read_text())
        payload["reports"].append(historical)
        path.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    real_replace = gate.os.replace

    def fail_latest_only(src, dest):
        if str(dest) == str(latest):
            raise OSError("simulated latest-catalog write failure")
        return real_replace(src, dest)

    monkeypatch.setattr(gate.os, "replace", fail_latest_only)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert ("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LOCAL_LATEST_WRITE") in events
