"""P0: the bounded R2 data uploader must not claim PASS on partial PUTs.

All tests are offline; upload calls are patched. No Cloudflare access, no
GitHub Actions dispatch, and no production customer data.
"""
from pathlib import Path
import os
from unittest import mock

import pytest

from scripts import r2_upload as upload


def _run_with_put_results(tmp_path, monkeypatch, results):
    from p0_r44_publication_boundary import finalize_public_feed
    del finalize_public_feed  # imported for the same module resolution as main()
    monkeypatch.setattr("p0_r44_publication_boundary.finalize_public_feed", lambda _root: None)
    monkeypatch.setattr(upload, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(upload, "get_credentials", lambda: ("fake-account", "fake-id", "fake-secret"))
    monkeypatch.setattr(upload, "install_awscli", lambda: None)
    monkeypatch.setattr(upload, "configure_awscli_performance", lambda: None)
    monkeypatch.setattr(upload, "count_manifest", lambda: 1)
    monkeypatch.setattr(upload, "_generate_ai_endpoints", lambda: None)
    monkeypatch.setattr(upload, "build_upload_plan",
                        lambda: [(str(tmp_path / "fixture.bin"), "test/fixture.bin")])
    monkeypatch.setattr(upload._tlp_boundary, "build_parent_index", lambda _paths: {})
    monkeypatch.setattr(upload, "write_github_env", lambda *_args: None)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    put_calls, telemetry = [], []
    iterator = iter(results)

    def fake_put(_src, _bucket, key, _endpoint, **_kwargs):
        put_calls.append(key)
        return next(iterator)

    monkeypatch.setattr(upload, "s3_cp", fake_put)
    monkeypatch.setattr(upload, "emit_summary",
                        lambda *_args, **kwargs: telemetry.append(kwargs))
    prev = Path.cwd()
    try:
        try:
            upload.main()
            exit_code = 0
        except SystemExit as e:
            exit_code = e.code
    finally:
        os.chdir(prev)
    return exit_code, put_calls, telemetry


def test_partial_data_put_fails_without_success_marker(tmp_path, monkeypatch):
    code, calls, telemetry = _run_with_put_results(tmp_path, monkeypatch, [False])
    assert code == 1
    assert calls == ["test/fixture.bin"]
    assert telemetry[-1]["status"] == "BLOCKED"
    assert telemetry[-1]["extra"]["reason"] == "R2_DATA_UPLOAD_INCOMPLETE"


def test_sync_metadata_put_failure_fails_closed(tmp_path, monkeypatch):
    code, calls, telemetry = _run_with_put_results(tmp_path, monkeypatch, [True, False])
    assert code == 1
    assert calls == ["test/fixture.bin", "intel/_sync_meta.json"]
    assert telemetry[-1]["status"] == "BLOCKED"
    assert telemetry[-1]["extra"]["reason"] == "R2_SYNC_META_UPLOAD_FAILED"


def test_all_planned_puts_succeed(tmp_path, monkeypatch):
    code, calls, telemetry = _run_with_put_results(tmp_path, monkeypatch, [True, True])
    assert code == 0
    assert calls == ["test/fixture.bin", "intel/_sync_meta.json"]
    assert telemetry[-1]["status"] == "PASS"
