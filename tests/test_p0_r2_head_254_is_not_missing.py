"""No report object may be classified absent from AWS CLI return-code alone.

Production S3 calls are replaced by deterministic subprocess mocks.
"""
from __future__ import annotations

import subprocess

import pytest
from scripts import r2_upload_verifier as verifier


@pytest.fixture(autouse=True)
def _bounded_s3_environment(monkeypatch):
    monkeypatch.setattr(verifier, "CF_ACCOUNT_ID", "localtest")
    monkeypatch.setattr(verifier, "ACCESS_KEY", "local-key")
    monkeypatch.setattr(verifier, "SECRET_KEY", "local-secret")
    monkeypatch.setattr(verifier, "R2_ENDPOINT", "https://localtest.r2.cloudflarestorage.com")
    monkeypatch.setattr(verifier, "MAX_RETRIES", 1)


@pytest.mark.parametrize(("rc", "stderr", "expected"), [
    (254, "An error occurred (InvalidRegionName) when calling the HeadObject operation", None),
    (254, "An error occurred (403) when calling the HeadObject operation: AccessDenied", None),
    (254, "An error occurred (400) when calling the HeadObject operation", None),
    (254, "Service unavailable", None),
    (255, "Transport connect failure", None),
    (254, "An error occurred (404) when calling the HeadObject operation", 404),
    (254, "An error occurred (NoSuchKey) when calling the HeadObject operation", 404),
    (254, "An error occurred (NotFound) when calling the HeadObject operation", 404),
])
def test_head_service_error_classification(monkeypatch, rc, stderr, expected):
    captured = []
    def fake_run(command, **kwargs):
        captured.append((command, kwargs))
        return subprocess.CompletedProcess(command, rc, "", stderr)
    monkeypatch.setattr(verifier.subprocess, "run", fake_run)
    result = verifier._s3api_head_object(
        "sentinel-apex-reports", "reports/2026/11/intel--test.html"
    )
    assert (result or {}).get("status") == expected
    assert len(captured) == 1
    command, kwargs = captured[0]
    assert command[command.index("--region") + 1] == "auto"
    assert command[command.index("--endpoint-url") + 1] == verifier.R2_ENDPOINT
    assert kwargs["env"]["AWS_ACCESS_KEY_ID"] == "local-key"
    assert kwargs["env"]["AWS_SECRET_ACCESS_KEY"] == "local-secret"


def test_verified_head_success_preserves_r2_metadata(monkeypatch):
    payload = '{"ContentLength":8192,"ETag":"\\"abc123\\""}'
    monkeypatch.setattr(verifier.subprocess, "run",
                        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, payload, ""))
    result = verifier._s3api_head_object("sentinel-apex-data", "intel/feed_manifest.json")
    assert result is not None
    assert result["status"] == 200
    assert result["content_length"] == 8192
    assert result["etag"] == "abc123"
