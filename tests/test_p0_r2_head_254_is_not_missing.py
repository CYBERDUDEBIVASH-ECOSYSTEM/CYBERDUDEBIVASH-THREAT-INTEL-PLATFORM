"""Offline negative controls for authenticated native R2 HeadObject.

No AWS credentials, cloud calls, AWS CLI process or network activity are used.
Only an explicit 404 with an object-absence error code proves absence.
"""
from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest
from scripts import r2_upload_verifier as verifier


class FakeClientError(Exception):
    def __init__(self, code: str, http_status: int):
        super().__init__("synthetic SDK error; never expose response text")
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": http_status},
        }


@pytest.fixture(autouse=True)
def _bounded_s3_environment(monkeypatch):
    monkeypatch.setattr(verifier, "CF_ACCOUNT_ID", "localtest")
    monkeypatch.setattr(verifier, "ACCESS_KEY", "local-key")
    monkeypatch.setattr(verifier, "SECRET_KEY", "local-secret")
    monkeypatch.setattr(verifier, "R2_ENDPOINT", "https://localtest.r2.cloudflarestorage.com")
    monkeypatch.setattr(verifier, "MAX_RETRIES", 1)


def _install_fake_s3(monkeypatch, *, response=None, error=None):
    """Stub lazy boto3/botocore imports; assert exact no-network client contract."""
    calls = []
    options = []

    class Config:
        def __init__(self, **kwargs):
            self.settings = kwargs

    def head_object(**kwargs):
        calls.append(kwargs)
        if error is not None:
            raise error
        return response

    def client(service, **kwargs):
        assert service == "s3"
        options.append(kwargs)
        return SimpleNamespace(head_object=head_object)

    boto3_module = types.ModuleType("boto3")
    boto3_module.client = client
    botocore_module = types.ModuleType("botocore")
    config_module = types.ModuleType("botocore.config")
    exceptions_module = types.ModuleType("botocore.exceptions")
    config_module.Config = Config
    exceptions_module.ClientError = FakeClientError
    botocore_module.config = config_module
    botocore_module.exceptions = exceptions_module
    for name, module in (
        ("boto3", boto3_module),
        ("botocore", botocore_module),
        ("botocore.config", config_module),
        ("botocore.exceptions", exceptions_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return calls, options


@pytest.mark.parametrize(("code", "http_status", "expected"), [
    ("InvalidRegionName", 400, None),
    ("AccessDenied", 403, None),
    ("ExpiredToken", 403, None),
    ("SlowDown", 429, None),
    ("InternalError", 500, None),
    ("NoSuchKey", 403, None),  # mismatch is NOT an absence proof
    ("NoSuchKey", 404, 404),
    ("NotFound", 404, 404),
    ("404", 404, 404),
])
def test_head_service_error_classification(monkeypatch, code, http_status, expected):
    calls, options = _install_fake_s3(
        monkeypatch, error=FakeClientError(code, http_status)
    )
    result = verifier._s3api_head_object(
        "sentinel-apex-reports", "reports/2026/11/intel--test.html"
    )
    assert (result or {}).get("status") == expected
    assert calls == [{
        "Bucket": "sentinel-apex-reports",
        "Key": "reports/2026/11/intel--test.html",
    }]
    kwargs = options[0]
    assert kwargs["region_name"] == "auto"
    assert kwargs["endpoint_url"] == verifier.R2_ENDPOINT
    assert kwargs["aws_access_key_id"] == "local-key"
    assert kwargs["aws_secret_access_key"] == "local-secret"
    assert kwargs["config"].settings["retries"]["total_max_attempts"] == 1


def test_verified_head_success_preserves_r2_metadata(monkeypatch):
    payload = {
        "ContentLength": 8192, "ETag": '"abc123"',
        "LastModified": "fixture-date",
    }
    calls, options = _install_fake_s3(monkeypatch, response=payload)
    result = verifier._s3api_head_object(
        "sentinel-apex-data", "intel/feed_manifest.json", full=True
    )
    assert result is not None and result["status"] == 200
    assert result["content_length"] == 8192
    assert result["etag"] == "abc123"
    assert result["raw"] == payload
    assert len(calls) == 1 and len(options) == 1


def test_broken_native_head_response_fails_closed(monkeypatch):
    _install_fake_s3(monkeypatch, response={"ContentLength": "broken", "ETag": "test"})
    assert verifier._s3api_head_object("sentinel-apex-data", "intel/feed_manifest.json") is None


def test_native_sdk_unavailable_never_proves_absence(monkeypatch):
    _install_fake_s3(monkeypatch, response={"ContentLength": 1, "ETag": "test"})
    monkeypatch.setitem(sys.modules, "boto3", None)
    assert verifier._s3api_head_object("sentinel-apex-data", "intel/feed_manifest.json") is None
