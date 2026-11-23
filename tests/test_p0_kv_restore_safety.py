"""Offline disaster-recovery negative controls; never contact Cloudflare."""
from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.error
from types import SimpleNamespace

import pytest

from scripts import restore_kv_from_r2 as restore

ACC = "a" * 32
OTHER = "b" * 32
NS = "API_KEYS_KV"
NSID = restore.KV_NAMESPACES[NS]
DAY = "2026-11-23"
SECRET = "SYNTHETIC_KV_RESTORE_ADMIN_TOKEN"


def snapshot(entries=None):
    if entries is None:
        entries = {"customer:key": '{"tier":"PRO","status":"active"}'}
    return {
        "namespace": NS, "namespace_id": NSID, "exported_at": DAY + "T01:00:00Z",
        "count": len(entries), "errors": 0,
        "checksum_sha256": hashlib.sha256(
            json.dumps(entries, sort_keys=True).encode()
        ).hexdigest(),
        "entries": entries,
    }


@pytest.mark.parametrize("alter", [
    {"namespace": "RATE_LIMIT_KV"},
    {"namespace_id": OTHER},
    {"errors": 1},
    {"count": 99},
    {"checksum_sha256": "0" * 64},
    {"entries": []},
    {"entries": {"x": None}, "count": 1},
    {"entries": {"": "value"}, "count": 1},
])
def test_malformed_snapshot_is_rejected_before_any_writes(monkeypatch, alter):
    doc = snapshot()
    doc.update(alter)
    called = []

    def forbidden(*args):
        called.append(args)
        raise AssertionError("no live writes permitted")

    monkeypatch.setattr(restore, "put_kv_value", forbidden)
    assert restore.restore_namespace(NS, NSID, doc, dry_run=False) is False
    assert called == []


def test_snapshot_over_500_keys_is_refused_before_writes(monkeypatch):
    doc = snapshot({f"key-{i}": "v" for i in range(501)})
    monkeypatch.setattr(
        restore, "put_kv_value",
        lambda *_: (_ for _ in ()).throw(AssertionError("unexpected write")),
    )
    assert restore.restore_namespace(NS, NSID, doc, dry_run=False) is False


def test_valid_snapshot_dry_run_never_writes(monkeypatch):
    monkeypatch.setattr(
        restore, "put_kv_value",
        lambda *_: (_ for _ in ()).throw(AssertionError("unexpected write")),
    )
    assert restore.restore_namespace(NS, NSID, snapshot(), dry_run=True)


@pytest.mark.parametrize("date", [
    "2026-1-2", "2026-02-30", "../../latest", "2026-11-23/evil",
    "2026-11-23?token=1", "not-date",
])
def test_only_canonical_snapshot_date_allowed(date):
    with pytest.raises(ValueError, match="INVALID_DATE"):
        restore.validate_date(date)
    restore.validate_date(DAY)


@pytest.mark.parametrize("endpoint", [
    "http://" + ACC + ".r2.cloudflarestorage.com",
    "https://" + OTHER + ".r2.cloudflarestorage.com",
    "https://attacker.invalid",
    "https://" + ACC + ".r2.cloudflarestorage.com.attacker.invalid",
    "https://user@" + ACC + ".r2.cloudflarestorage.com",
    "https://" + ACC + ".r2.cloudflarestorage.com:9999",
    "https://" + ACC + ".r2.cloudflarestorage.com/bucket/key",
    "https://" + ACC + ".r2.cloudflarestorage.com?exfil=1",
])
def test_r2_credentials_cannot_reach_untrusted_endpoint(monkeypatch, endpoint):
    monkeypatch.setattr(restore, "CF_ACCOUNT_ID", ACC)
    with pytest.raises(ValueError, match="UNTRUSTED_R2_ENDPOINT"):
        restore.validate_r2_endpoint(endpoint)


def test_missing_live_confirmation_blocks_before_snapshot_download(monkeypatch):
    monkeypatch.setattr(
        restore, "download_snapshot",
        lambda *_: (_ for _ in ()).throw(AssertionError("should not download")),
    )
    monkeypatch.setattr(
        sys, "argv", ["restore", "--namespace", NS, "--date", DAY]
    )
    with pytest.raises(SystemExit) as blocked:
        restore.main()
    assert blocked.value.code == 2


def test_explicitly_confirmed_restore_calls_only_prevalidated_keys(monkeypatch):
    writes = []
    monkeypatch.setattr(restore, "CF_ACCOUNT_ID", ACC)
    monkeypatch.setattr(restore, "CF_API_TOKEN", SECRET)
    monkeypatch.setattr(restore, "download_snapshot", lambda *_: snapshot())
    monkeypatch.setattr(
        restore, "put_kv_value",
        lambda ns_id, key, val: writes.append((ns_id, key, val)),
    )
    monkeypatch.setattr(
        sys, "argv", [
            "restore", "--namespace", NS, "--date", DAY,
            "--confirm-live-restore", f"{NS}:{DAY}",
        ]
    )
    restore.main()
    assert writes == [(NSID, "customer:key", '{"tier":"PRO","status":"active"}')]


def test_wrong_live_confirmation_blocks_before_snapshot_download(monkeypatch):
    monkeypatch.setattr(
        restore, "download_snapshot",
        lambda *_: (_ for _ in ()).throw(AssertionError("should not download")),
    )
    monkeypatch.setattr(
        sys, "argv", [
            "restore", "--namespace", NS, "--date", DAY,
            "--confirm-live-restore", f"RATE_LIMIT_KV:{DAY}",
        ]
    )
    with pytest.raises(SystemExit) as blocked:
        restore.main()
    assert blocked.value.code == 2


def test_cf_kv_put_requires_exact_account_namespace_and_token(monkeypatch):
    monkeypatch.setattr(restore, "CF_ACCOUNT_ID", ACC)
    monkeypatch.setattr(restore, "CF_API_TOKEN", SECRET)
    monkeypatch.setattr(
        restore.urllib.request, "build_opener",
        lambda *_: (_ for _ in ()).throw(AssertionError("should not open")),
    )
    for path in [
        "/accounts/" + OTHER + "/storage/kv/namespaces/" + NSID + "/values/x",
        "/accounts/" + ACC + "/storage/kv/namespaces/" + OTHER + "/values/x",
        "/accounts/" + ACC + "/storage/kv/namespaces/" + NSID + "/keys",
        "/accounts/" + ACC + "/storage/kv/namespaces/" + NSID + "/values/",
    ]:
        with pytest.raises(ValueError, match="WRITE_DESTINATION_REJECTED"):
            restore.cf_put(path, b"value")


def test_cf_kv_put_uses_nonredirecting_opener_and_requires_ack(monkeypatch):
    monkeypatch.setattr(restore, "CF_ACCOUNT_ID", ACC)
    monkeypatch.setattr(restore, "CF_API_TOKEN", SECRET)
    sent = []
    body = {'success': True}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self): return json.dumps(body).encode()
    class Opener:
        def open(self, req, timeout):
            sent.append((req, timeout))
            return Response()
    def factory(handler):
        assert handler is restore._NoCloudflareBearerRedirect
        return Opener()
    monkeypatch.setattr(restore.urllib.request, "build_opener", factory)
    path = f"/accounts/{ACC}/storage/kv/namespaces/{NSID}/values/customer%3Akey"
    assert restore.cf_put(path, b"synthetic") == {"success": True}
    assert sent[0][0].get_header("Authorization") == f"Bearer {SECRET}"
    assert sent[0][0].get_method() == "PUT"
    assert sent[0][1] == 30
    body['success'] = False
    with pytest.raises(RuntimeError, match="TRANSPORT_RuntimeError"):
        restore.cf_put(path, b"synthetic")


def test_redirect_denied_and_http_error_does_not_log_key_or_token(monkeypatch):
    policy = restore._NoCloudflareBearerRedirect()
    for target in [
        "https://attacker.invalid/steal",
        "https://api.cloudflare.com/client/v4/elsewhere",
    ]:
        assert policy.redirect_request(
            None, None, 302, "Moved", {"Location": target}, target
        ) is None
    monkeypatch.setattr(restore, "CF_ACCOUNT_ID", ACC)
    monkeypatch.setattr(restore, "CF_API_TOKEN", SECRET)
    path = f"/accounts/{ACC}/storage/kv/namespaces/{NSID}/values/customer-sensitive"
    class Redirecting:
        def open(self, req, timeout):
            raise urllib.error.HTTPError(
                req.full_url, 302, "Redirected to " + SECRET,
                {"Location": "https://attacker.invalid"}, io.BytesIO(b"key:" + SECRET.encode())
            )
    monkeypatch.setattr(
        restore.urllib.request, "build_opener", lambda *_: Redirecting()
    )
    with pytest.raises(RuntimeError, match="HTTP_302") as err:
        restore.cf_put(path, b"value")
    assert SECRET not in str(err.value)
    assert "customer-sensitive" not in str(err.value)
    assert err.value.__cause__ is None


def test_restore_failure_log_never_emits_customer_key_or_token(monkeypatch, capsys):
    monkeypatch.setattr(
        restore, "put_kv_value",
        lambda *_: (_ for _ in ()).throw(RuntimeError("private:" + SECRET)),
    )
    doc = snapshot({"personally-identifying-key": "secret-value"})
    assert restore.restore_namespace(NS, NSID, doc, dry_run=False) is False
    output = capsys.readouterr().out
    assert "personally-identifying-key" not in output
    assert "secret-value" not in output
    assert SECRET not in output
