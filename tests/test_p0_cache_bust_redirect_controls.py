"""P0: admin cache-bust credentials must never leave the pinned HTTPS origin."""
from __future__ import annotations

import logging
import urllib.error

import pytest

from scripts import bust_kv_cache as cache

SAFE_URL = "https://intel.cyberdudebivash.com/api/admin/cache/bust?key=idx:reports"
SECRET = "synthetic-admin-secret-never-log"
EVIL = "https://attacker.invalid/capture"


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_successful_pinned_cache_bust_sends_header_only_to_expected_origin(monkeypatch):
    requests = []

    class FakeOpener:
        def open(self, req, timeout):
            assert timeout == 12
            requests.append(req)
            return FakeResponse()

    def factory(handler):
        assert handler is cache._RejectCacheBustRedirect
        return FakeOpener()

    monkeypatch.setattr(cache.urllib.request, "build_opener", factory)
    assert cache._make_request(SAFE_URL, SECRET) == 200
    assert len(requests) == 1
    assert requests[0].full_url == SAFE_URL
    assert requests[0].get_header("X-admin-secret") == SECRET
    assert requests[0].get_method() == "POST"


@pytest.mark.parametrize("url, method", [
    (EVIL, "POST"),
    ("http://intel.cyberdudebivash.com/api/admin/cache/bust?key=x", "POST"),
    ("https://intel.cyberdudebivash.com.attacker.invalid/api/admin/cache/bust?key=x", "POST"),
    ("https://user@intel.cyberdudebivash.com/api/admin/cache/bust?key=x", "POST"),
    ("https://intel.cyberdudebivash.com:444/api/admin/cache/bust?key=x", "POST"),
    ("https://intel.cyberdudebivash.com/api/admin/cache/other?key=x", "POST"),
    (SAFE_URL + "#fragment", "POST"),
    (SAFE_URL, "GET"),
])
def test_wrong_destination_or_method_is_rejected_before_opener(monkeypatch, url, method):
    def forbidden_factory(*_):
        raise AssertionError("network opener must not be created for untrusted URLs")

    monkeypatch.setattr(cache.urllib.request, "build_opener", forbidden_factory)
    assert cache._make_request(url, SECRET, method) == 0


def test_no_credential_in_redirect_even_to_same_origin():
    policy = cache._RejectCacheBustRedirect()
    for dest in [EVIL, SAFE_URL]:
        assert policy.redirect_request(
            None, None, 302, "Found", {"Location": dest}, dest,
        ) is None


def test_302_is_not_followed_and_preserves_best_effort_status(monkeypatch):
    attempts = []

    class RedirectOpener:
        def open(self, req, timeout):
            attempts.append(req.full_url)
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", {"Location": EVIL}, None,
            )

    monkeypatch.setattr(
        cache.urllib.request, "build_opener", lambda *_: RedirectOpener(),
    )
    assert cache._make_request(SAFE_URL, SECRET) == 302
    assert attempts == [SAFE_URL]


def test_transport_exception_does_not_log_admin_secret(monkeypatch, caplog):
    class BrokenOpener:
        def open(self, req, timeout):
            raise RuntimeError("LEAK:" + SECRET)

    monkeypatch.setattr(
        cache.urllib.request, "build_opener", lambda *_: BrokenOpener(),
    )
    with caplog.at_level(logging.DEBUG, logger=cache.log.name):
        assert cache._make_request(SAFE_URL, SECRET) == 0
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert SECRET not in messages
    assert "RuntimeError" in messages


def test_empty_secret_rejected_before_network(monkeypatch):
    monkeypatch.setattr(
        cache.urllib.request, "build_opener",
        lambda *_: (_ for _ in ()).throw(AssertionError("must not open")),
    )
    assert cache._make_request(SAFE_URL, "") == 0
