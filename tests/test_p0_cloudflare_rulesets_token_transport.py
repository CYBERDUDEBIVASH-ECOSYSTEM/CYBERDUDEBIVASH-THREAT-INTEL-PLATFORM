"""Offline P0: Cloudflare Rulesets API bearer secrets never follow redirects."""
from __future__ import annotations

import io
import logging
import urllib.error

import pytest

from scripts import apply_security_headers_rule as rules

SECRET = "SYNTHETIC_CLOUDFLARE_BEARER_NEVER_EXPOSE"
ZONE = "a" * 32
ENTRYPOINT = f"/zones/{ZONE}/rulesets/phases/http_response_headers_transform/entrypoint"
LOOKUP = "/zones?name=cyberdudebivash.com"


class FakeResponse:
    status = 200
    headers = {"X-Frame-Options": "DENY"}

    def __init__(self, data=b'{"success":true,"result":{}}'):
        self.data = data

    def read(self, *_):
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_exact_zone_lookup_and_ruleset_write_pin_destination(monkeypatch):
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return FakeResponse()

    def build(handler):
        assert handler is rules._NoBearerRedirect
        return Opener()

    monkeypatch.setattr(rules.urllib.request, "build_opener", build)
    assert rules._api("GET", LOOKUP, SECRET)[0] == 200
    assert rules._api("GET", ENTRYPOINT, SECRET)[0] == 200
    assert rules._api("PUT", ENTRYPOINT, SECRET, {"rules": []})[0] == 200
    assert len(requests) == 3
    for request, timeout in requests:
        assert request.full_url.startswith("https://api.cloudflare.com/client/v4/")
        assert request.get_header("Authorization") == f"Bearer {SECRET}"
        assert timeout == 30
    assert requests[0][0].get_method() == "GET"
    assert requests[-1][0].get_method() == "PUT"


@pytest.mark.parametrize("method,path,body,token", [
    ("GET", "/zones?name=other.example", None, SECRET),
    ("GET", "/zones?name=cyberdudebivash.com#leak", None, SECRET),
    ("GET", "//attacker.invalid/", None, SECRET),
    ("GET", "/zones/../zones?name=cyberdudebivash.com", None, SECRET),
    ("PUT", LOOKUP, {"rules": []}, SECRET),
    ("POST", ENTRYPOINT, {"rules": []}, SECRET),
    ("GET", ENTRYPOINT, {"rules": []}, SECRET),
    ("PUT", ENTRYPOINT, None, SECRET),
    ("PUT", "/zones/" + "g"*32 + "/rulesets/phases/http_response_headers_transform/entrypoint", {"rules":[]}, SECRET),
    ("GET", "/user/tokens/verify", None, SECRET),
    ("GET", LOOKUP, None, ""),
])
def test_reject_invalid_api_target_without_creating_network_opener(
    monkeypatch, method, path, body, token
):
    monkeypatch.setattr(
        rules.urllib.request, "build_opener",
        lambda *_: (_ for _ in ()).throw(AssertionError("must never open")),
    )
    with pytest.raises(ValueError, match="destination or method rejected"):
        rules._api(method, path, token, body)


def test_bearer_redirects_refused_cross_origin_and_same_origin():
    policy = rules._NoBearerRedirect()
    for destination in [
        "https://attacker.invalid/steal",
        "https://api.cloudflare.com/client/v4/zones?name=cyberdudebivash.com",
    ]:
        assert policy.redirect_request(
            None, None, 302, "Moved", {"Location": destination}, destination
        ) is None


def test_redirect_response_does_not_retry_or_leak_bearer(monkeypatch):
    calls = []

    class RedirectOpener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            raise urllib.error.HTTPError(
                request.full_url, 302, "Moved", {"Location": "https://attacker.invalid/"},
                io.BytesIO(b"not-json"),
            )

    monkeypatch.setattr(
        rules.urllib.request, "build_opener", lambda *_: RedirectOpener()
    )
    status, data = rules._api("GET", LOOKUP, SECRET)
    assert status == 302
    assert data == {}
    assert calls == [rules.API + LOOKUP]


def test_transport_exception_redacts_bearer_text(monkeypatch):
    class BrokenOpener:
        def open(self, request, timeout):
            raise RuntimeError("Authorization: Bearer " + SECRET)

    monkeypatch.setattr(
        rules.urllib.request, "build_opener", lambda *_: BrokenOpener()
    )
    with pytest.raises(RuntimeError, match="RuntimeError") as err:
        rules._api("GET", LOOKUP, SECRET)
    assert SECRET not in str(err.value)
    assert err.value.__cause__ is None


def test_api_errors_do_not_echo_untrusted_body_with_bearer(monkeypatch):
    monkeypatch.setattr(
        rules, "_api",
        lambda *args, **kwargs: (403, {"errors": [SECRET]}),
    )
    with pytest.raises(RuntimeError) as lookup:
        rules._zone_id(SECRET)
    assert SECRET not in str(lookup.value)
    with pytest.raises(RuntimeError) as entrypoint:
        rules._entrypoint(SECRET, ZONE)
    assert SECRET not in str(entrypoint.value)


@pytest.mark.parametrize("url", [
    "https://evil.invalid/",
    "http://intel.cyberdudebivash.com/",
    "https://intel.cyberdudebivash.com.attacker.invalid/",
    "https://user@intel.cyberdudebivash.com/",
    "https://intel.cyberdudebivash.com:8443/",
    "https://intel.cyberdudebivash.com/admin/private",
    "https://intel.cyberdudebivash.com/?secrets=1",
])
def test_header_verify_rejects_unapproved_host_path_or_query(monkeypatch, url):
    monkeypatch.setattr(
        rules.urllib.request, "build_opener",
        lambda *_: (_ for _ in ()).throw(AssertionError("must never open")),
    )
    with pytest.raises(ValueError, match="destination rejected"):
        rules._headers(url)


def test_header_verify_uses_pinned_https_and_refuses_redirects(monkeypatch):
    called = []

    class Opener:
        def open(self, request, timeout):
            called.append((request.full_url, timeout))
            return FakeResponse()

    def build(handler):
        assert handler is rules._NoBearerRedirect
        return Opener()

    monkeypatch.setattr(rules.urllib.request, "build_opener", build)
    status, headers = rules._headers("https://intel.cyberdudebivash.com/pricing.html")
    assert status == 200
    assert headers["x-frame-options"] == "DENY"
    assert called == [("https://intel.cyberdudebivash.com/pricing.html", 30)]
