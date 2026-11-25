#!/usr/bin/env python3
"""
tests/test_public_feed_freshness_gate.py -- offline tests for the external
post-deploy freshness gate (scripts/public_feed_freshness_gate.py).

The 2026-09-24 production state (feed generated 2026-08-26, /api/health 200
"ok") must FAIL; a fresh feed with an agreeing /api/health must PASS.
"""
import sys
import urllib.error
import urllib.request

import pytest
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import public_feed_freshness_gate as gate  # noqa: E402

NOW = datetime(2026, 9, 24, 6, 0, 0, tzinfo=timezone.utc)
ITEMS = [{"id": "intel--a"}, {"id": "intel--b"}]
FRESH = {"generated_at": "2026-09-24T05:00:00Z", "count": 2, "items": ITEMS}
STALE = {"generated_at": "2026-08-26T09:55:27Z", "count": 2, "items": ITEMS}
OK = {"status": "ok"}
DEGRADED = {"status": "degraded", "reason": "intelligence_stale"}


def run(feed=(200, FRESH, None), health=(200, OK, None)):
    return gate.evaluate(*feed, *health, now=NOW)


def test_fresh_feed_and_ok_health_pass():
    r = run()
    assert r["verdict"] == "PASS", r["failures"]


def test_incident_state_fails_on_both_counts():
    r = run(feed=(200, STALE, None), health=(200, OK, None))
    assert r["verdict"] == "FAIL"
    assert any("stale" in f for f in r["failures"])
    assert any("reports status 'ok'" in f for f in r["failures"])


def test_stale_feed_with_truthful_503_health_still_fails_release():
    r = run(feed=(200, STALE, None), health=(503, DEGRADED, None))
    assert r["verdict"] == "FAIL"
    assert not any("reports status 'ok'" in f for f in r["failures"])


def test_fresh_feed_but_unhealthy_health_fails():
    assert run(health=(503, DEGRADED, None))["verdict"] == "FAIL"


def test_empty_missing_invalid_and_unreachable_feeds_fail():
    for feed in [
        (200, {"generated_at": "2026-09-24T05:00:00Z", "items": []}, None),
        (200, {"items": ITEMS}, None),
        (200, {"generated_at": "not-a-date", "items": ITEMS}, None),
        (200, {"generated_at": "2099-01-01T00:00:00Z", "items": ITEMS}, None),
        (503, {"error": "Feed not available"}, None),
        (None, None, "URLError: timed out"),
        (200, None, "unparseable JSON"),
    ]:
        assert run(feed=feed, health=(503, DEGRADED, None))["verdict"] == "FAIL", feed


def test_unreachable_health_fails():
    assert run(health=(None, None, "URLError"))["verdict"] == "FAIL"


def test_gate_uses_the_canonical_contract_threshold():
    import public_freshness_contract as c
    assert gate.contract is c
    r = run()
    assert r["max_public_manifest_age_hours"] == c.max_public_manifest_age_hours()


@pytest.mark.parametrize("url", [
    "http://example.com/feed",
    "file:///etc/passwd",
    "ftp://example.com/feed",
    "https://user:pass@example.com/feed",
    "https://example.com:0/feed",
    "https://example.com:bad/feed",
    "https://example.com/feed#fragment",
    "https://example.com/white space",
])
def test_unsafe_initial_target_rejected_before_network(url, monkeypatch):
    def unexpected_network(*args, **kwargs):
        pytest.fail("unsafe target must not construct a network client")
    monkeypatch.setattr(gate.urllib.request, "build_opener", unexpected_network)
    status, body, error = gate._get_json(url, 1)
    assert status is None and body is None and error


@pytest.mark.parametrize("target", [
    "http://example.com/next",
    "https://other.example.com/next",
    "https://example.com:444/next",
    "https://user@example.com/next",
])
def test_cross_origin_or_unsafe_redirect_rejected(target):
    handler = gate._SameOriginHTTPSRedirect()
    request = urllib.request.Request("https://example.com/feed")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(request, None, 302, "Found", {}, target)


def test_same_https_origin_redirect_preserved():
    handler = gate._SameOriginHTTPSRedirect()
    request = urllib.request.Request("https://example.com/feed")
    redirect = handler.redirect_request(
        request, None, 302, "Found", {}, "https://example.com:443/next")
    assert redirect.full_url == "https://example.com:443/next"


def test_valid_https_request_keeps_headers_and_json(monkeypatch):
    from unittest.mock import MagicMock
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.read.return_value = b'{"status":"ok"}'
    opener = MagicMock()
    opener.open.return_value = response
    build = MagicMock(return_value=opener)
    monkeypatch.setattr(gate.urllib.request, "build_opener", build)
    assert gate._get_json("https://example.com/feed", 3) == (200, {"status": "ok"}, None)
    assert isinstance(build.call_args.args[0], gate._SameOriginHTTPSRedirect)
    req = opener.open.call_args.args[0]
    assert req.get_header("User-agent") == gate.USER_AGENT
    assert req.get_header("Cache-control") == "no-cache"
    assert opener.open.call_args.kwargs["timeout"] == 3
