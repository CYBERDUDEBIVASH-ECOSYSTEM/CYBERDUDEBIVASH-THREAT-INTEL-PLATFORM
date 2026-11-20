"""Offline regression for R19 production certification network egress."""
from __future__ import annotations

import sys
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import p0_r19_live_release_truth as gate


def test_redirect_handler_denies_all_redirects():
    request = gate.urllib.request.Request(gate.ORIGIN + "/api/health")
    for status in (301, 302, 303, 307, 308):
        assert gate._NoRedirects().redirect_request(
            request, None, status, "Redirect", {},
            "https://attacker.example/collect"
        ) is None


def test_probe_uses_redirect_denying_opener():
    class FakeOpener:
        def open(self, request, timeout):
            assert timeout == 12
            assert request.full_url == gate.ORIGIN + "/api/health"
            raise urllib.error.HTTPError(
                request.full_url, 302, "Redirect",
                {"Location": "https://attacker.example/collect"}, None
            )

    with mock.patch.object(gate.urllib.request, "build_opener",
                           return_value=FakeOpener()) as build:
        with pytest.raises(urllib.error.HTTPError) as exc:
            gate._get_json("/api/health")
    assert exc.value.code == 302
    assert isinstance(build.call_args.args[0], gate._NoRedirects)


def test_external_redirect_never_attempted():
    # Exercises the real urllib redirect handler and uses no network access.
    req = gate.urllib.request.Request(gate.ORIGIN + "/api/health")
    handler = gate._NoRedirects()
    assert handler.redirect_request(
        req, None, 302, "Found", {"Location": "https://attacker.example"},
        "https://attacker.example"
    ) is None
