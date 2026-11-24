"""Offline regression for the authoritative CISA KEV HTTPS ingestion boundary."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import kev_feed_marker as kev  # noqa: E402


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status
        self.read_limits = []

    def read(self, limit: int):
        self.read_limits.append(limit)
        return self.body[:limit]


class FakeConnection:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, resource, headers):
        self.requests.append((method, resource, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def install_https(monkeypatch, response):
    connection = FakeConnection(response)
    creations = []

    def factory(host, port, timeout):
        creations.append((host, port, timeout))
        return connection

    monkeypatch.setattr(kev.http.client, "HTTPSConnection", factory)
    return connection, creations


def test_canonical_cisa_json_is_parsed_with_bounded_verified_https(monkeypatch):
    raw = json.dumps({"vulnerabilities": [{
        "cveID": "cve-2026-12345",
        "dateAdded": "2026-11-24",
        "vendorProject": "Example",
        "product": "Product",
        "vulnerabilityName": "Example vulnerability",
        "requiredAction": "Update",
        "dueDate": "2026-12-01",
    }]}).encode()
    response = FakeResponse(raw)
    connection, creations = install_https(monkeypatch, response)

    catalog = kev._fetch_kev_catalog()
    assert list(catalog) == ["CVE-2026-12345"]
    assert catalog["CVE-2026-12345"]["required_action"] == "Update"
    assert creations == [("www.cisa.gov", 443, kev.TIMEOUT)]
    assert len(connection.requests) == 1
    method, path, headers = connection.requests[0]
    assert method == "GET" and path == kev._CISA_KEV_PATH
    assert headers["Accept"] == "application/json"
    assert response.read_limits == [kev._MAX_CISA_KEV_BYTES + 1]
    assert connection.closed


@pytest.mark.parametrize("unapproved_url", [
    "http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov.attacker.test/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://attacker.test@www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov:8443/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "file:///etc/passwd",
])
def test_unapproved_destination_fails_before_network(monkeypatch, unapproved_url):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected connection to unapproved URL")

    monkeypatch.setattr(kev, "KEV_URL", unapproved_url)
    monkeypatch.setattr(kev.http.client, "HTTPSConnection", forbidden)
    assert kev._fetch_kev_catalog() == {}


@pytest.mark.parametrize("status", [301, 302, 307, 308, 403, 503])
def test_redirect_or_non_success_never_triggers_follow_up_request(monkeypatch, status):
    connection, creations = install_https(monkeypatch, FakeResponse(b"{}", status=status))
    assert kev._fetch_kev_catalog() == {}
    assert len(creations) == 1
    assert len(connection.requests) == 1
    assert connection.closed


def test_oversized_response_fails_closed(monkeypatch):
    body = b"x" * (kev._MAX_CISA_KEV_BYTES + 1)
    connection, _ = install_https(monkeypatch, FakeResponse(body))
    assert kev._fetch_kev_catalog() == {}
    assert connection.response.read_limits == [kev._MAX_CISA_KEV_BYTES + 1]
    assert connection.closed


@pytest.mark.parametrize("body", [
    b"not json", b"[]", b"{}", b'{"vulnerabilities": {}}',
    b'{"vulnerabilities": [null]}', b'{"vulnerabilities": [{"cveID": 123}]}',
])
def test_malformed_catalog_fails_closed(monkeypatch, body):
    connection, _ = install_https(monkeypatch, FakeResponse(body))
    assert kev._fetch_kev_catalog() == {}
    assert connection.closed


def test_network_exception_still_closes_connection(monkeypatch):
    class BrokenConnection:
        def __init__(self):
            self.closed = False
        def request(self, *args, **kwargs):
            raise OSError("simulated TLS/network failure")
        def close(self):
            self.closed = True
    connection = BrokenConnection()
    monkeypatch.setattr(kev.http.client, "HTTPSConnection",
                        lambda *args, **kwargs: connection)
    assert kev._fetch_kev_catalog() == {}
    assert connection.closed
