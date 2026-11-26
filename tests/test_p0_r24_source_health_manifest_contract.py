"""P0 R24: registered source health recognizes canonical manifest envelope."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import source_fabric_health as sfh


@pytest.mark.parametrize("payload", [
    [{"id": "intel--one", "feed_source": "rss_vendor_example"}],
    {"advisories": [{"id": "intel--one", "feed_source": "rss_vendor_example"}]},
    {"reports": [{"id": "intel--one", "feed_source": "rss_vendor_example"}]},
    {"items": [{"id": "intel--one", "feed_source": "rss_vendor_example"}]},
    {"data": [{"id": "intel--one", "feed_source": "rss_vendor_example"}]},
    {"entries": [{"id": "intel--one", "feed_source": "rss_vendor_example"}]},
])
def test_manifest_envelopes_preserve_real_rows(payload):
    assert sfh._manifest_rows(payload) == [
        {"id": "intel--one", "feed_source": "rss_vendor_example"}
    ]


@pytest.mark.parametrize("payload", [None, {}, {"advisories": {}}, "not-json",
                                        [], {"advisories": []}, [None, 2]])
def test_missing_or_invalid_manifest_never_creates_fake_source_rows(payload):
    assert sfh._manifest_rows(payload) == []


def _source():
    return {
        "source_id": "test_verified_rss",
        "canonical_name": "Reviewed RSS source",
        "pipeline_feed_source_key": "rss:*",
        "implementation_status": "ACTIVE",
        "integration_mode": "EVENT_STREAM",
        "wave": 1,
        "freshness_expectation": "DAILY",
        "criticality": "HIGH",
        "connector_ref": "scripts/true_intel_ingestor.py",
    }


def _audit(monkeypatch, payload):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(sfh, "load_registry", lambda: {"registry_version": "test-only"})
    monkeypatch.setattr(sfh, "all_sources", lambda: [_source()])
    monkeypatch.setattr(sfh, "_load_json_safe", lambda path: (
        payload if path == sfh.MANIFEST_PATH else
        {"sources": {}} if path == sfh.FEED_STATE_PATH else None
    ))
    return sfh.compute_health()


def test_real_fresh_event_from_envelope_has_observed_healthy_source(monkeypatch):
    source_event = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    raw = {"advisories": [{
        "id": "intel--fresh", "feed_source": "rss_vendor_example",
        "published_at": source_event,
    }]}
    result = _audit(monkeypatch, raw)
    assert result["manifest_total_entries"] == 1
    assert result["health_breakdown"]["HEALTHY"] == 1
    assert result["sources"][0]["records_received_current_window"] == 1


def test_old_event_remains_stale_and_does_not_pass_g10(monkeypatch):
    source_event = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    raw = {"advisories": [{
        "id": "intel--stale", "feed_source": "rss_vendor_example",
        "published_at": source_event
    }]}
    result = _audit(monkeypatch, raw)
    assert result["health_breakdown"]["HEALTHY"] == 0
    assert result["health_breakdown"]["STALE"] == 1


def test_zero_records_or_unmatched_collector_never_makes_healthy_source(monkeypatch):
    for payload in [{"items": []}, {"items": [{
        "id": "intel--unknown", "feed_source": "not_an_authorized_registry_key",
        "published_at": datetime.now(timezone.utc).isoformat()
    }]}]:
        result = _audit(monkeypatch, payload)
        assert result["health_breakdown"]["HEALTHY"] == 0
        assert result["sources"][0]["records_received_current_window"] == 0



def test_fresh_processing_timestamp_does_not_launder_old_publication(monkeypatch):
    now = datetime.now(timezone.utc)
    raw = {"advisories": [{
        "id": "intel--old-source",
        "feed_source": "rss_vendor_example",
        "published_at": (now - timedelta(days=12)).isoformat(),
        "timestamp": now.isoformat(),
        "processed_at": now.isoformat(),
    }]}
    audit = _audit(monkeypatch, raw)
    assert audit["health_breakdown"]["STALE"] == 1
    assert audit["health_breakdown"]["HEALTHY"] == 0


def test_unverified_processing_clock_alone_is_not_a_real_source_event(monkeypatch):
    now = datetime.now(timezone.utc).isoformat()
    raw = {"advisories": [{
        "id": "intel--no-source-clock",
        "feed_source": "rss_vendor_example",
        "timestamp": now, "processed_at": now,
    }]}
    audit = _audit(monkeypatch, raw)
    assert audit["health_breakdown"]["NO_DATA"] == 1
    assert audit["health_breakdown"]["HEALTHY"] == 0


def test_specific_rss_cursor_cannot_make_catchall_healthy(monkeypatch):
    specific = dict(_source(), source_id="specific", pipeline_feed_source_key="rss:cisa.gov")
    aggregate = dict(_source(), source_id="aggregate")
    now = datetime.now(timezone.utc)
    state = {"sources": {
        "rss_www_cisa_gov_advisories": {"last_seen": (now - timedelta(hours=1)).isoformat(),
                                         "last_reason_code": "OK"},
        "rss_vendor_old": {"last_seen": (now - timedelta(days=10)).isoformat(),
                            "last_reason_code": "HTTP_403"},
    }}
    monkeypatch.setattr(sfh, "load_registry", lambda: {"registry_version": "test-only"})
    monkeypatch.setattr(sfh, "all_sources", lambda: [aggregate, specific])
    monkeypatch.setattr(sfh, "_load_json_safe", lambda path: (
        state if path == sfh.FEED_STATE_PATH else [] if path == sfh.MANIFEST_PATH else None
    ))
    rows = {row["source_id"]: row for row in sfh.compute_health()["sources"]}
    assert rows["specific"]["health_status"] == "HEALTHY"
    assert rows["aggregate"]["health_status"] == "STALE"
    assert rows["aggregate"]["reason_code"] == "HTTP_403"
    del state["sources"]["rss_vendor_old"]
    rows = {row["source_id"]: row for row in sfh.compute_health()["sources"]}
    assert rows["aggregate"]["health_status"] == "NO_DATA"
    assert rows["aggregate"]["last_event"] is None


def test_rss_reason_uses_fetch_outcome_clock_not_publication_cursor():
    state = {
        "rss_vendor_a": {"last_seen": "2026-10-01T00:00:00Z",
                          "last_reason_at": "2026-10-03T00:00:00Z",
                          "last_reason_code": "HTTP_403"},
        "rss_vendor_b": {"last_seen": "2026-10-02T00:00:00Z",
                          "last_reason_at": "2026-10-02T00:00:00Z",
                          "last_reason_code": "OK"},
    }
    assert sfh._feed_state_reason_code("rss:*", state) == "HTTP_403"
    # Legacy entries without the outcome timestamp keep their cursor fallback.
    del state["rss_vendor_a"]["last_reason_at"]
    assert sfh._feed_state_reason_code("rss:*", state) == "OK"


def test_future_manifest_event_cannot_make_source_healthy(monkeypatch):
    now = datetime.now(timezone.utc)
    future = {"feed_source": "rss_vendor_example", "published_at": (now + timedelta(days=30)).isoformat()}
    result = _audit(monkeypatch, [future])
    assert result["health_breakdown"]["HEALTHY"] == 0
    assert result["sources"][0]["last_event"] is None
    old = {"feed_source": "rss_vendor_example", "published_at": (now - timedelta(days=5)).isoformat()}
    result = _audit(monkeypatch, [old, future])
    assert result["health_breakdown"]["STALE"] == 1
    assert result["sources"][0]["age_hours"] >= 119


def test_future_feed_cursor_cannot_hide_older_valid_cursor():
    now = datetime.now(timezone.utc)
    older = now - timedelta(days=5)
    future = now + timedelta(days=30)
    state = {
        "rss_vendor_future": {"last_seen": future.isoformat()},
        "rss_vendor_old": {"last_seen": older.isoformat()},
        "nvd_cve": {"last_seen": future.isoformat()},
    }
    assert sfh._feed_state_last_seen("rss:*", state, now=now) == older
    assert sfh._feed_state_last_seen("nvd_cve", state, now=now) is None
    del state["rss_vendor_old"]
    assert sfh._feed_state_last_seen("rss:*", state, now=now) is None


def test_future_reference_sync_does_not_certify_health(monkeypatch):
    source = dict(_source(), source_id="mitre_attack", integration_mode="REFERENCE_SYNC",
                  pipeline_feed_source_key="mitre_attack")
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(sfh, "load_registry", lambda: {"registry_version": "test-only"})
    monkeypatch.setattr(sfh, "all_sources", lambda: [source])
    monkeypatch.setattr(sfh, "_load_json_safe", lambda path: (
        {"synced_at": (now + timedelta(days=30)).isoformat(), "counts": {"techniques": 1}}
        if path == sfh.ATTCK_PATH else None
    ))
    result = sfh.compute_health()
    assert result["health_breakdown"]["HEALTHY"] == 0
    assert result["sources"][0]["health_status"] == "NO_DATA"
    assert result["sources"][0]["last_event"] is None
