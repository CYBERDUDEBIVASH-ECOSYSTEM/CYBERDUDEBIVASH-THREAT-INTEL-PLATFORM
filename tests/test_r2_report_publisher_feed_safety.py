"""P0: invalid/stale source feeds must never retire last-known-good R2 reports.

All tests offline; no R2, Cloudflare, deployment or API activity.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import r2_report_publisher as pub  # noqa: E402


@pytest.mark.parametrize("payload", [
    None,
    "{not-json",
    "[]",
    '{"items":[]}',
    '{"items":"not a list"}',
    '[null]',
    '[{"title":"missing id"}]',
])
def test_malformed_or_empty_feed_blocks_before_state_or_r2(monkeypatch, tmp_path, payload):
    file = tmp_path / "feed.json"
    if payload is not None:
        file.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(pub, "FEED_JSON", file)
    monkeypatch.setattr(pub, "report_publishing_enabled", lambda: True)
    monkeypatch.setattr(pub, "load_publish_state",
                        lambda: (_ for _ in ()).throw(AssertionError("state must stay untouched")))
    monkeypatch.setattr(pub, "get_credentials",
                        lambda: (_ for _ in ()).throw(AssertionError("no Cloudflare authentication")))
    monkeypatch.setattr(pub, "s3_delete",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no delete")))
    monkeypatch.setattr(pub, "s3_cp",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no PUT")))
    monkeypatch.setattr(sys, "argv", ["r2_report_publisher.py"])
    reports = []
    monkeypatch.setattr(pub, "emit_summary",
                        lambda *a, **k: reports.append(k))
    assert pub.main() == 2
    assert reports[-1]["status"] == "BLOCKED"
    assert reports[-1]["extra"]["reason"] == "untrusted_or_empty_feed"


@pytest.mark.parametrize("root", [
    [{"id": "intel--one", "timestamp": "2026-11-22T00:00:00Z"}],
    {"items": [{"id": "intel--one"}]},
    {"advisories": [{"id": "intel--one"}]},
])
def test_supported_nonempty_feed_shapes_remain_valid(tmp_path, root):
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(root), encoding="utf-8")
    assert len(pub.load_verified_publish_feed(path)) == 1


def test_expired_only_feed_never_retires_last_known_good(monkeypatch, tmp_path):
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    file = tmp_path / "feed.json"
    file.write_text(json.dumps([{"id": "intel--old", "timestamp": old_timestamp}]))
    monkeypatch.setattr(pub, "FEED_JSON", file)
    monkeypatch.setattr(pub, "report_publishing_enabled", lambda: True)
    monkeypatch.setattr(pub, "apply_tlp_gate", lambda items, state: (items, []))
    monkeypatch.setattr(pub, "write_tlp_quarantine_report", lambda *a: None)
    state = {"items": {"intel--old": {
        "html_key": "reports/2026/11/intel--old.html",
        "canonical_ts": old_timestamp,
    }}}
    before = json.dumps(state, sort_keys=True)
    monkeypatch.setattr(pub, "load_publish_state", lambda: state)
    monkeypatch.setattr(pub, "save_publish_state",
                        lambda *a: (_ for _ in ()).throw(AssertionError("no state mutation")))
    monkeypatch.setattr(pub, "get_credentials",
                        lambda: (_ for _ in ()).throw(AssertionError("no R2 access")))
    monkeypatch.setattr(sys, "argv", ["r2_report_publisher.py"])
    reports = []
    monkeypatch.setattr(pub, "emit_summary", lambda *a, **k: reports.append(k))
    assert pub.main() == 2
    assert json.dumps(state, sort_keys=True) == before
    assert reports[-1]["extra"]["reason"] == "no_eligible_current_intelligence"


def test_all_tlp_withheld_feed_cannot_trigger_retirement(monkeypatch, tmp_path):
    file = tmp_path / "feed.json"
    file.write_text(json.dumps([{"id": "intel--one", "timestamp": datetime.now(timezone.utc).isoformat()}]))
    monkeypatch.setattr(pub, "FEED_JSON", file)
    monkeypatch.setattr(pub, "report_publishing_enabled", lambda: True)
    monkeypatch.setattr(pub, "load_publish_state", lambda: {"items": {}})
    monkeypatch.setattr(pub, "apply_tlp_gate", lambda items, state: ([], []))
    monkeypatch.setattr(pub, "write_tlp_quarantine_report", lambda *a: None)
    monkeypatch.setattr(pub, "get_credentials",
                        lambda: (_ for _ in ()).throw(AssertionError("no R2 access")))
    monkeypatch.setattr(sys, "argv", ["r2_report_publisher.py"])
    reports = []
    monkeypatch.setattr(pub, "emit_summary", lambda *a, **k: reports.append(k))
    assert pub.main() == 2
    assert reports[-1]["extra"]["reason"] == "no_eligible_current_intelligence"
