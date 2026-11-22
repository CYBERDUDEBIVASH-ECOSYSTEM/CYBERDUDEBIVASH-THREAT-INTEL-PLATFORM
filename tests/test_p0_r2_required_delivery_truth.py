"""P0 R2 report delivery integrity gate: negative controls, no external network."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from scripts import r2_reports_integrity as gate
from tests.r2_publish_state_helper import mark_published


def _fixture(monkeypatch, tmp_path):
    root = tmp_path / "api"
    (root / "reports").mkdir(parents=True)
    reports = [
        {"id": "intel--aaa", "path": "/reports/2026/11/intel--aaa.html"},
        {"id": "intel--bbb", "path": "/reports/2026/11/intel--bbb.html"},
    ]
    payload = {"reports": reports, "reports_listed": 2, "total_reports": 2}
    index, latest, feed = root / "reports" / "index.json", root / "reports" / "latest.json", root / "feed.json"
    index.write_text(json.dumps(payload))
    latest.write_text(json.dumps(payload))
    # These are deliberately fresh: the publisher only owes report delivery
    # for the canonical rolling window, never every historical feed row.
    fresh_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # Production feed items carry a TLP label (STAGE 3.1.0b backfill). The
    # publisher withholds unlabelled/restricted items, so a realistic fixture
    # must label the items it expects to be published.
    feed.write_text(json.dumps([
        {"id": row["id"], "report_url": row["path"], "timestamp": fresh_ts,
         "tlp": "TLP:CLEAR"}
        for row in reports
    ]))
    # These reports were rendered and PUT by the bounded publisher, so STAGE
    # 3.5.1 owes R2 delivery for them (see tests/r2_publish_state_helper.py).
    mark_published(monkeypatch, tmp_path, [(r["id"], r["path"]) for r in reports])
    for name, p in [("INDEX_PATH", index), ("LATEST_PATH", latest), ("FEED_PATH", feed)]:
        monkeypatch.setattr(gate, name, p)
    monkeypatch.setenv("CF_ACCOUNT_ID", "testaccount")
    monkeypatch.setenv("CF_R2_REPORTS_KEY_ID", "local-test")
    monkeypatch.setenv("CF_R2_REPORTS_SECRET_KEY", "local-test")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    events = []
    monkeypatch.setattr(gate, "_write_github_env", lambda k, v: events.append((k, v)))
    before = (index.read_bytes(), latest.read_bytes())
    return index, latest, feed, reports, events, before


def _never_write(*args, **kwargs):
    raise AssertionError("blocked audit must not write to cloud")


def test_partial_current_run_loss_blocks_without_catalog_mutation(monkeypatch, tmp_path):
    idx, latest, _, rows, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    monkeypatch.setattr(gate, "_r2_object_exists", lambda key, *args: not key.endswith("bbb.html"))
    assert gate.main() == 1
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_REPORTS" in v for _, v in events)


def test_feed_only_key_is_head_checked_and_blocks_catalog(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    extra = "/reports/2026/11/intel--not-in-catalog.html"
    f = json.loads(feed.read_text())
    f.append({
        "id": "intel--new", "report_url": extra, "tlp": "TLP:CLEAR",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(f))
    # Rendered and PUT, but absent from the customer catalog: a real defect.
    mark_published(monkeypatch, tmp_path, [("intel--new", extra)])
    checked = []
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    def head(key, *args):
        checked.append(key)
        return True
    monkeypatch.setattr(gate, "_r2_object_exists", head)
    assert gate.main() == 1
    assert extra.lstrip("/") in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("unindexed_1" in v for _, v in events)


def test_expired_feed_only_report_is_not_falsely_required_as_current(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    historical = "/reports/2026/11/intel--old-feed-only.html"
    items = json.loads(feed.read_text())
    items.append({
        "id": "intel--historical", "report_url": historical,
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=72))
                     .isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(items))
    heads = []
    def head(key, *args):
        heads.append(key)
        return True
    monkeypatch.setattr(gate, "_r2_object_exists", head)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert historical.lstrip("/") not in heads
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any(v.startswith("OK_purged=0") for _, v in events)


def test_in_window_feed_only_report_still_blocks_catalog(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    fresh_key = "/reports/2026/11/intel--not-indexed-new.html"
    items.append({
        "id": "intel--new", "report_url": fresh_key, "tlp": "TLP:CLEAR",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    feed.write_text(json.dumps(items))
    mark_published(monkeypatch, tmp_path, [("intel--new", fresh_key)])
    checked = []
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: checked.append(key) or True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 1
    assert fresh_key.lstrip("/") in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("unindexed_1" in v for _, v in events)


def test_expired_only_feed_does_not_certify_empty_current_delivery(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    old = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    for item in items:
        item["timestamp"] = old
    feed.write_text(json.dumps(items))
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_FEED_EVIDENCE" in v for _, v in events)


def _now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# The publisher (r2_report_publisher.main) removes TLP-withheld items with
# apply_tlp_gate() BEFORE building candidates, so it never uploads them. The
# gate must demand delivery only for what the publisher is obligated to
# publish; otherwise one restricted/unlabelled in-window advisory makes the
# gate unsatisfiable and blocks publication of the whole intelligence feed.
@pytest.mark.parametrize("withheld", [
    {"tlp": "TLP:RED"},
    {"tlp": "TLP:AMBER"},
    {},  # no label from an unapproved collector -> MISSING_LABEL -> withheld
], ids=["restricted-red", "restricted-amber", "unlabelled"])
def test_tlp_withheld_in_window_report_is_not_required_in_r2(monkeypatch, tmp_path, withheld):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    held_key = "/reports/2026/11/intel--tlp-withheld.html"
    items = json.loads(feed.read_text())
    items.append({"id": "intel--withheld", "report_url": held_key,
                  "timestamp": _now_z(), **withheld})
    feed.write_text(json.dumps(items))
    checked = []

    def head(key, *args):
        checked.append(key)
        # The publisher never uploaded the withheld report, so R2 has no object.
        return key != held_key.lstrip("/")

    monkeypatch.setattr(gate, "_r2_object_exists", head)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert held_key.lstrip("/") not in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert not any("BLOCKED" in v for _, v in events)


def test_withheld_in_window_count_and_reason_codes_are_logged(monkeypatch, tmp_path, caplog):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    items += [
        {"id": "intel--red", "tlp": "TLP:RED", "timestamp": _now_z(),
         "report_url": "/reports/2026/11/intel--red.html"},
        {"id": "intel--nolabel", "timestamp": _now_z(),
         "report_url": "/reports/2026/11/intel--nolabel.html"},
        # Withheld but OUT of window: must not inflate the in-window count.
        {"id": "intel--old-red", "tlp": "TLP:RED",
         "timestamp": (datetime.now(timezone.utc) - timedelta(hours=72))
                      .isoformat().replace("+00:00", "Z"),
         "report_url": "/reports/2026/11/intel--old-red.html"},
    ]
    feed.write_text(json.dumps(items))
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    with caplog.at_level("INFO", logger="sentinel.r2_integrity"):
        assert gate.main() == 0
    line = next(r.getMessage() for r in caplog.records
                if "TLP policy withheld" in r.getMessage())
    assert "withheld 2 in-window item(s)" in line
    assert "'MISSING_LABEL': 1" in line and "'RESTRICTED_LABEL': 2" in line
    # Ids and report content are never logged, only counts and reason codes.
    assert "intel--red" not in line and "intel--nolabel" not in line


def test_tlp_withheld_item_cannot_mask_real_current_loss(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    items.append({"id": "intel--withheld", "tlp": "TLP:RED", "timestamp": _now_z(),
                  "report_url": "/reports/2026/11/intel--tlp-withheld.html"})
    feed.write_text(json.dumps(items))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    # A TLP:CLEAR in-window report that WAS owed (bbb) is genuinely absent.
    monkeypatch.setattr(gate, "_r2_object_exists", lambda key, *args: not key.endswith("bbb.html"))
    assert gate.main() == 1
    assert (idx.read_bytes(), latest.read_bytes()) == before
    # Exactly one owed report is missing: the withheld item is not counted.
    assert any("BLOCKED_CURRENT_REPORTS_missing_1_unindexed_0" in v for _, v in events)


def test_all_in_window_items_withheld_does_not_certify_delivery(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    items = json.loads(feed.read_text())
    for item in items:
        item["tlp"] = "TLP:RED"
    feed.write_text(json.dumps(items))
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    # Same fail-closed answer as the publisher's BLOCKED_NO_ELIGIBLE_FEED: an
    # empty obligation set is "delivery not proven", never "delivery proven".
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_FEED_EVIDENCE" in v for _, v in events)


# ---- late renders ----------------------------------------------------------
# STAGE 3.5a publishes only what is rendered when it runs. Items the feed gains
# afterwards (e.g. STAGE 3.1.13's multi-source collector) are rendered by STAGE
# 5.4.0b and published by 5.4.0c, then policed by the end-of-run gates (5.4.1
# existence validator, 5.8.1c convergence). STAGE 3.5.1 sits BEFORE that repair
# and 5.4.0b/c are skipped when it fails, so demanding an R2 object for an item
# that has not been rendered yet deadlocks publication of the whole feed.
# Production run 44941209717: BLOCKED_CURRENT_REPORTS_missing_2_unindexed_2 --
# two in-window TLP:CLEAR items, no HTML anywhere, no publish state.
def _late_item(item_id="intel--late-render"):
    path = f"/reports/2026/11/{item_id}.html"
    return {"id": item_id, "tlp": "TLP:CLEAR", "timestamp": _now_z(),
            "report_url": path}, path


def test_late_render_without_a_report_is_not_required_at_3_5_1(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    late, late_path = _late_item()
    feed.write_text(json.dumps(json.loads(feed.read_text()) + [late]))
    checked = []

    def head(key, *args):
        checked.append(key)
        return key != late_path.lstrip("/")      # no object: never rendered

    monkeypatch.setattr(gate, "_r2_object_exists", head)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert late_path.lstrip("/") not in checked
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert not any("BLOCKED" in v for _, v in events)


def test_report_rendered_locally_but_missing_from_r2_still_blocks(monkeypatch, tmp_path):
    """Control: a real upload failure must not be excused as a 'late render'."""
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    item, path = _late_item("intel--rendered-not-uploaded")
    feed.write_text(json.dumps(json.loads(feed.read_text()) + [item]))
    html = tmp_path / "reports" / "intel--rendered-not-uploaded.html"
    html.parent.mkdir(parents=True)
    html.write_text("<html></html>")                 # rendered on the runner
    pub = mark_published(monkeypatch, tmp_path, [])  # not in publish state
    monkeypatch.setattr(pub, "rel_report_path",
                        lambda it: html if it.get("id") == item["id"] else tmp_path / "absent.html")
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: key != path.lstrip("/"))
    assert gate.main() == 1
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_REPORTS_missing_1_unindexed_1" in v for _, v in events)


def test_late_render_cannot_mask_a_real_published_report_loss(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    late, _ = _late_item()
    feed.write_text(json.dumps(json.loads(feed.read_text()) + [late]))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("bbb.html"))
    assert gate.main() == 1
    assert (idx.read_bytes(), latest.read_bytes()) == before
    # Exactly one owed report is missing; the late render is not counted.
    assert any("BLOCKED_CURRENT_REPORTS_missing_1_unindexed_0" in v for _, v in events)


def test_only_late_renders_do_not_certify_delivery(monkeypatch, tmp_path):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    # Nothing was rendered or published: an empty obligation set proves nothing.
    (tmp_path / "r2_report_publish_state.json").write_text(
        json.dumps({"schema_version": "1.0", "items": {}}))
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CURRENT_FEED_EVIDENCE" in v for _, v in events)


def test_pending_render_count_is_logged(monkeypatch, tmp_path, caplog):
    idx, latest, feed, rows, events, before = _fixture(monkeypatch, tmp_path)
    late, _ = _late_item()
    feed.write_text(json.dumps(json.loads(feed.read_text()) + [late]))
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    with caplog.at_level("INFO", logger="sentinel.r2_integrity"):
        assert gate.main() == 0
    line = next(r.getMessage() for r in caplog.records if "not yet rendered" in r.getMessage())
    assert "1 in-window report(s) not yet rendered" in line
    assert "STAGE 5.4.0b" in line and "intel--late-render" not in line


@pytest.mark.parametrize("field", ["CF_ACCOUNT_ID", "CF_R2_REPORTS_KEY_ID", "CF_R2_REPORTS_SECRET_KEY"])
def test_missing_credentials_blocks_not_skips(monkeypatch, tmp_path, field):
    idx, latest, _, _, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.delenv(field)
    # Fallback to job-level credentials must not mask missing dedicated key.
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before


def test_invalid_index_fails_closed_without_r2_writes(monkeypatch, tmp_path):
    idx, _, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    idx.write_text("{corrupt")
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert any("BLOCKED_READ_INDEX" in v for _, v in events)


def test_invalid_feed_fails_closed_without_r2_writes(monkeypatch, tmp_path):
    idx, latest, feed, _, events, before = _fixture(monkeypatch, tmp_path)
    feed.write_text('{"items": [{"id": "no-report-url"}]}')
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before


def test_failed_historical_catalog_publication_rolls_back_local_bytes(monkeypatch, tmp_path):
    idx, latest, feed, _, events, before = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    payload["reports_listed"] = 3
    payload["total_reports"] = 3
    idx.write_text(json.dumps(payload))
    original = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test")
    monkeypatch.setattr(gate, "_s3_cp", lambda *args: False)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == original
    assert any("BLOCKED_CATALOG_PUBLICATION" in v for _, v in events)


def test_all_verified_current_run_reports_can_pass_without_mutation(monkeypatch, tmp_path):
    idx, latest, _, _, events, before = _fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(gate, "_r2_object_exists", lambda *args: True)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 0
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any(v.startswith("OK_purged=0") for _, v in events)


def test_catalog_readback_mismatch_blocks_release_and_restores_local(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    idx.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test")
    calls = []
    monkeypatch.setattr(gate, "_s3_cp", lambda *args: calls.append("upload") or True)
    monkeypatch.setattr(gate, "_remote_catalog_matches", lambda *args: False)
    assert gate.main() == 2
    assert calls
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert any("BLOCKED_CATALOG_PUBLICATION" in v for _, v in events)


def test_unreadable_latest_catalog_blocks_before_any_r2_operation(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    latest.write_text("{invalid")
    monkeypatch.setattr(gate, "_r2_object_exists", _never_write)
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    assert gate.main() == 2
    assert any("BLOCKED_LATEST_SCHEMA" in v for _, v in events)


def test_authenticated_catalog_readback_requires_exact_bytes(monkeypatch, tmp_path):
    local = tmp_path / "local.json"
    local.write_bytes(b'{"verified":true}')
    remote_bytes = b'{"verified":true}'
    commands = []
    def fake_run(command, **kwargs):
        import subprocess
        commands.append(command)
        # AWS 'get-object' writes the requested output file.
        output_path = command[-1]
        from pathlib import Path
        Path(output_path).write_bytes(remote_bytes)
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    args = (str(local), "data", "api/reports/index.json",
            "https://test.r2.cloudflarestorage.com", "k", "s")
    assert gate._remote_catalog_matches(*args) is True
    remote_bytes = b'{"verified":false}'
    assert gate._remote_catalog_matches(*args) is False
    assert all("--region" in c and c[c.index("--region")+1] == "auto" for c in commands)


def test_index_write_failure_fails_closed_before_remote_catalog_mutation(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    payload = json.loads(idx.read_text())
    payload["reports"].append({"id": "old", "path": "/reports/2025/01/intel--old.html"})
    idx.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)

    def fail_replace(*args):
        raise OSError("simulated read-only filesystem")

    monkeypatch.setattr(gate.os, "replace", fail_replace)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert ("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LOCAL_INDEX_WRITE") in events


def test_latest_write_failure_restores_prior_index_change(monkeypatch, tmp_path):
    idx, latest, _, _, events, _ = _fixture(monkeypatch, tmp_path)
    historical = {"id": "old", "path": "/reports/2025/01/intel--old.html"}
    for path in (idx, latest):
        payload = json.loads(path.read_text())
        payload["reports"].append(historical)
        path.write_text(json.dumps(payload))
    before = (idx.read_bytes(), latest.read_bytes())
    monkeypatch.setattr(gate, "_r2_object_exists",
                        lambda key, *args: not key.endswith("old.html"))
    monkeypatch.setattr(gate, "_s3_cp", _never_write)
    real_replace = gate.os.replace

    def fail_latest_only(src, dest):
        if str(dest) == str(latest):
            raise OSError("simulated latest-catalog write failure")
        return real_replace(src, dest)

    monkeypatch.setattr(gate.os, "replace", fail_latest_only)
    assert gate.main() == 2
    assert (idx.read_bytes(), latest.read_bytes()) == before
    assert ("R2_REPORTS_INTEGRITY_STATUS", "BLOCKED_LOCAL_LATEST_WRITE") in events
