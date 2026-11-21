"""P0 2026-09-26: scripts/intel_freshness_guard.py decision table.

The publisher (sentinel-blogger) was displaced from the shared
sentinel-data-writer concurrency queue and the public feed went 9h stale.
The guard re-dispatches it -- but only when the PUBLISHED feed is stale, no
publisher run is in flight, and it is not hammering a broken pipeline.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import intel_freshness_guard as g  # noqa: E402

NOW = datetime(2026, 9, 26, 5, 0, tzinfo=timezone.utc)


def health(status, age_hours):
    return {"status": "degraded" if status != "fresh" else "ok",
            "intelligence": {"status": status, "age_seconds": int(age_hours * 3600), "generated_at": "2026-09-25T19:49:35Z"}}


def run(minutes_ago, conclusion=None, status="completed"):
    return {"created_at": (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
            "status": status, "conclusion": conclusion}


def test_fresh_feed_needs_nothing():
    assert g.decide(health("fresh", 1), [], [], NOW)["action"] == "none"


def test_the_incident_stale_9h_no_publisher_dispatches():
    d = g.decide(health("stale", 9), [], [], NOW)
    assert d["action"] == "dispatch"
    assert d["reason"] == "stale_no_active_publisher"
    assert d["exit"] == 0


def test_approaching_stale_dispatches_before_the_contract_breaks():
    # fresh but already past DISPATCH_AT_HOURS: a ~80 min run must start now to land inside 6h
    d = g.decide(health("fresh", 4.5), [], [], NOW)
    assert d["action"] == "dispatch"
    assert d["reason"] == "approaching_stale"


def test_never_dispatches_while_a_publisher_run_is_active_or_queued():
    assert g.decide(health("stale", 9), [run(5, status="in_progress")], [], NOW)["reason"] == "publisher_active"
    assert g.decide(health("stale", 9), [run(1, status="queued")], [], NOW)["action"] == "none"


def test_cooldown_after_its_own_dispatch():
    d = g.decide(health("stale", 9), [], [run(30, conclusion="success")], NOW)
    assert d["reason"] == "cooldown"
    assert g.decide(health("stale", 9), [], [run(120, conclusion="success")], NOW)["action"] == "dispatch"


def test_a_displaced_dispatch_is_retried_at_once():
    # the exact failure mode: the pending run was cancelled by a newer queued run
    assert g.decide(health("stale", 9), [], [run(20, conclusion="cancelled")], NOW)["action"] == "dispatch"


def test_stops_and_alerts_when_the_publisher_itself_is_failing():
    d = g.decide(health("stale", 12), [], [run(100, conclusion="failure")], NOW)
    assert d["action"] == "alert"
    assert d["reason"] == "publisher_failing"
    assert d["exit"] == 1
    # an old failure (> 4h) no longer blocks a new attempt
    assert g.decide(health("stale", 12), [], [run(300, conclusion="failure")], NOW)["action"] == "dispatch"


def test_unreadable_health_alerts_and_never_dispatches_blind():
    for h in (None, {}, {"intelligence": {}}):
        d = g.decide(h, [], [], NOW)
        assert d["action"] == "alert"
        assert d["exit"] == 1


def test_untrustworthy_timestamp_states_are_cured_by_a_run():
    for state in ("missing_timestamp", "invalid_timestamp", "future_timestamp"):
        assert g.decide({"intelligence": {"status": state, "age_seconds": None}}, [], [], NOW)["action"] == "dispatch"


def test_a_zombie_active_run_does_not_suppress_dispatch_forever():
    # one sentinel-blogger run has sat "pending" since 2026-05-26
    zombie = run(60 * 24 * 123, status="pending")
    assert g.decide(health("stale", 9), [zombie], [], NOW)["action"] == "dispatch"
    assert g.decide(health("stale", 9), [zombie, run(10, status="in_progress")], [], NOW)["reason"] == "publisher_active"


def test_customer_503_always_alerts_when_publisher_is_running():
    publisher = run(15, status="in_progress")
    for state, age in (("fresh", 2), ("stale", 9), ("missing_timestamp", 9)):
        h = health(state, age)
        h["reason"] = "public_classification_unverified"
        result = g.decide(h, [publisher], [], NOW, health_http_status=503)
        assert result["action"] == "alert"
        assert result["reason"] == "customer_api_unavailable"
        assert result["publisher_active"] is True
        assert result["health_http_status"] == 503
        assert result["exit"] == 1


def test_fresh_timestamp_does_not_hide_customer_503_without_publisher():
    result = g.decide(health("fresh", 1), [], [], NOW, health_http_status=503)
    assert result["action"] == "alert"
    assert result["reason"] == "customer_api_unavailable"
    assert result["publisher_active"] is False
    assert result["exit"] == 1


def test_stale_503_without_publisher_keeps_existing_bounded_self_heal():
    result = g.decide(health("stale", 9), [], [], NOW, health_http_status=503)
    assert result["action"] == "dispatch"
    assert result["reason"] == "stale_no_active_publisher"


def test_200_with_healthy_active_publisher_remains_non_alerting():
    result = g.decide(health("fresh", 2), [run(15, status="in_progress")], [], NOW, health_http_status=200)
    assert result["action"] == "none"
    assert result["exit"] == 0


def test_freshness_guard_fails_closed_when_github_run_state_cannot_be_verified(
        monkeypatch, capsys):
    """Never infer 'no publisher' from GitHub 401/403/429/5xx or bad JSON."""
    import json
    for gh_status, gh_body in (
        (401, {"message": "Bad credentials"}),
        (403, {"message": "API rate limit exceeded"}),
        (429, {"message": "rate limited"}),
        (503, None),
        (200, {"message": "schema not a run list"}),
        (200, {"workflow_runs": [{"id": "not-an-int", "created_at": "invalid"}]}),
    ):
        def fake_get_json(url, token=None):
            if url == g.HEALTH_URL:
                return 503, health("stale", 9)
            return gh_status, gh_body

        monkeypatch.setattr(g, "_get_json", fake_get_json)
        monkeypatch.setattr(g, "DRY_RUN", False)
        # A dispatch attempt would be a safety regression; forbid all outbound POST.
        monkeypatch.setattr(g, "_open_https",
                            lambda req, timeout: (_ for _ in ()).throw(
                                AssertionError("unexpected GitHub dispatch")))
        assert g.main() == 1
        report = json.loads(capsys.readouterr().out)
        assert report["action"] == "alert"
        assert report["reason"] == "github_run_state_unavailable"


def test_freshness_guard_fails_closed_if_dispatch_history_query_breaks(
        monkeypatch, capsys):
    import json
    def fake_get_json(url, token=None):
        if url == g.HEALTH_URL:
            return 503, health("stale", 9)
        if "event=workflow_dispatch" in url:
            return 403, {"message": "permission denied"}
        return 200, {"workflow_runs": []}

    monkeypatch.setattr(g, "_get_json", fake_get_json)
    monkeypatch.setattr(g, "DRY_RUN", False)
    monkeypatch.setattr(g, "_open_https",
                        lambda req, timeout: (_ for _ in ()).throw(
                            AssertionError("unexpected GitHub dispatch")))
    assert g.main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "github_run_state_unavailable"


def test_freshness_guard_preserves_existing_recovery_when_run_state_is_verified(
        monkeypatch, capsys):
    import json
    def fake_get_json(url, token=None):
        if url == g.HEALTH_URL:
            return 503, health("stale", 9)
        return 200, {"workflow_runs": []}

    monkeypatch.setattr(g, "_get_json", fake_get_json)
    monkeypatch.setattr(g, "DRY_RUN", True)
    assert g.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["action"] == "dispatch"
    assert report["reason"] == "stale_no_active_publisher"
    assert report["dry_run"] is True
