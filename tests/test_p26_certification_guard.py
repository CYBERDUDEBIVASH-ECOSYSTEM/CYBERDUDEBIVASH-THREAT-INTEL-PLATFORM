"""P0: a stale, unverified or partial P26 certificate must never certify global release."""
from datetime import datetime, timezone
import pytest
from scripts.p26_certification_guard import validate_p26_worldwide_report as validate

NOW = datetime(2026, 11, 19, 16, 30, tzinfo=timezone.utc)

def good():
    return {
        "release_tier": "WORLDWIDE_RELEASE",
        "blocker_count": 0, "warning_count": 0,
        "feed_items": 5, "generated_at": "2026-11-19T16:20:00Z",
        "github_run_id": "123", "github_sha": "a" * 40,
        "audits": {f"A{i}": {"passed": True} for i in range(1, 14)}
    }

def check(report):
    return validate(report, now=NOW, expected_items=5,
                    current_run_id="123", current_sha="a" * 40)

def test_valid_current_run():
    assert check(good())[0] is True

@pytest.mark.parametrize("tier", ["ENTERPRISE_RELEASE", "CONTROLLED_RELEASE", "RELEASE_BLOCKED", "REJECTED", ""])
def test_not_worldwide(tier):
    r=good();r["release_tier"]=tier
    assert check(r)[0] is False

def test_stale_august_report():
    r=good();r["generated_at"]="2026-08-26T09:55:26.403606Z"
    assert check(r)==(False,"P26_CERTIFICATE_STALE_OR_FUTURE")

@pytest.mark.parametrize("index", range(1,14))
def test_any_failed_dimension(index):
    r=good();r["audits"][f"A{index}"]["passed"]=False
    assert check(r)[0] is False

def test_missing_audit():
    r=good();r["audits"].pop("A13")
    assert check(r)[0] is False

def test_blocker_or_warning():
    for k in ("blocker_count", "warning_count"):
        r=good();r[k]=1
        assert check(r)[0] is False

def test_bool_is_not_valid_integer():
    r=good();r["blocker_count"]=False
    assert check(r)[0] is False

def test_count_must_match_source():
    r=good();r["feed_items"]=79
    assert check(r)==(False,"P26_FEED_COUNT_MISMATCH")

def test_future_or_naive_or_invalid_timestamp():
    for stamp in ("2026-11-20T00:00:00Z","2026-11-19T16:20:00","not a date"):
        r=good();r["generated_at"]=stamp
        assert check(r)[0] is False

def test_run_or_source_mismatch():
    for k,v in (("github_run_id","old"),("github_sha","0"*40)):
        r=good();r[k]=v
        assert check(r)[0] is False

def test_ci_identity_required(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS","true")
    monkeypatch.delenv("GITHUB_RUN_ID",raising=False)
    monkeypatch.delenv("GITHUB_SHA",raising=False)
    assert validate(good(),now=NOW,expected_items=5)[0] is False

def test_matching_ci_identity(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS","true")
    monkeypatch.setenv("GITHUB_RUN_ID","123")
    monkeypatch.setenv("GITHUB_SHA","a"*40)
    assert validate(good(),now=NOW,expected_items=5)[0] is True
