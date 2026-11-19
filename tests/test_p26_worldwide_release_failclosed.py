"""P0: no false worldwide certification from failed P26 audit dimensions."""
from scripts.p26_intelligence_excellence import _a13_worldwide_release


def _audit(**failures):
    audit = {f"A{i}": {"passed": True, "notes": "pass"} for i in range(1, 13)}
    for code, description in failures.items():
        audit[code] = {"passed": False, "notes": description}
    return audit


def test_all_audit_dimensions_and_nonempty_feed_are_needed_for_worldwide():
    result = _a13_worldwide_release(_audit(), [{"id": "fixture"}])
    assert result["release_tier"] == "WORLDWIDE_RELEASE"
    assert result["passed"] is True
    assert result["total_blockers"] == result["total_warnings"] == 0


def test_failed_regression_suite_is_a_release_blocker():
    result = _a13_worldwide_release(_audit(A10="Regression suite failed"), [{"id": "fixture"}])
    assert result["release_tier"] == "RELEASE_BLOCKED"
    assert result["passed"] is False
    assert result["total_blockers"] == 1


def test_failed_commercial_gate_is_a_release_blocker():
    result = _a13_worldwide_release(_audit(A11="Commercial gate failed"), [{"id": "fixture"}])
    assert result["release_tier"] == "RELEASE_BLOCKED"


def test_failed_enterprise_gate_is_a_release_blocker():
    result = _a13_worldwide_release(_audit(A12="Enterprise gate failed"), [{"id": "fixture"}])
    assert result["release_tier"] == "RELEASE_BLOCKED"


def test_failed_security_audit_still_blocks():
    result = _a13_worldwide_release(_audit(A3="Security audit failed"), [{"id": "fixture"}])
    assert result["release_tier"] == "RELEASE_BLOCKED"


def test_one_noncritical_warning_never_claims_worldwide():
    result = _a13_worldwide_release(_audit(A4="Quality warning"), [{"id": "fixture"}])
    assert result["release_tier"] == "ENTERPRISE_RELEASE"
    assert result["passed"] is True
    assert result["total_warnings"] == 1


def test_multiple_noncritical_warnings_remain_controlled_not_worldwide():
    result = _a13_worldwide_release(
        _audit(A4="Quality warning", A5="Evidence warning", A6="Detection warning"),
        [{"id": "fixture"}],
    )
    assert result["release_tier"] == "CONTROLLED_RELEASE"
    assert result["passed"] is False
    assert result["total_warnings"] == 3


def test_empty_feed_never_certified():
    result = _a13_worldwide_release(_audit(), [])
    assert result["release_tier"] == "RELEASE_BLOCKED"
    assert result["passed"] is False
