"""P0 release-truth regression: invalid confidence or failed tests cannot certify enterprise."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import p26_intelligence_excellence as p26


def item(confidence):
    return {"confidence": confidence, "enrichment_score": 65}


def test_fractional_confidence_is_reported_as_percent():
    result = p26._a4_quality_audit([item(0.75), item(0.9)])
    assert result["passed"] is True
    assert result["invalid_confidence_count"] == 0
    assert result["average_confidence"] == "82.5%"


@pytest.mark.parametrize("bad", [1.2, -0.1, 75, "not-a-number", float("nan"), float("inf")])
def test_invalid_confidence_is_not_displayed_as_credible_percentage(bad):
    result = p26._a4_quality_audit([item(0.8), item(bad)])
    assert result["passed"] is False
    assert result["invalid_confidence_count"] == 1
    assert result["average_confidence"].startswith("UNVERIFIED")


def _audits():
    return {f"A{i}": {"passed": True, "notes": "ok"} for i in range(1, 13)}


@pytest.mark.parametrize("critical", ["A4", "A10"])
def test_invalid_data_or_failed_regression_blocks_enterprise_and_worldwide(critical):
    checks = _audits()
    checks[critical] = {"passed": False, "notes": "unverified"}
    decision = p26._a13_worldwide_release(checks, [item(0.8)])
    assert decision["release_tier"] not in {"ENTERPRISE_RELEASE", "WORLDWIDE_RELEASE"}
    assert decision["passed"] is False
    assert decision["total_blockers"] == 1


def test_clean_evidence_remains_eligible_for_worldwide_release():
    decision = p26._a13_worldwide_release(_audits(), [item(0.8)])
    assert decision["release_tier"] == "WORLDWIDE_RELEASE"


@pytest.mark.parametrize(
    ("output", "returncode", "expected"),
    [
        ("[PASS] one\n", 0, True),
        ("[PASS] one\n[FAIL] another\n", 0, False),
        ("", 0, False),
        ("[PASS] one\n", 1, False),
    ],
)
def test_regression_aggregation_is_fail_closed(output, returncode, expected):
    response = SimpleNamespace(stdout=output, stderr="", returncode=returncode)
    with patch.object(p26.subprocess, "run", return_value=response):
        result = p26._a10_regression_status()
    assert result["passed"] is expected
