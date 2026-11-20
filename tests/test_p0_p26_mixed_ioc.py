"""P0 regression: mixed legacy IOC representations must not crash P26."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import p26_intelligence_excellence as p26


def _row(iocs, count=0):
    return {"id": "test", "ioc_count": count, "ioc_fp_removed": 0, "iocs": iocs}


def test_legacy_string_iocs_not_counted_as_p20_hardened():
    result = p26._a7_ioc_audit([_row(["1.2.3.4", "example.invalid"], 2)])
    assert result["items_with_iocs"] == 1
    assert result["total_validated_iocs"] == 2
    assert result["p20_hardened_items"] == 0


def test_mixed_types_only_explicit_true_counts_as_hardened():
    result = p26._a7_ioc_audit([
        _row(["example.invalid", None, {"p20_hardened": True}], 1),
        _row([{"p20_hardened": "false"}, {"p20_hardened": False}], 0),
        _row({"unexpected": "mapping"}, 0),
    ])
    assert result["p20_hardened_items"] == 1


def test_no_iocs_is_valid_for_cve_only_advisory():
    result = p26._a7_ioc_audit([_row([], 0), _row(None, 0)])
    assert result["p20_hardened_items"] == 0
    assert result["passed"] is True
