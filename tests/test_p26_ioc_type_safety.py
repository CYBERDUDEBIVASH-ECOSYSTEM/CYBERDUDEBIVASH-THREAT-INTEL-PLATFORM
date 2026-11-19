"""P0 regression: P26 A7 audit handles heterogeneous IOC payloads without false certification."""
from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "p26_intelligence_excellence.py"
_spec = importlib.util.spec_from_file_location("p26_ioc_type_safety_under_test", _SCRIPT)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_mixed_string_and_dict_indicators_do_not_crash():
    items = [
        {"ioc_count": 2, "iocs": ["evil.example", {"type": "ip", "value": "192.0.2.5", "p20_hardened": True}]},
        {"ioc_count": 1, "iocs": ["198.51.100.1"]},
    ]
    result = _mod._a7_ioc_audit(items)
    assert result["p20_hardened_items"] == 1
    assert result["items_with_iocs"] == 2
    assert result["total_validated_iocs"] == 3


def test_strings_are_never_misrepresented_as_hardened():
    result = _mod._a7_ioc_audit([{"ioc_count": 2, "iocs": ["evil.example", "198.51.100.1"]}])
    assert result["p20_hardened_items"] == 0


def test_dict_p20_hardened_flag_still_counts():
    result = _mod._a7_ioc_audit([{"ioc_count": 2, "iocs": [{"p20_hardened": False}, {"p20_hardened": True}]}])
    assert result["p20_hardened_items"] == 1


def test_empty_indicators_valid_for_cve_only():
    result = _mod._a7_ioc_audit([{"ioc_count": 0, "iocs": []}])
    assert result["p20_hardened_items"] == 0
    assert result["passed"] is True


def test_missing_and_null_indicator_lists_are_safe():
    result = _mod._a7_ioc_audit([{"ioc_count": 0, "iocs": None}, {"ioc_count": 0}])
    assert result["p20_hardened_items"] == 0


def test_each_item_counts_once_even_with_multiple_hardened_indicators():
    result = _mod._a7_ioc_audit([
        {"ioc_count": 2, "iocs": [{"p20_hardened": True}, {"p20_hardened": True}]},
        {"ioc_count": 2, "iocs": ["example.net", {"p20_hardened": True}]},
    ])
    assert result["p20_hardened_items"] == 2

def test_string_false_hardening_label_cannot_claim_validated_provenance():
    result = _mod._a7_ioc_audit([
        {"ioc_count": 3, "iocs": [
            {"p20_hardened": "false"},
            {"p20_hardened": "true"},
            {"p20_hardened": 1},
        ]},
    ])
    assert result["p20_hardened_items"] == 0


def test_only_boolean_true_is_counted_as_hardened():
    result = _mod._a7_ioc_audit([
        {"ioc_count": 2, "iocs": [
            {"p20_hardened": "false"}, {"p20_hardened": True},
        ]},
    ])
    assert result["p20_hardened_items"] == 1
