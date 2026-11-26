"""scripts/apply_security_headers_rule.py: the upsert never disturbs other rules.

The Cloudflare entrypoint PUT replaces the whole phase's rule list, so the
merge is the safety-critical part: every unrelated rule must survive, in
order, and our rule must be replaced in place (keeping its id) rather than
duplicated. Pure functions only; no network.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("apply_rule", REPO / "scripts/apply_security_headers_rule.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

OURS = mod.load_rule()
OTHER_A = {"id": "a1", "version": "3", "last_updated": "x", "description": "CORS for fonts",
           "expression": "true", "action": "rewrite", "action_parameters": {"headers": {}}, "enabled": True}
OTHER_B = {"id": "b2", "description": "Cache hints", "expression": "true", "action": "rewrite",
           "action_parameters": {"headers": {}}, "enabled": False}


def test_rule_file_is_ours():
    assert OURS["description"].startswith(mod.RULE_KEY)


def test_empty_zone_gets_just_our_rule():
    merged = mod.merge_rules([], OURS)
    assert len(merged) == 1 and merged[0]["expression"] == OURS["expression"]


def test_unrelated_rules_are_preserved_in_order():
    merged = mod.merge_rules([OTHER_A, OTHER_B], OURS)
    assert [r.get("id") for r in merged[:2]] == ["a1", "b2"]
    assert merged[2]["description"] == OURS["description"]
    # Read-only fields are dropped, content kept.
    assert "version" not in merged[0] and "last_updated" not in merged[0]
    assert merged[0]["description"] == "CORS for fonts" and merged[1]["enabled"] is False


def test_our_existing_rule_is_replaced_in_place_and_keeps_its_id():
    old = {"id": "ours1", "description": mod.RULE_KEY + " (old scope)", "expression": "old",
           "action": "rewrite", "action_parameters": {"headers": {}}, "enabled": True}
    merged = mod.merge_rules([OTHER_A, old, OTHER_B], OURS)
    assert [r.get("id") for r in merged] == ["a1", "ours1", "b2"]
    assert merged[1]["expression"] == OURS["expression"]
    assert len(merged) == 3


def test_two_rules_of_ours_is_refused():
    dup = {"id": "d", "description": mod.RULE_KEY, "expression": "x"}
    with pytest.raises(ValueError):
        mod.merge_rules([dup, dict(dup, id="e")], OURS)


def test_verify_expects_exactly_the_rule_headers():
    want = mod.expected_headers(OURS)
    assert want["x-content-type-options"] == "nosniff"
    assert want["content-security-policy"].startswith("frame-ancestors ")
    assert set(mod.WORKER_PATHS) and all(p.startswith(("/api/", "/reports/")) for p in mod.WORKER_PATHS)


def test_usage_error_without_mode():
    assert mod.main(["x"]) == 2


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 429, 500, 503])
def test_static_error_or_redirect_cannot_certify_headers(monkeypatch, status):
    expected = mod.expected_headers(OURS)
    def headers(url):
        if url == mod.HOST + "/upgrade.html":
            return status, expected
        return 200, expected if url.removeprefix(mod.HOST) in mod.STATIC_PAGES else {"x-frame-options": "DENY"}
    monkeypatch.setattr(mod, "_headers", headers)
    assert mod.verify(OURS, attempts=1) is False


def test_successful_static_pages_and_worker_headers_still_pass(monkeypatch):
    expected = mod.expected_headers(OURS)
    monkeypatch.setattr(mod, "_headers", lambda url: (
        200, expected if url.removeprefix(mod.HOST) in mod.STATIC_PAGES else {"x-frame-options": "DENY"}
    ))
    assert mod.verify(OURS, attempts=1) is True


def test_forbidden_entrypoint_is_actionable_and_never_mutates(monkeypatch):
    calls = []
    def api(method, path, token, body=None):
        calls.append(method)
        return 403, {"errors": ["UNTRUSTED_RESPONSE_MUST_NOT_BE_PRINTED"]}
    monkeypatch.setattr(mod, "_api", api)
    with pytest.raises(RuntimeError, match="Zone Transform Rules Read/Write") as error:
        mod._entrypoint("TEST_TOKEN", "a" * 32)
    assert calls == ["GET"]
    assert "UNTRUSTED_RESPONSE_MUST_NOT_BE_PRINTED" not in str(error.value)
