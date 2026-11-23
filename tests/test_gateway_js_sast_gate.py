"""Offline negative controls for fail-closed Gateway JavaScript SAST."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import ci_gateway_js_sast as gate

HEAD = "a" * 40
BASE = "b" * 40


def fixture(tmp_path, monkeypatch):
    source = tmp_path / "workers" / "intel-gateway" / "src"
    source.mkdir(parents=True)
    (source / "handler.js").write_text("export const answer = 42;\n", encoding="utf-8")
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps({
        "event": "pull_request", "base_sha": BASE, "head_sha": HEAD,
        "target_count": 1, "targets": ["workers/intel-gateway/src/handler.js"],
    }), encoding="utf-8")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return source, manifest


@pytest.mark.parametrize("name", [
    "../outside.js",
    "scripts/a.js",
    "/absolute/a.js",
    "workers/intel-gateway/src/../../outside.js",
    "workers/intel-gateway/src/handler.js\\outside",
])
def test_reject_untrusted_source_paths(tmp_path, name):
    (tmp_path / "workers" / "intel-gateway" / "src").mkdir(parents=True)
    with pytest.raises(ValueError):
        gate.source_targets(tmp_path, [name])


def test_source_paths_only_include_exact_js_files(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    (source / "new.txt").write_text("ignored")
    selected = gate.source_targets(tmp_path, [
        "workers/intel-gateway/src/new.txt",
        "workers/intel-gateway/src/deleted.js",
        "workers/intel-gateway/src/handler.js",
        "workers/intel-gateway/src/handler.js",
    ])
    assert selected == ["workers/intel-gateway/src/handler.js"]


def test_symlink_escape_is_rejected(tmp_path, monkeypatch):
    source, _ = fixture(tmp_path, monkeypatch)
    other = tmp_path / "secret.js"
    other.write_text("export const notOwned = true")
    try:
        (source / "alias.js").symlink_to(other)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="SYMLINK"):
        gate.source_targets(tmp_path, ["workers/intel-gateway/src/alias.js"])


def test_exact_head_checkout_required(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=BASE + "\n"))
    with pytest.raises(ValueError, match="HEAD_MISMATCH"):
        gate.verify_checkout(tmp_path, HEAD)


def test_diff_selection_is_bounded_and_does_not_execute_changed_code(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args[:3])
        if args[:2] == ["git", "diff"]:
            return SimpleNamespace(stdout=b"workers/intel-gateway/src/handler.js\0")
        if args[:2] == ["git", "fetch"]:
            return SimpleNamespace(stdout=b"")
        raise AssertionError(args)

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate.select_targets(tmp_path, "pull_request", BASE, HEAD) == [
        "workers/intel-gateway/src/handler.js"
    ]
    assert [x[1] for x in calls] == ["fetch", "diff"]


def test_missing_pr_diff_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="MISSING_DIFF_AUTHORITY"):
        gate.select_targets(tmp_path, "pull_request", "", HEAD)


def test_report_rejects_missing_coverage_and_errors():
    target = ["workers/intel-gateway/src/handler.js"]
    doc = {"version": "1.148.0", "results": [], "errors": [],
           "paths": {"scanned": target}}
    assert gate.validate_report(doc, target) == []
    with pytest.raises(ValueError, match="INCOMPLETE_SCAN"):
        gate.validate_report({**doc, "paths": {"scanned": []}}, target)
    with pytest.raises(RuntimeError, match="REPORTED_ERRORS"):
        gate.validate_report({**doc, "errors": [{"type": "ParseError"}]}, target)
    with pytest.raises(ValueError, match="REPORT_INVALID"):
        gate.validate_report({"results": [], "errors": []}, target)


@pytest.mark.parametrize(("case", "returncode", "expect"), [
    ("clean", 0, None),
    ("finding", 1, "JS_SAST_SCANNER_FAILED_OR_FINDINGS"),
    ("finding_but_zero_exit", 0, "JS_SAST_SECURITY_FINDINGS"),
    ("scanner_error", 2, "JS_SAST_SCANNER_FAILED_OR_FINDINGS"),
    ("missing_report", 1, "JS_SAST_REPORT_MISSING"),
    ("missing_coverage", 0, "JS_SAST_INCOMPLETE_SCAN"),
    ("malformed_report", 0, "JSONDecodeError"),
])
def test_scan_fails_closed_on_findings_errors_and_missing_evidence(
    tmp_path, monkeypatch, case, returncode, expect
):
    source, manifest = fixture(tmp_path, monkeypatch)
    target = "workers/intel-gateway/src/handler.js"

    def fake_run(args, **kwargs):
        if args[:3] == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(stdout=HEAD + "\n", returncode=0)
        assert args[0] == "semgrep"
        assert "--error" in args and "--severity" in args
        assert target in args
        report = tmp_path / gate.REPORT
        if case == "missing_report":
            return SimpleNamespace(returncode=returncode)
        if case == "malformed_report":
            report.write_text("{invalid}", encoding="utf-8")
        else:
            report.write_text(json.dumps({
                "version": "1.148.0",
                "results": ([{"path": target, "check_id": "security.synthetic",
                             "start": {"line": 1}}]
                            if case.startswith("finding") else []),
                "errors": [],
                "paths": {"scanned": [] if case == "missing_coverage" else [target]},
            }), encoding="utf-8")
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    if expect:
        with pytest.raises((RuntimeError, ValueError, json.JSONDecodeError), match=expect):
            gate.scan(tmp_path, manifest)
    else:
        assert gate.scan(tmp_path, manifest) == 0


def test_empty_verified_scope_skips_external_scanner(tmp_path, monkeypatch):
    _, manifest = fixture(tmp_path, monkeypatch)
    manifest.write_text(json.dumps({
        "event": "pull_request", "base_sha": BASE, "head_sha": HEAD,
        "target_count": 0, "targets": [],
    }), encoding="utf-8")

    def fake_run(args, **kwargs):
        assert args[:3] == ["git", "rev-parse", "HEAD"]
        return SimpleNamespace(stdout=HEAD + "\n")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate.scan(tmp_path, manifest) == 0
