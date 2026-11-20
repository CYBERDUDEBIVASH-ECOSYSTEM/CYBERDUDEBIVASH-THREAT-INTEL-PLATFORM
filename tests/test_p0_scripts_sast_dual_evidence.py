"""Offline regression: both script SAST scanners run before fail-closed verdict."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci_scripts_sast_scope as sast


@pytest.mark.parametrize(
    ("bandit_findings", "semgrep_findings", "expected_error"),
    [
        (1, 0, "SCRIPT_SAST_BANDIT_HIGH_FINDINGS"),
        (0, 1, "SCRIPT_SAST_SEMGREP_FINDINGS"),
        (1, 1, "SCRIPT_SAST_BANDIT_HIGH_FINDINGS"),
    ],
)
def test_both_scanners_run_even_when_bandit_finds_issues(
    bandit_findings, semgrep_findings, expected_error
):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "sample.py").write_text("value = 1\n", encoding="utf-8")
        scope = root / "scope.json"
        scope.write_text(
            json.dumps({"targets": ["scripts/sample.py"]}), encoding="utf-8"
        )
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args[0])
            if args[0] == "bandit":
                (root / ".scripts-sast-bandit.json").write_text(
                    json.dumps({
                        "results": [{
                            "filename": str(scripts / "sample.py"),
                            "test_id": "B310",
                            "line_number": 1,
                        }] * bandit_findings,
                    }), encoding="utf-8"
                )
            elif args[0] == "semgrep":
                (root / ".scripts-sast-semgrep.json").write_text(
                    json.dumps({
                        "results": [{
                            "path": str(scripts / "sample.py"),
                            "check_id": "test.rule",
                            "start": {"line": 1},
                        }] * semgrep_findings,
                    }), encoding="utf-8"
                )
            else:
                raise AssertionError(f"Unexpected scanner: {args[0]}")
            return mock.Mock(returncode=0)

        with mock.patch.object(sast.subprocess, "run", side_effect=fake_run):
            with pytest.raises(RuntimeError, match=expected_error):
                sast.scan(root, scope)

        assert calls == ["bandit", "semgrep"]


def test_both_clean_scanners_produce_pass():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "scripts").mkdir()
        (root / "scripts" / "sample.py").write_text("pass\n", encoding="utf-8")
        scope = root / "scope.json"
        scope.write_text(json.dumps({"targets": ["scripts/sample.py"]}))
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args[0])
            file = (root / ".scripts-sast-bandit.json"
                    if args[0] == "bandit"
                    else root / ".scripts-sast-semgrep.json")
            file.write_text('{"results": []}', encoding="utf-8")
            return mock.Mock(returncode=0)

        with mock.patch.object(sast.subprocess, "run", side_effect=fake_run):
            assert sast.scan(root, scope) == 0
        assert calls == ["bandit", "semgrep"]
