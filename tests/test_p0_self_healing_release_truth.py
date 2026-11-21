"""P0 self-healing outcome: Actions SUCCESS must require a genuinely healthy pass.

Offline only: execute the final gate's shell script with synthetic step outputs.
No API calls, workflow dispatches, Cloudflare calls or production writes.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/self-healing.yml"
GATE_NAME = "P0 — Enforce customer self-healing truth"


def _load_gate():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert workflow["permissions"] == {"contents": "read"}, (
        "Do not silently grant recovery dispatch authority without approval"
    )
    steps = workflow["jobs"]["self-healing-pass"]["steps"]
    assert steps[-1]["name"] == GATE_NAME
    gate = steps[-1]
    assert gate["if"] == "always()", "Gate must run even after a failed earlier step"
    assert "HEALING_STATUS" in gate["env"]
    assert "HEALING_EXIT_CODE" in gate["env"]
    return gate


@pytest.mark.parametrize("status,exit_code", [
    ("degraded", "2"),
    ("failed", "1"),
    ("healthy", "2"),
    ("degraded", "0"),
    ("", ""),
    ("", "0"),
    ("healthy", ""),
])
def test_degraded_or_unverified_healing_cannot_pass(status, exit_code):
    gate = _load_gate()
    env = {**os.environ, "HEALING_STATUS": status, "HEALING_EXIT_CODE": exit_code}
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", gate["run"]],
        env=env, text=True, capture_output=True, timeout=5, check=False,
    )
    assert result.returncode != 0
    assert "P0 Self-Healing Unrecovered" in result.stdout


def test_true_healthy_healing_passes():
    gate = _load_gate()
    env = {**os.environ, "HEALING_STATUS": "healthy", "HEALING_EXIT_CODE": "0"}
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", gate["run"]],
        env=env, text=True, capture_output=True, timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "healthy and exit 0" in result.stdout


def test_recovery_pipeline_preserves_diagnostics_before_final_gate():
    flow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = flow["jobs"]["self-healing-pass"]["steps"]
    names = [step["name"] for step in steps]
    assert names.index("Print healing summary") < names.index(GATE_NAME)
    assert names.index("Alert on degraded status") < names.index(GATE_NAME)
    engine = next(step for step in steps if step["name"] == "Run self-healing engine")
    assert 'EXIT=${PIPESTATUS[0]}' in engine["run"], (
        "Engine exit code must come from Python, not the tee logging process"
    )
