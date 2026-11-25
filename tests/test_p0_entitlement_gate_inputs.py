"""Offline negative controls for required entitlement certification inputs."""
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/entitlement_resource_drift_gate.py"
WORKER = Path("workers/intel-gateway")
RESOURCE = 'ENTITLEMENT_ENFORCEMENT_RESOURCES = "cve_detail_full"'
CONFIG = f"[vars]\n{RESOURCE}\n[env.production.vars]\n{RESOURCE}\n"


@pytest.mark.parametrize("case", [
    "valid", "explicit_empty", "missing_config", "missing_engine",
    "missing_index", "missing_enterprise", "missing_default_section",
    "missing_production_section", "missing_declaration", "commented_declaration",
    "duplicate_declaration", "unknown_resource", "missing_live_callsite",
])
def test_entitlement_drift_gate_required_inputs(tmp_path, case):
    files = {
        WORKER / "wrangler.toml": CONFIG,
        WORKER / "src/revenue-enforcement.js":
            'export function enforceTierGate() { switch (resource) { case "cve_detail_full": break; } }\n',
        WORKER / "src/index.js":
            'resolveEntitlement(ctx, env, "cve_detail_full", fallback);\n',
        WORKER / "src/enterprise-endpoints.js": "// No additional calls required.\n",
    }
    config = WORKER / "wrangler.toml"
    missing = {
        "missing_config": config,
        "missing_engine": WORKER / "src/revenue-enforcement.js",
        "missing_index": WORKER / "src/index.js",
        "missing_enterprise": WORKER / "src/enterprise-endpoints.js",
    }
    if case in missing:
        del files[missing[case]]
    elif case == "explicit_empty":
        files[config] = CONFIG.replace('"cve_detail_full"', '""')
    elif case == "missing_default_section":
        files[config] = f"[env.production.vars]\n{RESOURCE}\n"
    elif case == "missing_production_section":
        files[config] = f"[vars]\n{RESOURCE}\n"
    elif case == "missing_declaration":
        files[config] = f"[vars]\n{RESOURCE}\n[env.production.vars]\n"
    elif case == "commented_declaration":
        files[config] = f"[vars]\n{RESOURCE}\n[env.production.vars]\n# {RESOURCE}\n"
    elif case == "duplicate_declaration":
        files[config] = CONFIG + RESOURCE + "\n"
    elif case == "unknown_resource":
        files[config] = CONFIG.replace("cve_detail_full", "unknown_resource")
    elif case == "missing_live_callsite":
        files[WORKER / "src/index.js"] = '// resolveEntitlement(ctx, env, "cve_detail_full", fallback);\n'
    files[Path("scripts/entitlement_resource_drift_gate.py")] = GATE.read_text(encoding="utf-8")
    for rel, data in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(tmp_path / "scripts/entitlement_resource_drift_gate.py")],
        capture_output=True, text=True, timeout=10, check=False,
    )
    expected = 0 if case in {"valid", "explicit_empty"} else 1
    assert result.returncode == expected, result.stdout + result.stderr
    if expected:
        assert "FAIL" in result.stdout
        assert "PASS --" not in result.stdout
