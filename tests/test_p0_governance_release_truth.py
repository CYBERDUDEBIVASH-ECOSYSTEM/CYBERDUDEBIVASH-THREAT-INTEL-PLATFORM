"""P0: a passing policy checker is not an authorized customer production release."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deployment_gate.py"


def test_access_governance_success_is_explicitly_not_deployment_approval():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "ACCESS GOVERNANCE PASSED" in source
    assert "Production release NOT authorized by this gate" in source
    assert "DEPLOYMENT APPROVED" not in source


def test_existing_strict_fail_closed_verdict_remains():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "if GATE_FAIL_COUNT == 0:" in source
    assert "DEPLOYMENT BLOCKED" in source
    assert "if args.strict:" in source
    assert "sys.exit(1)" in source
    assert "GATE_FAIL_COUNT + GATE_PASS_COUNT" in source or "GATE_PASS_COUNT + GATE_FAIL_COUNT" in source
