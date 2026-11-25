"""P0 zero-trust tenant bootstrap and false-green webhook dispatch regression."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run_isolated(tmp_path, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_missing_tenant_registry_import_does_not_create_active_credential(tmp_path):
    process = _run_isolated(
        tmp_path, "-c",
        "from agent.license_validator import LICENSE_VALIDATOR; "
        "assert LICENSE_VALIDATOR.is_valid('CDB-ENT-EXTERNALLY-KNOWN') is False",
    )
    assert process.returncode == 0, process.stderr
    assert not (tmp_path / "data" / "sovereign" / "tenants.json").exists()


def test_unimplemented_webhook_dispatch_fails_not_false_green(tmp_path):
    process = _run_isolated(
        tmp_path, "-m", "agent.subscription_manager", "--webhook-event",
    )
    assert process.returncode == 78
    assert "P0_FULFILLMENT_HOLD" in process.stderr
    assert "no customer credential issued" in process.stderr
    assert not (tmp_path / "data" / "sovereign" / "tenants.json").exists()
    assert not process.stdout.strip()


def test_unsupported_direct_provisioning_cli_refuses_cleanly(tmp_path):
    process = _run_isolated(tmp_path, "-m", "agent.subscription_manager")
    assert process.returncode == 64
    assert "P0_FULFILLMENT_HOLD" in process.stderr
    assert not (tmp_path / "data" / "sovereign" / "tenants.json").exists()


def test_provider_fulfillment_logs_do_not_expose_keys_or_license_values():
    source = (ROOT / "agent" / "fulfillment" / "gumroad_handler.py").read_text(
        encoding="utf-8"
    )
    assert "Provisioned {new_api_key}" not in source
    assert "Invalid Gumroad key {license_key}" not in source
    assert "Fulfillment API Error: {str(e)}" not in source


def test_governance_refusal_probe_is_behavioral_and_isolated(monkeypatch):
    from scripts import jwt_governance as audit
    status, detail = audit.check_legacy_webhook_refusal(audit.SUBSCRIPTION_MGR)
    assert status == "PASS", detail

    def unexpected_success(*args, **kwargs):
        assert "CDB_JWT_SECRET" not in kwargs["env"]
        assert "RAZORPAY_KEY_SECRET" not in kwargs["env"]
        assert kwargs["timeout"] == 15
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(audit.subprocess, "run", unexpected_success)
    assert audit.check_legacy_webhook_refusal(audit.SUBSCRIPTION_MGR)[0] == "FAIL"


def test_governance_refusal_probe_rejects_side_effects(monkeypatch):
    from scripts import jwt_governance as audit

    def unexpected_write(*args, **kwargs):
        (Path(kwargs["cwd"]) / "unexpected.json").write_text("{}")
        return subprocess.CompletedProcess(args, 78, "", "P0_FULFILLMENT_HOLD: no customer credential issued")

    monkeypatch.setattr(audit.subprocess, "run", unexpected_write)
    assert audit.check_legacy_webhook_refusal(audit.SUBSCRIPTION_MGR)[0] == "FAIL"
