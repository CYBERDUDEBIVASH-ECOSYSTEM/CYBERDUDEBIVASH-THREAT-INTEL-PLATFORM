"""P0: execute production certification's real provisioning shell offline.

No network or production credential is accessed. Mock curl proves that every
issued key is revoked by the EXIT trap when a later tier fails provisioning.
"""
import os
from pathlib import Path
import subprocess

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/commercial-customer-ops-certification.yml"


@pytest.mark.parametrize(
    ("failed_tier", "expected_exit", "expected_revoked"),
    [
        ("PRO", 1, []),
        ("ENTERPRISE", 1, ["fixture-PRO"]),
        ("MSSP", 1, ["fixture-PRO", "fixture-ENTERPRISE"]),
        ("", 0, ["fixture-PRO", "fixture-ENTERPRISE", "fixture-MSSP"]),
    ],
)
def test_partial_provisioning_reclaims_every_issued_key(
    tmp_path, failed_tier, expected_exit, expected_revoked
):
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    run = workflow["jobs"]["authenticated-customer-ops-tests"]["steps"][0]["run"]

    # Keep the exact checked-in setup, provisioning and EXIT trap. Do not
    # execute subsequent customer probes: this test covers cleanup only.
    marker = "# NOTE: handleSLAReport"
    assert run.count(marker) == 1
    shell = run[: run.index(marker)] + "\nexit 0\n"

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    mock_curl = bin_dir / "curl"
    mock_curl.write_text(
        """#!/bin/bash
set -e
if [[ "$*" == *"-X POST"* ]]; then
  tier=""
  for arg in "$@"; do
    case "$arg" in
      *'\"tier\":\"PRO\"'*) tier="PRO" ;;
      *'\"tier\":\"ENTERPRISE\"'*) tier="ENTERPRISE" ;;
      *'\"tier\":\"MSSP\"'*) tier="MSSP" ;;
    esac
  done
  [[ -n "$tier" ]] || exit 90
  if [[ "$tier" == "$FAIL_TIER" ]]; then
    printf '{"error":"synthetic_provision_failure"}\\n'
  else
    printf '{"key":"fixture-%s"}\\n' "$tier"
  fi
  exit 0
fi
if [[ "$*" == *"-X DELETE"* ]]; then
  for arg in "$@"; do
    case "$arg" in
      "$WORKER_BASE"/api/admin/keys/*)
        printf '%s\\n' "${arg##*/}" >> "$DELETE_LOG"
        exit 0
        ;;
    esac
  done
  exit 91
fi
exit 92
""",
        encoding="utf-8",
    )
    mock_curl.chmod(0o755)

    log = tmp_path / "reclaimed_keys"
    env = dict(
        os.environ,
        PATH=f"{bin_dir}:{os.environ['PATH']}",
        WORKER_BASE="https://example.invalid",
        ADMIN_SECRET="fixture-admin-secret",
        FAIL_TIER=failed_tier,
        DELETE_LOG=str(log),
    )
    completed = subprocess.run(
        ["/bin/bash", "-c", shell],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
        check=False,
    )

    assert completed.returncode == expected_exit, completed.stderr
    reclaimed = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    assert reclaimed == expected_revoked
    output = completed.stdout + completed.stderr
    assert "fixture-admin-secret" not in output
    for key in ("fixture-PRO", "fixture-ENTERPRISE", "fixture-MSSP"):
        assert key not in output
