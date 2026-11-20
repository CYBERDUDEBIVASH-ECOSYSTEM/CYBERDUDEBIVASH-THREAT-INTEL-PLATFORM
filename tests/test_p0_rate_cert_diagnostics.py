"""Offline tests for the production FREE-tier rate certification shell logic.

The tests execute the actual workflow's shell with a fake curl binary.
No production traffic, credentials, or Cloudflare usage is involved.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/commercial-customer-ops-certification.yml"


def _rate_check_shell() -> str:
    source = WORKFLOW.read_text(encoding="utf-8")
    marker = '      - name: "Send 33 unauthenticated requests, expect the 31st+ to 429 with Retry-After"\n        run: |\n'
    assert source.count(marker) == 1
    body = source.split(marker, 1)[1].split("\n  summary:", 1)[0]
    return textwrap.dedent(body)


@pytest.mark.parametrize(
    ("first_rejection", "quota_kind", "expected_success", "expected_text"),
    [
        (31, "minute", True, "FREE tier (limit 30/min) started returning 429"),
        (22, "daily", False, "P0_DAILY_QUOTA_INTERFERENCE"),
        (22, "minute", False, "P0_RATE_BOUNDARY_UNVERIFIED"),
    ],
)
def test_rate_boundary_classifies_cause(
    tmp_path, first_rejection, quota_kind, expected_success, expected_text
):
    # Simulate response codes and gateway-specific headers using a fake curl
    # executable on PATH, while running the real workflow shell logic.
    fake = tmp_path / "curl"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from pathlib import Path\n"
        "p = Path(os.environ['RATE_TEST_COUNTER'])\n"
        "n = int(p.read_text()) + 1 if p.exists() else 1\n"
        "p.write_text(str(n))\n"
        "if n < int(os.environ['RATE_TEST_FIRST_429']):\n"
        "    print('HTTP/2 200')\n"
        "    print()\n"
        "else:\n"
        "    print('HTTP/2 429')\n"
        "    print('Retry-After: 75528' if os.environ['RATE_TEST_KIND'] == 'daily' else 'Retry-After: 60')\n"
        "    print('X-DailyLimit-Limit: 50' if os.environ['RATE_TEST_KIND'] == 'daily' else 'X-RateLimit-Limit: 30')\n"
        "    print()\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "PATH": str(tmp_path) + os.pathsep + env.get("PATH", ""),
        "WORKER_BASE": "https://invalid.test",
        "RATE_TEST_COUNTER": str(tmp_path / "counter"),
        "RATE_TEST_FIRST_429": str(first_rejection),
        "RATE_TEST_KIND": quota_kind,
    })
    result = subprocess.run(
        ["bash", "-e", "-c", _rate_check_shell()],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=25,
        check=False,
    )
    output = result.stdout + result.stderr
    assert (result.returncode == 0) is expected_success, output
    assert expected_text in output, output
