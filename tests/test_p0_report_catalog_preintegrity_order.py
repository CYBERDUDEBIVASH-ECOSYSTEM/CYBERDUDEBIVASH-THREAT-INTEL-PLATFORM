"""P0 regression: local reports catalog must reflect completed publication state.

Production customer outage root: publisher uploaded reports while 3.5.1
verified an earlier 3.3.7 catalog. This is a static, offline workflow DAG
proof. No GitHub, Cloudflare, AWS, R2 or local report data is mutated.
"""
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-apex.yml"
BUILDER = ROOT / "scripts" / "build_reports_index.py"
REFRESH = "STAGE 3.5a.1 - Pre-Integrity Local Reports Catalog Refresh (P0)"
PUBLISH = "STAGE 3.5a - Bounded 24h Report Publisher (P0 R2 Cost Fix)"
VERIFY = "STAGE 3.5.1 - R2 Reports Index Integrity Gate (v1.0 P0 Permanent Fix)"
LATE = "STAGE 5.4.0d - Refresh Customer Reports Catalog"


def stages():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = document["jobs"]
    job = next(value for value in jobs.values()
               if any(step.get("name") == PUBLISH for step in value.get("steps", [])))
    return job["steps"]


def test_refresh_runs_after_bounded_publisher_and_before_head_integrity():
    steps = stages()
    names = [s.get("name") for s in steps]
    assert names.count(REFRESH) == 1
    assert names.count(PUBLISH) == names.count(VERIFY) == 1
    assert names.index(PUBLISH) < names.index(REFRESH) < names.index(VERIFY)
    assert names.index(VERIFY) < names.index(LATE)
    # The first integrity step must remain the real mandatory verifier.
    integrity = steps[names.index(VERIFY)]
    assert integrity["run"].strip() == "python3 scripts/r2_reports_integrity.py"
    assert not integrity.get("continue-on-error", False)
    assert not integrity.get("if"), "Do not make R2 integrity optional"


def test_local_refresh_is_hard_fail_read_only_and_uses_canonical_writer():
    steps = stages()
    refresh = next(step for step in steps if step.get("name") == REFRESH)
    assert refresh.get("if") == "env.PIPELINE_LOCKED != 'true'"
    assert not refresh.get("continue-on-error", False)
    assert 0 < refresh["timeout-minutes"] <= 5
    assert refresh["run"].splitlines()[0].strip() == "set -euo pipefail"
    assert "python3 scripts/build_reports_index.py" in refresh["run"]
    assert "python3 scripts/report_chronology_integrity.py --catalog api/reports/index.json" in refresh["run"]
    assert not refresh.get("env"), "No Cloudflare/R2 credentials allowed in this local step"
    forbidden = ["aws ", "wrangler ", "r2_upload", "r2_resync", "curl ",
                 "|| true", "upload", "--reports-index-only", "gh workflow"]
    for token in forbidden:
        assert token not in refresh["run"], f"Local preflight must never mutate R2: {token}"


def test_indexer_uses_existing_bounded_publisher_state_not_unverified_urls():
    source = BUILDER.read_text(encoding="utf-8")
    assert 'PUBLISH_STATE = REPO_ROOT / "data" / "cache" / "r2_report_publish_state.json"' in source
    assert "def _published_report_paths()" in source
    assert 'entry.get("html_sha256")' in source
    assert '"html_key"' in source
    # Do not invent new index logic or replace the canonical builder.
    assert "api/reports/index.json written:" in source


def test_late_catalog_refresh_and_r2_write_gate_are_preserved():
    steps = stages()
    late = next(step for step in steps if step.get("name") == LATE)
    script = late["run"]
    assert "python3 scripts/build_reports_index.py" in script
    assert "python3 scripts/r2_reports_integrity.py" in script
    assert "python3 scripts/report_chronology_integrity.py --catalog api/reports/index.json" in script
    assert "python3 scripts/r2_upload.py --reports-index-only" in script
    assert script.index("python3 scripts/r2_reports_integrity.py") < script.index("python3 scripts/r2_upload.py --reports-index-only")
