"""Customer report delivery before the first R2 publish. All storage is local."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import generate_intel_reports as renderer
import prepare_current_report_files as prepare
from report_chronology_integrity import BASE
import report_existence_validator as validator
import r2_report_publisher as publisher

NOW = datetime.now(timezone.utc)


def advisory(number, *, age=2, label="TLP:CLEAR", absolute=True):
    ident = f"intel--{number:024x}"
    date = NOW - timedelta(hours=age)
    path = f"/reports/{date:%Y/%m}/{ident}.html"
    return {"id": ident, "report_url": (BASE if absolute else "") + path,
            "title": "Verified package update", "description": "A defensive update.",
            "timestamp": date.isoformat(), "processed_at": date.isoformat(), "tlp": label}


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    for mod in (renderer, publisher):
        monkeypatch.setattr(mod, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(renderer, "REPORTS_ROOT", tmp_path / "reports")
    monkeypatch.setattr(renderer, "MANIFEST_PATH", tmp_path / "source.json")
    monkeypatch.setattr(publisher, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(publisher, "FEED_JSON", tmp_path / "feed.json")
    return tmp_path


def test_current_absolute_and_relative_links_reach_the_bounded_upload_plan(workspace):
    records = [advisory(1), advisory(2, absolute=False), advisory(3, age=26),
               advisory(4, label="TLP:AMBER"), advisory(5), advisory(6)]
    records[4]["report_url"] = "https://vendor.example/advisory/5"
    durable = records[5]
    publisher.STATE_PATH.write_text(json.dumps({"items": {durable["id"]: {
        "html_sha256": "a" * 64, "html_key": durable["report_url"].removeprefix(BASE + "/")
    }}}))
    source = json.dumps(records).encode()
    publisher.FEED_JSON.write_bytes(source)
    assert prepare.main() == 0
    expected = {records[0]["id"], records[1]["id"]}
    files = list((workspace / "reports").rglob("*.html"))
    assert {file.stem for file in files} == expected
    assert all(file.stat().st_size > 1024 for file in files)
    assert publisher.FEED_JSON.read_bytes() == source
    allowed, _ = publisher.apply_tlp_gate(records, {})
    candidates = publisher.build_publish_candidates(allowed, 24, NOW)
    _, puts, _ = publisher.build_plan(candidates, publisher.load_publish_state(), 24, NOW)
    assert {op["id"] for op in puts} == expected
    original = {file: file.stat().st_mtime_ns for file in files}
    assert prepare.main() == 0
    assert original == {file: file.stat().st_mtime_ns for file in files}


@pytest.mark.parametrize("damage", ["wrong-id", "wrong-month", "no-output", "budget"])
def test_unfulfilled_owned_link_blocks_preparation(workspace, monkeypatch, damage):
    row = advisory(1)
    if damage == "wrong-id":
        row["report_url"] = advisory(2)["report_url"]
    elif damage == "wrong-month":
        row["report_url"] = row["report_url"].replace(NOW.strftime("/%Y/"), "/2001/")
    elif damage == "no-output":
        monkeypatch.setattr(renderer, "main", lambda argv: 0)
    else:
        monkeypatch.setenv("MAX_REPORT_UPLOADS_PER_RUN", "1")
    rows = [row, advisory(3)] if damage == "budget" else [row]
    publisher.FEED_JSON.write_text(json.dumps(rows))
    assert prepare.main() != 0
    assert not list((workspace / "reports").rglob("*.html"))


def test_validator_checks_absolute_owned_report_but_ignores_external_source(workspace):
    row, external = advisory(1), advisory(2)
    external["report_url"] = "https://vendor.example/advisory/2"
    publisher.FEED_JSON.write_text(json.dumps([row, external]))
    checked, missing, _, _ = validator.validate(
        publisher.FEED_JSON, workspace, now=NOW, window_hours=24, published_ids=set())
    assert (checked, missing) == (1, 1)


def test_incremental_renderer_repairs_an_absolute_dossier_and_preserves_external_links(workspace):
    owned, external = advisory(1), advisory(2)
    external["report_url"] = "https://vendor.example/reports/2026/11/" + external["id"] + ".html"
    manifest = workspace / "source.json"
    manifest.write_text(json.dumps({"advisories": [owned, external]}))
    assert renderer.main(["--manifest", str(manifest), "--only-missing", "--since-hours", "24"]) == 0
    path = owned["report_url"].removeprefix(BASE)
    assert (workspace / path.lstrip("/")).is_file()
    saved = json.loads(manifest.read_text())["advisories"]
    assert saved[0]["report_url"] == path
    assert saved[1]["report_url"] == external["report_url"]
    assert not renderer.rel_report_path(external).exists()


def test_publication_workflow_requires_current_reports_and_validated_manifests():
    steps = yaml.safe_load((ROOT / ".github/workflows/sentinel-apex.yml").read_text())["jobs"]["generate-and-sync"]["steps"]
    prep = next(i for i, s in enumerate(steps) if "scripts/prepare_current_report_files.py" in s.get("run", ""))
    upload = next(i for i, s in enumerate(steps) if s.get("id") == "p0-report-publish-initial")
    assert prep < upload
    assert not steps[prep].get("continue-on-error")
    refresh = next(s for s in steps if "STAGE 3.5a.1 -" in s.get("name", ""))
    assert refresh["run"].index("steps.p0-report-publish-initial.outcome") < refresh["run"].index("scripts/build_reports_index.py")
    final = next(s for s in steps if s.get("env", {}).get("CDB_FINAL_PAID_R2_SYNC") == "1")
    for step_id in ("p0-report-publish-initial", "r2-reports-index-integrity",
                    "final-manifest-parity", "final-manifest-validation"):
        assert f"steps.{step_id}.outcome == 'success'" in final["if"]
        assert any(s.get("id") == step_id for s in steps[:steps.index(final)])
