"""P0: every customer catalog artifact is a mandatory release output.

Offline unit tests only: no GitHub actions dispatch, R2, Cloudflare or
customer API writes. A failed atomic write must never report a green build.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_reports_index as catalog  # noqa: E402


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    feed = tmp_path / "api" / "feed.json"
    feed.parent.mkdir(parents=True)
    feed.write_text("[]", encoding="utf-8")
    output = tmp_path / "api" / "reports"
    monkeypatch.setattr(catalog, "REPORTS_ROOT", reports)
    monkeypatch.setattr(catalog, "API_FEED", feed)
    monkeypatch.setattr(catalog, "API_REPORTS", output)
    monkeypatch.setattr(catalog, "PUBLISH_STATE", tmp_path / "missing-state.json")
    return output


@pytest.mark.parametrize("failed_name", ["index.json", "latest.json", "stats.json"])
def test_single_failed_output_blocks_release(monkeypatch, isolated, failed_name):
    real_write = catalog._atomic_write
    attempted = []

    def fail_exactly_one(path, payload, indent=2):
        attempted.append(path.name)
        if path.name == failed_name:
            return False
        return real_write(path, payload, indent=indent)

    monkeypatch.setattr(catalog, "_atomic_write", fail_exactly_one)
    assert catalog.main() == 2, f"{failed_name} failure must block publication"
    assert attempted == ["index.json", "latest.json", "stats.json"]
    assert not (isolated / failed_name).exists(), "Do not present a failed write as an artifact"
    for valid in set(attempted) - {failed_name}:
        assert isinstance(json.loads((isolated / valid).read_text(encoding="utf-8")), dict)


def test_complete_three_artifact_build_remains_successful(isolated):
    assert catalog.main() == 0
    for name in ("index.json", "latest.json", "stats.json"):
        payload = json.loads((isolated / name).read_text(encoding="utf-8"))
        assert payload["reports_listed"] == 0 if name != "stats.json" else payload["total_reports"] == 0
