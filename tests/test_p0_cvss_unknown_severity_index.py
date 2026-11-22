"""P0: CVSS-backed UNKNOWN input must not escape bounded dossier parity repair.

Pure local fixtures. No R2, Cloudflare, outbound calls, or report publication.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for module_dir in (ROOT, ROOT / "scripts"):
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))

import generate_intel_reports as gir  # noqa: E402


def _scan(monkeypatch, tmp_path, records):
    api = tmp_path / "api"
    api.mkdir(exist_ok=True)
    (api / "feed.json").write_text(json.dumps(records), encoding="utf-8")
    monkeypatch.setattr(gir, "REPO_ROOT", tmp_path)
    return gir._proven_severity_report_index()


def _cve(i, severity="UNKNOWN", cvss=9.1):
    return {
        "id": "intel--" + f"{i:024x}",
        "cve_id": f"CVE-2026-{10000+i}",
        "title": f"CVE-2026-{10000+i} security update",
        "description": "Source-reported vulnerability advisory",
        "severity": severity,
        "cvss_score": cvss,
    }


def test_cvss_rated_unknown_and_missing_severity_get_a_repair_label(monkeypatch, tmp_path):
    unknown = _cve(1, severity="UNKNOWN", cvss=9.1)
    missing = _cve(2, severity=None, cvss=7.5)
    labels = _scan(monkeypatch, tmp_path, [unknown, missing])
    assert labels[unknown["id"]] == "CRITICAL"
    assert labels[missing["id"]] == "HIGH"


def test_unknown_without_cvss_does_not_promote_heuristic_severity(monkeypatch, tmp_path):
    no_cvss = _cve(3, severity="UNKNOWN", cvss=None)
    non_vuln = {
        "id": "intel--" + "f" * 24,
        "title": "Sector news",
        "severity": "UNKNOWN",
        "cvss_score": 9.1,
    }
    labels = _scan(monkeypatch, tmp_path, [no_cvss, non_vuln])
    assert no_cvss["id"] not in labels
    assert non_vuln["id"] not in labels


def test_duplicate_id_with_cvss_is_never_authorized_for_refresh(monkeypatch, tmp_path):
    first = _cve(4, cvss=9.1)
    second = _cve(4, cvss=7.5)
    assert first["id"] not in _scan(monkeypatch, tmp_path, [first, second])
