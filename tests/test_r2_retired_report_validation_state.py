"""P0: retired R2 reports must not retain an active delivery certification.

Isolated local-manifest fixtures only. No network, PUT, DELETE or paid calls.
"""
import json

import pytest

from scripts import r2_report_publisher as publisher


def _retire(tmp_path, monkeypatch, entries, *, html_ids=(), pdf_ids=()):
    manifest = tmp_path / "fixture.json"
    manifest.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(publisher, "REPORT_URL_MANIFESTS", [manifest])
    assert publisher.clear_report_urls(html_ids=set(html_ids), pdf_ids=set(pdf_ids)) == []
    return json.loads(manifest.read_text(encoding="utf-8"))


@pytest.mark.parametrize("status", ["ok", "enriched", "valid"])
def test_html_retirement_revokes_customer_ready_status(tmp_path, monkeypatch, status):
    entry = {"id":"intel--a","validation_status":status,
             "report_url":"/reports/2026/11/a.html",
             "internal_report_url":"/reports/2026/11/a.html",
             "tlp":"TLP:CLEAR"}
    retired = _retire(tmp_path, monkeypatch, [entry], html_ids={"intel--a"})[0]
    assert retired["validation_status"] == "report_retired"
    assert retired["report_url"] == ""
    assert retired["internal_report_url"] == ""
    assert retired["tlp"] == "TLP:CLEAR"
    assert retired["validation_status"] not in ("ok","enriched")


def test_pdf_only_retirement_preserves_active_html_report(tmp_path, monkeypatch):
    row={"id":"intel--a","validation_status":"ok",
         "report_url":"/reports/2026/11/a.html","pdf_url":"/reports/pdf/a.pdf"}
    changed = _retire(tmp_path, monkeypatch, [row], pdf_ids={"intel--a"})[0]
    assert changed["validation_status"] == "ok"
    assert changed["report_url"] == "/reports/2026/11/a.html"
    assert changed["pdf_url"] == ""


def test_unaffected_id_and_tlp_quarantine_not_modified(tmp_path, monkeypatch):
    entries=[
      {"id":"intel--a","validation_status":"quarantined_tlp","tlp":"TLP:AMBER","report_url":"/reports/2026/11/a.html"},
      {"id":"intel--b","validation_status":"ok","report_url":"/reports/2026/11/b.html"}
    ]
    got=_retire(tmp_path,monkeypatch,entries,html_ids={"intel--a"})
    assert got[0]["validation_status"] == "quarantined_tlp"
    assert got[0]["tlp"] == "TLP:AMBER"
    assert got[0]["report_url"] == ""
    assert got[1] == entries[1]


def test_nonexistent_id_does_not_rewrite_original_bytes(tmp_path, monkeypatch):
    path=tmp_path/"file.json"
    payload='[{"id":"intel--a","validation_status":"ok","report_url":"/reports/a.html"}]'
    path.write_text(payload)
    monkeypatch.setattr(publisher,"REPORT_URL_MANIFESTS",[path])
    assert publisher.clear_report_urls(html_ids={"intel--absent"},pdf_ids=set()) == []
    assert path.read_text() == payload


def test_no_report_url_but_preexisting_ok_status_transitions_when_retired(tmp_path, monkeypatch):
    row={"id":"intel--a","validation_status":"ok","report_url":""}
    changed=_retire(tmp_path, monkeypatch, [row], html_ids={"intel--a"})[0]
    assert changed["validation_status"] == "report_retired"
    assert changed["report_url"] == ""
