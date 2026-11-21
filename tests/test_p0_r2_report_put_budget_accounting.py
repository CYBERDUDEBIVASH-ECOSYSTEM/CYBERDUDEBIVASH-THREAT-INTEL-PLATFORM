"""P0 R2 publisher Class A accounting and pre-mutation budget proof.

Run without cloud credentials or network: temporary local HTML/PDF fixtures only.
Prevents recurrence of run 44925059324: 121 successful PUTs, plan.PUT 0.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import r2_report_publisher as pub
from scripts.r2_cost_guard import R2Budgets, R2BudgetExceeded, enforce_budget


@pytest.fixture
def plan_fixture(tmp_path, monkeypatch):
    reports = tmp_path / "reports" / "2026" / "11"
    reports.mkdir(parents=True)
    pdfs = tmp_path / "reports" / "pdf"
    pdfs.mkdir(parents=True)
    html = reports / "intel--unit.html"
    pdf = pdfs / "intel--unit.pdf"
    html.write_bytes(b"<html>report</html>")
    pdf.write_bytes(b"%PDF-1.4\nfixture")
    monkeypatch.setattr(pub, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(pub, "PDF_DIR", pdfs)
    monkeypatch.setattr(pub, "rel_report_path", lambda item: html)
    ts = datetime.now(timezone.utc) - timedelta(hours=1)
    item = {"id": "intel--unit", "timestamp": ts.isoformat()}
    candidate = {"item": item, "id": item["id"], "canonical_ts": ts}
    return [candidate], html, pdf, ts


def _plan(plan_fixture, state=None):
    candidates, html, pdf, now = plan_fixture
    return pub.build_plan(
        candidates, state or {"items": {}}, 24, now,
        max_deletes=0,
    )


def test_html_and_pdf_puts_are_both_accounted_before_mutation(plan_fixture):
    plan, put_ops, delete_ops = _plan(plan_fixture)
    assert len(put_ops) == 2
    assert {op["kind"] for op in put_ops} == {"html", "pdf"}
    assert plan.put == len(put_ops) == 2
    assert plan.bytes_uploaded == sum(op["size"] for op in put_ops)
    assert plan.estimated_class_a() == 2
    assert plan.new == 1
    assert plan.list_calls == 0
    assert delete_ops == []


@pytest.mark.parametrize("ceiling", [0, 1])
def test_budget_rejects_underreported_two_put_plan(plan_fixture, ceiling):
    plan, put_ops, _ = _plan(plan_fixture)
    assert len(put_ops) == 2
    budgets = R2Budgets(max_report_writes_per_run=ceiling)
    with pytest.raises(R2BudgetExceeded, match="MAX_REPORT_UPLOADS_PER_RUN"):
        enforce_budget(plan, budgets, is_report_plan=True)


def test_budget_accepts_exact_two_put_limit(plan_fixture):
    plan, put_ops, _ = _plan(plan_fixture)
    assert len(put_ops) == 2
    enforce_budget(plan, R2Budgets(max_report_writes_per_run=2),
                   is_report_plan=True)


def test_unchanged_html_pdf_have_zero_put_and_zero_class_a(plan_fixture):
    _, html, pdf, _ = plan_fixture
    state = {"items": {"intel--unit": {
        "html_sha256": pub._sha256_file(html),
        "pdf_sha256": pub._sha256_file(pdf),
    }}}
    plan, puts, _ = _plan(plan_fixture, state)
    assert puts == []
    assert plan.put == 0
    assert plan.estimated_class_a() == 0
    assert plan.bytes_uploaded == 0
    assert plan.unchanged == 1


@pytest.mark.parametrize("kind", ["html", "pdf"])
def test_single_changed_artifact_counts_exactly_one_put(plan_fixture, kind):
    _, html, pdf, _ = plan_fixture
    state = {"items": {"intel--unit": {
        "html_sha256": pub._sha256_file(html),
        "pdf_sha256": pub._sha256_file(pdf),
    }}}
    path = html if kind == "html" else pdf
    path.write_bytes(path.read_bytes() + b" updated")
    plan, puts, _ = _plan(plan_fixture, state)
    assert len(puts) == 1 and puts[0]["kind"] == kind
    assert plan.put == 1
    assert plan.bytes_uploaded == path.stat().st_size


def test_planned_operations_have_no_network_or_remote_mutation(plan_fixture, monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("Budget planning must not touch R2")
    monkeypatch.setattr(pub, "s3_cp", prohibited)
    monkeypatch.setattr(pub, "s3_delete", prohibited)
    plan, puts, _ = _plan(plan_fixture)
    assert plan.put == len(puts) == 2
