#!/usr/bin/env python3
"""
tests/test_report_continuity_barrier_metrics.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Report Continuity: Final-Barrier Metrics Observability

P0.2 mandate Section 26: the final barrier's repair count must be observable,
not a silent internal detail -- a barrier that quietly "fixes" hundreds of
items every run is masking an upstream defect, not curing it. This locks in
that generate_intel_reports.py --only-missing writes
data/health/report_continuity_barrier.json with repair_candidates/repaired/
failed/r2_uploaded/r2_failed counts and a HEALTHY/DEGRADED/CRITICAL status,
for BOTH call sites that share this one engine (STAGE 5.4.0b's direct YAML
invocation and run_pipeline.py's apply_report_materialization_barrier()).
"""
# P0 #721: fixtures carry an explicit TLP:CLEAR label -- unlabelled items are (correctly) refused publication
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "generate_intel_reports.py"
BARRIER_REPORT = REPO_ROOT / "data" / "health" / "report_continuity_barrier.json"

_BASE_ITEM = {
    "title": "Barrier Metrics Regression Test Advisory",
    "description": "Synthetic advisory for test_report_continuity_barrier_metrics.py.",
    "source": "TEST-FIXTURE",
    "tlp": "TLP:CLEAR", "severity": "LOW",
    "timestamp": "2026-06-01T00:00:00Z",
    "processed_at": "2026-06-01T00:00:00Z",
}


def _run_only_missing(manifest_path: Path, since_hours: int | None = None) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(SCRIPT), "--manifest", str(manifest_path),
            "--public-prefix", "https://intel.cyberdudebivash.com",
            "--only-missing", "--limit", "0"]
    if since_hours is not None:
        argv.extend(["--since-hours", str(since_hours)])
    return subprocess.run(
        argv, cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )


def _cleanup_reports(*item_ids):
    for item_id in item_ids:
        for p in (REPO_ROOT / "reports").rglob(f"{item_id}.html*"):
            p.unlink(missing_ok=True)


def _read_barrier_report_or_skip(test_case):
    if not BARRIER_REPORT.exists():
        test_case.fail(f"expected {BARRIER_REPORT} to be written by --only-missing")
    return json.loads(BARRIER_REPORT.read_text(encoding="utf-8"))


class TestBarrierMetricsObservability(unittest.TestCase):
    def test_clean_manifest_reports_healthy_zero_repairs(self):
        """Steady-state proof: when nothing is dangling, the barrier metrics
        file must show status=HEALTHY and repair_candidates=repaired=0 --
        this is the acceptance signal the P0.2 fix is judged against."""
        item_id = "intel--barriermetrics0c01"
        existing_url = f"/reports/2026/06/{item_id}.html"
        item = dict(_BASE_ITEM, id=item_id, report_url="")

        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": [item]}), encoding="utf-8")
            try:
                # First pass materializes the report for real.
                first = subprocess.run(
                    [sys.executable, str(SCRIPT), "--manifest", str(manifest),
                     "--public-prefix", "https://intel.cyberdudebivash.com", "--limit", "0"],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(first.returncode, 0, first.stderr)

                # Second pass: --only-missing over an already-clean manifest.
                second = _run_only_missing(manifest)
                self.assertEqual(second.returncode, 0, second.stderr)

                report = _read_barrier_report_or_skip(self)
                self.assertEqual(report["status"], "HEALTHY")
                self.assertEqual(report["repair_candidates"], 0)
                self.assertEqual(report["repaired"], 0)
                self.assertEqual(report["failed"], 0)
            finally:
                _cleanup_reports(item_id)

    def test_dangling_item_reports_degraded_with_repaired_count(self):
        """When the barrier actually has to fix something, the metrics file
        must show status=DEGRADED with an accurate repaired count -- this is
        what makes chronic (non-zero, run after run) repair visible instead
        of silently absorbed."""
        item_id = "intel--barriermetrics0c02"
        dangling_url = f"/reports/2026/06/{item_id}.html"
        item = dict(_BASE_ITEM, id=item_id, report_url=dangling_url)

        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": [item]}), encoding="utf-8")
            try:
                result = _run_only_missing(manifest)
                self.assertEqual(result.returncode, 0, result.stderr)

                report = _read_barrier_report_or_skip(self)
                self.assertEqual(report["status"], "DEGRADED")
                self.assertEqual(report["repair_candidates"], 1)
                self.assertEqual(report["repaired"], 1)
                self.assertEqual(report["failed"], 0)
            finally:
                _cleanup_reports(item_id)

    def test_barrier_report_has_all_mandated_fields(self):
        item_id = "intel--barriermetrics0c03"
        item = dict(_BASE_ITEM, id=item_id, report_url="")

        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": [item]}), encoding="utf-8")
            try:
                result = _run_only_missing(manifest)
                self.assertEqual(result.returncode, 0, result.stderr)

                report = _read_barrier_report_or_skip(self)
                for field in ("generated_at", "manifest", "repair_candidates", "repaired",
                              "failed", "r2_uploaded", "r2_failed", "status"):
                    self.assertIn(field, report, f"missing mandated field: {field}")
                self.assertIn(report["status"], ("HEALTHY", "DEGRADED", "CRITICAL"))
            finally:
                _cleanup_reports(item_id)

    def test_window_excluded_history_does_not_become_false_critical_failure(self):
        """One eligible repair and one historical skip must be DEGRADED, not CRITICAL."""
        fresh_id = "intel--barriermetrics0c04"
        old_id = "intel--barriermetrics0c05"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fresh = dict(_BASE_ITEM, id=fresh_id, timestamp=now, processed_at=now, report_url="")
        historical = dict(_BASE_ITEM, id=old_id, report_url="")
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": [historical, fresh]}), encoding="utf-8")
            try:
                result = _run_only_missing(manifest, since_hours=24)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = _read_barrier_report_or_skip(self)
                self.assertEqual(report["repair_candidates"], 1)
                self.assertEqual(report["repaired"], 1)
                self.assertEqual(report["failed"], 0)
                self.assertEqual(report["status"], "DEGRADED")
                self.assertFalse(any((REPO_ROOT / "reports").rglob(f"{old_id}.html")))
            finally:
                _cleanup_reports(fresh_id, old_id)

    def test_all_historical_window_exclusions_are_healthy_noop(self):
        """A 24h quiet window must not manufacture failed repairs or re-render history."""
        old_id = "intel--barriermetrics0c06"
        historical = dict(_BASE_ITEM, id=old_id, report_url="")
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "feed_manifest.json"
            manifest.write_text(json.dumps({"advisories": [historical]}), encoding="utf-8")
            try:
                result = _run_only_missing(manifest, since_hours=24)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = _read_barrier_report_or_skip(self)
                self.assertEqual(report["repair_candidates"], 0)
                self.assertEqual(report["repaired"], 0)
                self.assertEqual(report["failed"], 0)
                self.assertEqual(report["status"], "HEALTHY")
                self.assertFalse(any((REPO_ROOT / "reports").rglob(f"{old_id}.html")))
            finally:
                _cleanup_reports(old_id)


if __name__ == "__main__":
    unittest.main()
