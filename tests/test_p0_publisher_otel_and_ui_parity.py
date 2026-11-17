"""P0 offline contract: compatible OpenTelemetry family and truthful UI registry.

This test never installs, accesses network/R2, or modifies customer state.
Actual resolver, SAST, and end-to-end publisher gates must pass separately.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from capability_registry_gate import evaluate

SERVICES = ("exec-risk", "ai-engine", "intel-core", "agentshield",
            "api-gateway", "surfacewatch", "intel-exchange",
            "soc-automation", "billing-engine")
PAGES = ("command-floor.html", "instagram-live-studio.html")


class P0PublisherRecoveryContract(unittest.TestCase):
    def test_otel_family_pins_are_aligned(self):
        for path in [ROOT / "requirements.txt"] + [
            ROOT / "platform" / "services" / x / "requirements.txt" for x in SERVICES
        ]:
            with self.subTest(manifest=str(path)):
                s = path.read_text(encoding="utf-8")
                self.assertIn("opentelemetry-sdk==1.45.2", s)
                self.assertIn("opentelemetry-exporter-otlp-proto-grpc==1.45.2", s)
                self.assertIn("opentelemetry-instrumentation-fastapi==0.66b2", s)
                self.assertNotIn("opentelemetry-instrumentation-fastapi==0.66b1", s)
        root = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("opentelemetry-instrumentation-requests==0.66b2", root)

    def test_new_public_surfaces_registered(self):
        registry = json.loads((ROOT / "data/quality/frontend_capability_registry.json").read_text(encoding="utf-8"))
        coverage = json.loads((ROOT / "data/quality/frontend_api_coverage_report.json").read_text(encoding="utf-8"))
        entries = {e["id"]: e for e in registry["entries"]}
        dynamic = {x["file"] for x in coverage["dynamic_pages"]}
        for page in PAGES:
            with self.subTest(page=page):
                self.assertTrue((ROOT / page).is_file())
                self.assertIn(page, entries)
                self.assertEqual(entries[page]["category"], "CUSTOMER_UI")
                self.assertEqual(entries[page]["status"], "live")
                self.assertIn(page, dynamic)
        self.assertEqual(len(registry["entries"]), registry["total_pages"])
        self.assertEqual(len(entries), len(registry["entries"]))
        self.assertEqual(coverage["total_pages"], coverage["dynamic_count"] + coverage["static_count"])
        verdict = evaluate(registry, coverage, [p.name for p in ROOT.glob("*.html")])
        self.assertTrue(verdict["passed"], verdict["findings"])


if __name__ == "__main__":
    unittest.main()
