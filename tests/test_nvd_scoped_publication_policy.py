"""Focused no-network regression tests for the scoped NVD publication rule."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import tlp_policy as policy

APPROVED = {"legacy_white_treated_as_clear": False, "first_party_public_sources": [
    {"source": "nist nvd", "hosts": ["nvd.nist.gov"], "projection": "nvd_metadata_v1"}
]}
CVE = "CVE-2026-00001"
DATE = "2026-11-26T10:30:00+00:00"


def projection():
    return {
        "id": "intel--0123456789abcdef", "cve_id": CVE, "cve_ids": [CVE], "cves": [CVE],
        "title": CVE + " — NVD vulnerability record",
        "description": f"NVD lists {CVE}. Review the linked vulnerability record and vendor guidance for affected products and remediation.",
        "source": "NIST NVD", "source_name": "NIST NVD", "feed_source": "nvd_cve",
        "source_url": "https://nvd.nist.gov/vuln/detail/" + CVE,
        "published_at": DATE, "publication_timestamp": DATE, "timestamp": DATE,
        "retrieval_timestamp": DATE, "source_modified_at": DATE,
        "content_hash": "a" * 64, "content_hash_scope": "canonical_nvd_record_sha256",
        "trust_score": 9.0, "evidence_count": 1, "corroboration_count": 0,
        "cvss_score": 9.8, "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_severity": "CRITICAL", "metric_validation": "CVSS31_ARITHMETIC_VERIFIED",
        "risk_score": None, "severity": None, "epss_score": None, "kev_status": "unverified",
        "vuln_status": "Deferred", "threat_type": "CVE", "iocs": [], "ioc_count": 0,
        "is_published": True,
    }


class ScopedNvdPolicyTests(unittest.TestCase):
    def allowed(self, row, pol=APPROVED):
        return policy.publication_decision(row, pol)["allowed"]

    def test_exact_projection(self):
        self.assertTrue(self.allowed(projection()))

    def test_default_denies(self):
        self.assertFalse(self.allowed(projection(), {"first_party_public_sources": []}))

    def test_review_only_denied(self):
        for flags in ({"is_published": False}, {"publication_state": "REVIEW_ONLY"},
                      {"production_release_authorized": False}):
            self.assertFalse(self.allowed(dict(projection(), **flags)))

    def test_host_path_and_scheme(self):
        for url in ("https://foo.nvd.nist.gov/vuln/detail/"+CVE,
                    "http://nvd.nist.gov/vuln/detail/"+CVE,
                    "https://nvd.nist.gov.evil.invalid/vuln/detail/"+CVE,
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-00002",
                    "https://nvd.nist.gov/vuln/detail/"+CVE+"?extra=1",
                    "https://user@nvd.nist.gov/vuln/detail/"+CVE):
            self.assertFalse(self.allowed(dict(projection(), source_url=url)))

    def test_source_identity(self):
        for fields in ({"source": "NVD"}, {"feed_source": "rss"}, {"source_name": "other"}):
            self.assertFalse(self.allowed(dict(projection(), **fields)))

    def test_raw_and_arbitrary_content_denied(self):
        for fields in ({"source_record": {}}, {"references": []}, {"title": "arbitrary"},
                       {"description": "arbitrary"}, {"risk_score": 9.9}, {"epss_score": 0.9},
                       {"iocs": ["unknown"]}, {"content_hash": "fake"}, {"vuln_status": "Rejected"}):
            self.assertFalse(self.allowed(dict(projection(), **fields)))

    def test_restricted_labels_never_relabeled(self):
        for label in ("TLP:GREEN", "TLP:AMBER", "TLP:RED", "TLP:AMBER+STRICT", "TLP:PURPLE"):
            self.assertFalse(self.allowed(dict(projection(), tlp=label)))
        self.assertFalse(self.allowed(dict(projection(), evidence_chain=[{"tlp": "TLP:RED"}])))

    def test_missing_metric_not_fabricated(self):
        row = dict(projection(), cvss_score=None, cvss_version=None, cvss_vector=None,
                   cvss_severity=None, metric_validation="METRIC_REVIEW_REQUIRED")
        self.assertTrue(self.allowed(row))

    def test_invalid_metric(self):
        for score in (True, -1, 11, 10**1000, float("nan"), float("inf")):
            self.assertFalse(self.allowed(dict(projection(), cvss_score=score)))
        self.assertFalse(self.allowed(dict(projection(), cvss_vector="CVSS:3.1/AV:N/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H")))

    def test_materialize_copy(self):
        row = projection()
        original = copy.deepcopy(row)
        out = policy.materialize_nvd_public_classification(row, APPROVED)
        self.assertEqual(row, original)
        self.assertEqual(out["tlp"], "TLP:CLEAR")
        self.assertEqual(out["tlp_assignment"], "policy_first_party_public_source")
        self.assertTrue(self.allowed(out))

    def test_materialize_denial(self):
        with self.assertRaises(ValueError):
            policy.materialize_nvd_public_classification(dict(projection(), tlp="TLP:RED"), APPROVED)

    def test_existing_explicit_clear_unchanged(self):
        row = {"id": "old", "title": "old", "tlp": "TLP:CLEAR"}
        self.assertEqual(policy.materialize_nvd_public_classification(row, APPROVED), row)

    def test_no_broad_nvd_fallback(self):
        broad = {"first_party_public_sources": [{"source": "nist nvd", "hosts": ["nvd.nist.gov"]}]}
        self.assertFalse(self.allowed(projection(), broad))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"policy.json"
            path.write_text(json.dumps(broad), encoding="utf-8")
            self.assertEqual(policy.load_policy(path)["first_party_public_sources"], [])

    def test_existing_other_approved_source(self):
        pol = {"first_party_public_sources": [{"source": "other", "hosts": ["example.org"]}]}
        self.assertTrue(self.allowed({"source": "other", "source_url": "https://example.org/a"}, pol))

    def test_config_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"policy.json"
            path.write_text(json.dumps(APPROVED), encoding="utf-8")
            self.assertEqual(policy.load_policy(path), APPROVED)
            self.assertTrue(self.allowed(projection(), policy.load_policy(path)))

    def test_timezone_and_chronology(self):
        self.assertFalse(self.allowed(dict(projection(), retrieval_timestamp="2026-11-26T10:30:00")))
        self.assertFalse(self.allowed(dict(projection(), retrieval_timestamp="2026-11-26T09:00:00+00:00")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
