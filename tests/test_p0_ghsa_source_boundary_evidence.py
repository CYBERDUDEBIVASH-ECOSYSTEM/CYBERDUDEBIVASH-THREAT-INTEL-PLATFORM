"""P0: GHSA source provenance is captured, not inferred at publication time."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from agent.p0_r39_evidence import capture_ghsa_api_evidence
import true_intel_ingestor as ingestor
from p0_r35_feed_prewrite_guard import select_publishable


def _stamp(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _advisory(published: str) -> dict:
    return {
        "ghsa_id": "GHSA-1234-5678-abcd",
        "html_url": "https://github.com/advisories/GHSA-1234-5678-abcd",
        "published_at": published,
        "summary": "Real upstream dependency vulnerability",
        "description": "Observed public advisory in the GitHub Advisory REST API",
        "severity": "high",
        "identifiers": [{"type": "CVE", "value": "CVE-2026-12345"}],
    }


def _registry(tmp_path: Path, score=0.8) -> Path:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"trust_scores": {"github.com": {"trust_score": score}}}))
    return path


def test_ghsa_api_evidence_fingerprints_observed_response_and_uses_reviewed_trust(tmp_path):
    published = _stamp(-30)
    observed = _stamp()
    doc = _advisory(published)
    registry = _registry(tmp_path)
    evidence = capture_ghsa_api_evidence(doc, observed, registry)
    assert evidence["source_name"] == "github.com"
    assert evidence["source_domain"] == "github.com"
    assert evidence["source_url"] == doc["html_url"]
    assert evidence["publication_timestamp"] == published
    assert evidence["retrieval_timestamp"] == observed
    assert evidence["content_hash_scope"] == "captured_ghsa_api_record_sha256"
    assert len(evidence["content_hash"]) == 64
    assert evidence["evidence_count"] == 1
    assert evidence["evidence_basis"] == ["captured_github_advisory_api"]
    assert evidence["trust_score"] == pytest.approx(8.0)
    assert capture_ghsa_api_evidence({**doc, "description": "different"}, observed, registry)["content_hash"] != evidence["content_hash"]


@pytest.mark.parametrize("bad_url", [
    "https://github.com.evil.invalid/advisories/GHSA-1234-5678-abcd",
    "https://github.com/advisories/GHSA-1234-5678-aaaa",
    "http://github.com/advisories/GHSA-1234-5678-abcd",
    "https://github.com/advisories/GHSA-1234-5678-abcd?track=true",
])
def test_spoofed_or_noncanonical_advisory_url_cannot_attest_source(tmp_path, bad_url):
    doc = {**_advisory(_stamp(-30)), "html_url": bad_url}
    assert capture_ghsa_api_evidence(doc, _stamp(), _registry(tmp_path)) == {}


@pytest.mark.parametrize("bad_published", [
    "", "2026-11-16T24:00:00Z", "unparseable", None,
])
def test_missing_or_invalid_publication_clock_not_attested(tmp_path, bad_published):
    doc = {**_advisory(_stamp(-30)), "published_at": bad_published,
           "created_at": _stamp(-45)}
    assert capture_ghsa_api_evidence(doc, _stamp(), _registry(tmp_path)) == {}


def test_future_dated_source_is_not_attested(tmp_path):
    doc = _advisory(_stamp(120))
    assert capture_ghsa_api_evidence(doc, _stamp(), _registry(tmp_path)) == {}


def test_unknown_trust_remains_missing_and_downstream_gate_denies(tmp_path):
    pub = _stamp(-30)
    evidence = capture_ghsa_api_evidence(_advisory(pub), _stamp(), tmp_path / "missing-trust.json")
    assert evidence and "trust_score" not in evidence
    raw = ingestor._normalize_item("github_advisory", "Real GHSA advisory",
                                   "https://github.com/advisories/GHSA-1234-5678-abcd", pub)
    raw.update(evidence)
    selected, held = select_publishable([raw])
    assert not selected and held[0]["reason_code"] == "PREWRITE_DENIED"


def test_genuine_ghsa_ingestor_emits_required_evidence_at_network_boundary(monkeypatch):
    class Checkpoint:
        def __init__(self):
            self.updated = None

        def is_new(self, source_key, item_ts):
            assert source_key == "github_advisory"
            return bool(item_ts)

        def update_last_seen(self, source_key, stamp):
            self.updated = (source_key, stamp)

    document = _advisory(_stamp(-20))
    monkeypatch.setattr(ingestor, "_get_json", lambda url, headers=None: [document])
    checkpoint = Checkpoint()
    rows = ingestor.ingest_github_advisories(checkpoint)
    assert len(rows) == 1
    row = rows[0]
    assert row["publication_timestamp"] == document["published_at"]
    retrieval = datetime.fromisoformat(row["retrieval_timestamp"].replace("Z", "+00:00"))
    processed = datetime.fromisoformat(row["processed_at"].replace("Z", "+00:00"))
    assert abs((retrieval - processed).total_seconds()) <= 5
    assert row["source_url"] == document["html_url"]
    assert row["evidence_count"] == 1
    assert checkpoint.updated is not None
    selected, held = select_publishable(rows)
    assert selected == rows, held
