"""P0: a dossier rendered before CVSS enrichment must be refreshed to the catalog severity.

Incident: sentinel-apex run #239 -- intel--1017421c... was rendered by the
orchestrator before NVD/OSV attached CVSS 9.1. The customer-ready catalog (built
later from the final feed through dossier_integrity.severity_basis) advertised
CRITICAL while the published dossier still showed UNRATED, so
customer_report_fetchback_probe.mjs failed with REPORT_SEVERITY_METADATA_DIVERGENCE
and STAGE 5.9.2 was skipped. --only-missing never revisits an existing file.

The fix extends the bounded --refresh-verified-epss pass (STAGE 5.4.0b) with a
sibling severity-parity repair. These tests pin: the matcher against real renderer
output, parity with the JS probe that gates the release, the feed index, and the
repair loop's safety controls. No network, R2, Cloudflare or payment access;
every fixture is hypothetical.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for directory in (ROOT, ROOT / "scripts"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import generate_intel_reports as gir  # noqa: E402

PREFIX = "https://intel.cyberdudebivash.com"
PROBE = ROOT / "scripts" / "customer_report_fetchback_probe.mjs"


def _stamp(hours_ago: float = 1.0) -> str:
    moment = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _item(n: int = 1, *, cvss=None, hours_ago: float = 1.0, **overrides) -> dict:
    stamp = _stamp(hours_ago)
    base = {
        "id": f"intel--sevrefresh{n:012d}",
        "title": f"CVE-2026-1204{n:02d} - Hypothetical Plugin < 1.0 - Unauthenticated Disclosure",
        "description": "Hypothetical advisory used only by an offline regression test.",
        "severity": "CRITICAL", "risk_score": 1.6, "threat_type": "vulnerability",
        "timestamp": stamp, "processed_at": stamp, "published": stamp,
        "tlp": "TLP:CLEAR", "source": "CVE Feed",
        "source_url": "https://example.org/advisory", "cve_id": f"CVE-2026-1204{n:02d}",
        "iocs": [], "ttps": [],
    }
    if cvss is not None:
        base["cvss_score"] = cvss
    base.update(overrides)
    return base


def _render(item: dict) -> str:
    return gir.render_report(item, PREFIX)


# --------------------------------------------------------------------------- #
# matcher                                                                      #
# --------------------------------------------------------------------------- #
def test_matcher_distinguishes_pre_and_post_enrichment_renders():
    unrated = _render(_item(1))                # rendered before CVSS arrived
    critical = _render(_item(1, cvss=9.1))     # rendered after CVSS arrived
    assert gir._dossier_severity_matches_value(unrated, "UNRATED")
    assert not gir._dossier_severity_matches_value(unrated, "CRITICAL")
    assert gir._dossier_severity_matches_value(critical, "CRITICAL")
    assert not gir._dossier_severity_matches_value(critical, "UNRATED")


@pytest.mark.parametrize("html,expected", [
    (None, "CRITICAL"),
    ("", "CRITICAL"),
    ("<div class='section' id='s1'></div><div class='section' id='s2'></div>", "CRITICAL"),
    ("no sections at all", "CRITICAL"),
    (_render(_item(2, cvss=9.1)), "NOT-A-LABEL"),
    (_render(_item(2, cvss=9.1)), ""),
])
def test_matcher_fails_closed_on_malformed_input(html, expected):
    assert gir._dossier_severity_matches_value(html, expected) is False


def test_matcher_only_trusts_the_s1_severity_row():
    # A Severity chip outside S1 (e.g. in a later section or the page header) must not count.
    stray = ("<div class='section' id='s1'><div class='kv-key'>Other</div></div>"
             "<div class='section' id='s2'>"
             "<div class='kv-key'>Severity</div><div class='kv-val'>"
             "<span class='sev-chip sev-CRITICAL'>CRITICAL</span></div></div>")
    assert gir._dossier_severity_matches_value(stray, "CRITICAL") is False


def test_local_matcher_handles_missing_and_oversize_files(tmp_path):
    p = tmp_path / "intel--x.html"
    assert gir._local_dossier_severity_matches(p, "CRITICAL") is False
    p.write_text(_render(_item(3, cvss=9.1)), encoding="utf-8")
    assert gir._local_dossier_severity_matches(p, "CRITICAL") is True
    p.write_text("x" * (gir._P0_EPSS_REPORT_MAX_BYTES + 1), encoding="utf-8")
    assert gir._local_dossier_severity_matches(p, "CRITICAL") is False


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("cvss,label", [(None, "UNRATED"), (9.1, "CRITICAL"),
                                        (7.8, "HIGH"), (5.9, "MEDIUM"), (2.1, "LOW")])
def test_python_matcher_agrees_with_the_release_gate_probe(tmp_path, cvss, label):
    """The JS probe is the gate; the Python matcher must never disagree with it."""
    html = _render(_item(4, cvss=cvss))
    page = tmp_path / "dossier.html"
    page.write_text(html, encoding="utf-8")
    script = (
        "import {readFileSync} from 'node:fs';"
        f"import {{reportSeverityMatchesCatalog}} from {json.dumps(PROBE.as_uri())};"
        f"const h=readFileSync({json.dumps(str(page))},'utf8');"
        "console.log(JSON.stringify(Object.fromEntries("
        "['CRITICAL','HIGH','MEDIUM','LOW','UNRATED','UNKNOWN']"
        ".map(l=>[l,reportSeverityMatchesCatalog(h,l)]))));"
    )
    out = subprocess.run(["node", "--input-type=module", "-e", script],
                         capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    js = json.loads(out.stdout.strip().splitlines()[-1])
    py = {lab: gir._dossier_severity_matches_value(html, lab) for lab in js}
    assert js == py, (js, py)
    assert py[label] is True and sum(py.values()) == 1


# --------------------------------------------------------------------------- #
# expected-label index                                                         #
# --------------------------------------------------------------------------- #
def _repo(tmp_path, monkeypatch, feed) -> Path:
    root = tmp_path / "repo"
    (root / "api").mkdir(parents=True)
    (root / "api" / "feed.json").write_text(json.dumps(feed), encoding="utf-8")
    monkeypatch.setattr(gir, "REPO_ROOT", root)
    return root


def test_index_reuses_the_catalog_severity_authority(tmp_path, monkeypatch):
    _repo(tmp_path, monkeypatch, [
        _item(1, cvss=9.1),                                     # CVSS band wins over heuristic
        _item(2),                                               # CVE title, no CVSS -> UNRATED
        _item(3, cvss=5.9, severity="HIGH"),                    # heuristic disagrees -> CVSS band
        _item(4, severity=""),                                  # no stated severity -> skipped
        _item(5, severity="UNKNOWN"),                           # skipped
        {"id": "intel--dup", **{k: v for k, v in _item(6, cvss=9.1).items() if k != "id"}},
        {"id": "intel--dup", **{k: v for k, v in _item(6, cvss=2.0).items() if k != "id"}},
        {"title": "no id"},
        "not-a-dict",
    ])
    index = gir._proven_severity_report_index()
    assert index == {
        _item(1)["id"]: "CRITICAL",
        _item(2)["id"]: "UNRATED",
        _item(3)["id"]: "MEDIUM",
    }, index


@pytest.mark.parametrize("raw", ["{}", "[", ""])
def test_index_is_empty_for_unreadable_or_non_list_feed(tmp_path, monkeypatch, raw):
    root = _repo(tmp_path, monkeypatch, [])
    (root / "api" / "feed.json").write_text(raw, encoding="utf-8")
    assert gir._proven_severity_report_index() == {}
    (root / "api" / "feed.json").unlink()
    assert gir._proven_severity_report_index() == {}


# --------------------------------------------------------------------------- #
# repair loop (real generator main(), isolated repo root)                      #
# --------------------------------------------------------------------------- #
class _World:
    """An isolated repo root holding a feed, a manifest and existing dossiers."""

    def __init__(self, tmp_path, monkeypatch):
        self.root = _repo(tmp_path, monkeypatch, [])
        self.manifest = self.root / "data" / "stix" / "feed_manifest.json"
        self.manifest.parent.mkdir(parents=True)
        monkeypatch.setattr(gir, "REPORTS_ROOT", self.root / "reports", raising=False)

    def seed(self, feed_items, manifest_items, stale_render_of):
        """feed_items = final public feed; manifest_items = what the late pass renders from;
        stale_render_of = items whose existing dossier is rendered from this pre-enrichment copy."""
        (self.root / "api" / "feed.json").write_text(json.dumps(feed_items), encoding="utf-8")
        enriched = []
        for entry in manifest_items:
            entry = dict(entry)
            entry["report_url"] = "/" + gir.rel_report_path(entry).relative_to(self.root).as_posix()
            enriched.append(entry)
        self.manifest.write_text(json.dumps({"advisories": enriched}), encoding="utf-8")
        for stale in stale_render_of:
            path = gir.rel_report_path(stale)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_render(stale), encoding="utf-8")

    def run(self, *extra):
        argv = ["--manifest", str(self.manifest), "--public-prefix", PREFIX,
                "--only-missing", "--limit", "0", "--since-hours", "24", *extra]
        return gir.main(argv)

    def dossier(self, item) -> Path:
        return gir.rel_report_path(item)


@pytest.fixture()
def world(tmp_path, monkeypatch):
    return _World(tmp_path, monkeypatch)


def test_pre_enrichment_dossier_is_refreshed_to_catalog_severity(world):
    stale, final = _item(1), _item(1, cvss=9.1)
    world.seed([final], [final], [stale])
    path = world.dossier(final)
    assert gir._local_dossier_severity_matches(path, "UNRATED")      # the production defect

    world.run("--refresh-verified-epss")

    assert gir._local_dossier_severity_matches(path, "CRITICAL")
    assert not gir._local_dossier_severity_matches(path, "UNRATED")


def test_already_matching_dossier_is_never_touched(world):
    final = _item(1, cvss=9.1)
    world.seed([final], [final], [final])
    path = world.dossier(final)
    before, mtime = path.read_bytes(), path.stat().st_mtime_ns

    world.run("--refresh-verified-epss")

    assert path.read_bytes() == before and path.stat().st_mtime_ns == mtime


def test_repair_is_withheld_when_manifest_cannot_reproduce_the_label(world):
    """Control: the late pass renders from the manifest. If the manifest still lacks CVSS the
    re-render would again say UNRATED -> keep the original bytes, never swap in a mismatch."""
    stale, final = _item(1), _item(1, cvss=9.1)
    world.seed([final], [stale], [stale])           # feed enriched, manifest not
    path = world.dossier(final)
    before = path.read_bytes()

    world.run("--refresh-verified-epss")

    assert path.read_bytes() == before
    assert gir._local_dossier_severity_matches(path, "UNRATED")


def test_without_the_opt_in_flag_existing_dossiers_are_never_revisited(world):
    stale, final = _item(1), _item(1, cvss=9.1)
    world.seed([final], [final], [stale])
    path = world.dossier(final)
    before = path.read_bytes()

    world.run()                                      # no --refresh-verified-epss

    assert path.read_bytes() == before


def test_items_outside_the_window_are_left_alone(world):
    stale, final = _item(1, hours_ago=72), _item(1, cvss=9.1, hours_ago=72)
    world.seed([final], [final], [stale])
    path = world.dossier(final)
    before = path.read_bytes()

    world.run("--refresh-verified-epss")

    assert path.read_bytes() == before


def test_per_run_cap_bounds_the_number_of_re_renders(world, monkeypatch):
    cap = 3
    monkeypatch.setattr(gir, "P0_MAX_VERIFIED_SEVERITY_REPAIRS", cap)
    count = cap + 3
    stale = [_item(n) for n in range(1, count + 1)]
    final = [_item(n, cvss=9.1) for n in range(1, count + 1)]
    world.seed(final, final, stale)

    world.run("--refresh-verified-epss")

    fixed = sum(gir._local_dossier_severity_matches(world.dossier(i), "CRITICAL") for i in final)
    assert fixed == cap
    left = sum(gir._local_dossier_severity_matches(world.dossier(i), "UNRATED") for i in final)
    assert left == count - cap


def test_shipped_cap_covers_a_whole_runs_freshly_ingested_cohort(world):
    """Run #240: 10 of 21 customer-ready dossiers (every item first ingested that run) were
    UNRATED against catalog HIGH/MEDIUM. The probe samples the NEWEST reports, so a cap smaller
    than the cohort would leave it red. The shipped cap must repair the whole cohort at once."""
    cohort = 10
    assert gir.P0_MAX_VERIFIED_SEVERITY_REPAIRS >= cohort
    stale = [_item(n) for n in range(1, cohort + 1)]
    final = [_item(n, cvss=score) for n, score in
             zip(range(1, cohort + 1), (6.5, 7.1, 6.5, 7.1, 7.1, 7.1, 8.5, 6.8, 7.1, 7.1))]
    world.seed(final, final, stale)
    assert all(gir._local_dossier_severity_matches(world.dossier(i), "UNRATED") for i in final)

    world.run("--refresh-verified-epss")

    expected = ["MEDIUM", "HIGH", "MEDIUM", "HIGH", "HIGH", "HIGH", "HIGH", "MEDIUM", "HIGH", "HIGH"]
    for item, label in zip(final, expected):
        assert gir._local_dossier_severity_matches(world.dossier(item), label), item["id"]

    # Idempotent: a second pass has nothing left to repair and rewrites nothing.
    snapshot = {i["id"]: world.dossier(i).read_bytes() for i in final}
    world.run("--refresh-verified-epss")
    assert {i["id"]: world.dossier(i).read_bytes() for i in final} == snapshot


def test_item_without_epss_is_still_repaired(world):
    """Regression guard for the restructured block: the production item had epss_score=null,
    which the EPSS-only logic used to `continue` past before any other check."""
    stale, final = _item(1), _item(1, cvss=9.1, epss_score=None)
    world.seed([final], [final], [stale])

    world.run("--refresh-verified-epss")

    assert gir._local_dossier_severity_matches(world.dossier(final), "CRITICAL")


def test_tlp_restricted_item_is_never_refreshed_or_published(world):
    # The renderer itself refuses TLP:AMBER (PublicationDenied), so the pre-existing dossier
    # (e.g. published while the item was still CLEAR) is seeded from a CLEAR render.
    stale_clear = _item(1)
    final = _item(1, cvss=9.1, tlp="TLP:AMBER")
    with pytest.raises(gir._tlp.PublicationDenied):
        _render(final)
    world.seed([final], [final], [stale_clear])
    path = world.dossier(final)
    before = path.read_bytes()
    assert gir._local_dossier_severity_matches(path, "UNRATED")

    world.run("--refresh-verified-epss")

    assert path.read_bytes() == before            # the TLP gate still wins


def test_workflow_invocation_is_unchanged_and_still_scoped_to_the_late_barrier():
    """The fix is deliberately Python-only: no workflow edit, no new flag, no new CI trigger."""
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    assert workflow.count("--refresh-verified-epss") == 1
    assert "--refresh-verified-severity" not in workflow
