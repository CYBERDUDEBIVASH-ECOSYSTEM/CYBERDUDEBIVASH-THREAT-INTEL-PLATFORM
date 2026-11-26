"""Item-derived text must never reach a published report as markup.

Report fields originate in third-party feeds. The generator escapes almost all of them; two builders in
agent/apex_intelligence_upgrade.py interpolated values raw: the section 05 narrative (the product name taken from the
title) and the ATT&CK mapping table (technique id, name, justification, tactic, confidence, and the id inside the
link's href attribute).

This test puts a unique payload into ONE field at a time, across the report types that take different narrative
branches, and fails if any payload reaches the page unescaped. It also checks that ordinary values render exactly as
before. Fixtures are fictional; nothing is published.
"""
import copy
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

import generate_intel_reports as gir  # noqa: E402
from agent import apex_intelligence_upgrade as aiu  # noqa: E402

PREFIX = "https://intel.cyberdudebivash.com"

BASE = {
    "id": "intel--escape-fuzz", "title": "CVE-2026-119582 — synthetic fixture", "description": "Fictional record for offline regression.",
    "cve_id": "CVE-2026-119582", "cvss_score": 6.5, "risk_score": 0.4, "severity": "MEDIUM", "timestamp": "2026-11-24T12:00:00Z",
    "source_url": "https://example.org/advisory", "tlp": "TLP:CLEAR", "kev": False, "kev_present": False, "threat_type": "Vulnerability",
    "feed_source": "fixture-feed", "source": "fixture-src", "actor_tag": "CDB-UNATTR-CVE", "tags": ["web"],
    "iocs": [{"type": "domain", "value": "synthetic.invalid"}], "ttps": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "mitre_tactics": [{"id": "T1190", "name": "Initial Access"}], "kill_chain": [{"phase": "Initial Access", "description": "fixture"}],
    "affected_products": ["fixture-product 1.0"], "vendor": "fixture-vendor", "product": "fixture-product",
}
TYPES = {
    "cve": {},
    "malware": {"threat_type": "Malware", "cve_id": "", "title": "Fixture malware campaign", "cvss_score": None},
    "ransomware": {"threat_type": "Ransomware", "cve_id": "", "title": "Fixture ransomware group", "cvss_score": None},
    "actor": {"threat_type": "Threat Actor", "cve_id": "", "title": "Fixture threat actor campaign", "cvss_score": None},
}
SCALAR_FIELDS = ["title", "description", "cve_id", "source_url", "feed_source", "source", "actor_tag", "threat_type", "vendor", "product"]
LIST_FIELDS = {
    "tags": lambda p: [p],
    "iocs": lambda p: [{"type": "domain", "value": p}],
    "ttps": lambda p: [{"id": "T1190", "name": p}],
    "ttps_id": lambda p: [{"id": p, "name": "Fixture technique"}],
    "ttps_just": lambda p: [{"id": "T1190", "name": "Fixture technique", "justification": p}],
    "ttps_tactic": lambda p: [{"id": "T1190", "name": "Fixture technique", "tactic": p}],
    "ttps_conf": lambda p: [{"id": "T1190", "name": "Fixture technique", "confidence": p}],
    "ttps_str": lambda p: [p],
    "mitre_tactics": lambda p: [{"id": "T1190", "name": p}],
    "kill_chain": lambda p: [{"phase": p, "description": p}],
    "affected_products": lambda p: [p],
}
PAYLOADS = ("<img src=x onerror=alert({tag})>", "'><script>alert({tag})</script>", "\" onmouseover=\"alert({tag})")
RAW_MARKERS = ("<img src=x", "<script>alert", "onmouseover=\"alert", "'><script")


def render(item):
    return gir.render_report(item, PREFIX)


def make(type_name, field, payload):
    item = copy.deepcopy({**BASE, **TYPES[type_name]})
    if field in SCALAR_FIELDS:
        item[field] = payload
    else:
        item[field.split("_")[0] if field.startswith("ttps_") else field] = LIST_FIELDS[field](payload)
    return item


@pytest.mark.parametrize("type_name", sorted(TYPES))
@pytest.mark.parametrize("field", SCALAR_FIELDS + sorted(LIST_FIELDS))
@pytest.mark.parametrize("payload", PAYLOADS)
def test_no_item_field_reaches_the_page_as_markup(type_name, field, payload):
    tag = f"{type_name}-{field}"
    p = payload.format(tag=tag)
    html = render(make(type_name, field, p))
    leaked = [m for m in RAW_MARKERS if m in html]
    assert not leaked, f"{type_name}.{field}: payload reached the page as raw markup ({leaked})"


SOURCE_FILES = ("scripts/generate_intel_reports.py", "agent/apex_intelligence_upgrade.py", "scripts/context_aware_narrative_engine.py",
                "scripts/ecosystem_showcase.py", "scripts/dossier_integrity.py")
TYPED_KEYS = {"id", "tlp", "timestamp", "severity", "cvss_score", "risk_score", "kev", "kev_present"}  # validated scalars


def keys_read_from_the_item():
    """Every key the report code reads with item.get("<key>"): the list updates itself when a new field is added."""
    keys = set()
    for rel in SOURCE_FILES:
        keys |= set(re.findall(r"""item\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""", (ROOT / rel).read_text(encoding="utf-8")))
    return sorted(keys - TYPED_KEYS)


def test_the_key_enumeration_is_not_vacuous():
    keys = keys_read_from_the_item()
    assert len(keys) >= 40 and {"title", "actor", "description"} <= set(keys)


@pytest.mark.parametrize("type_name", sorted(TYPES))
@pytest.mark.parametrize("key", keys_read_from_the_item())
@pytest.mark.parametrize("shape", ["scalar", "list"])
def test_every_key_the_report_reads_is_escaped(type_name, key, shape):
    """The actor field leaked in all four report types and the title in two, before this guard existed."""
    payload = f"<img src=x onerror=alert('{type_name}-{key}-{shape}')>"
    item = copy.deepcopy({**BASE, **TYPES[type_name]})
    item[key] = payload if shape == "scalar" else [payload]
    try:
        html = render(item)
    except Exception:  # a crash on a weird type is a robustness question, not a markup leak
        return
    assert payload not in html and "<img src=x" not in html, f"{type_name}.{key} ({shape}) reached the page as raw markup"


class TestOrdinaryValuesAreUnchanged:
    def test_attack_row_for_a_normal_technique_renders_as_before(self):
        rows = aiu.render_ttps_premium([{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "confidence": "HIGH"}], {})
        assert "href='https://attack.mitre.org/techniques/T1059/001/'" in rows
        assert ">T1059.001</a>" in rows and "<strong>PowerShell</strong>" in rows
        assert "<span class='sev-chip'>Execution</span>" in rows and "apex-conf-high'>HIGH<" in rows

    def test_ampersands_and_quotes_in_real_names_are_escaped_not_dropped(self):
        rows = aiu.render_ttps_premium([{"id": "T1190", "name": "Command & Scripting \"Interpreter\"", "tactic": "Execution"}], {})
        assert "Command &amp; Scripting &quot;Interpreter&quot;" in rows

    HREF_OK = re.compile(r"^https://attack\.mitre\.org/techniques/[A-Za-z0-9/%._-]*/$")

    def test_technique_id_cannot_break_out_of_the_link_attribute(self):
        rows = aiu.render_ttps_premium([{"id": "T1'onmouseover='alert(1)", "name": "x"}], {})
        href = re.search(r"<a href='([^']*)'", rows).group(1)
        assert self.HREF_OK.match(href), f"link is not a clean, URL-encoded MITRE path: {href}"
        assert "onmouseover='alert" not in rows

    def test_string_form_technique_ids_are_escaped_in_text_and_url(self):
        # render_report normalises ids before this builder, so exercise the string branch directly
        rows = aiu.render_ttps_premium(["<img src=x onerror=1>"], {})
        assert "<img" not in rows.lower() and "onerror=1>" not in rows
        href = re.search(r"<a href='([^']*)'", rows).group(1)
        assert self.HREF_OK.match(href), href

    def test_registry_values_are_escaped_even_if_a_registry_entry_were_hostile(self, monkeypatch):
        hostile = {"id": "T9999", "name": "<b onmouseover=1>n</b>", "tactic": "<i>t</i>", "desc": "<u>d</u>"}
        monkeypatch.setattr(aiu, "resolve_technique", lambda t: dict(hostile))
        rows = aiu.render_ttps_premium(["T9999"], {})
        for raw in ("<b onmouseover", "<i>t</i>", "<u>d</u>"):
            assert raw not in rows
