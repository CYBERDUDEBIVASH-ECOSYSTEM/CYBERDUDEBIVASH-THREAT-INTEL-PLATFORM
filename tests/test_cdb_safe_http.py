"""scripts/cdb_safe_http.py: scheme-validated urlopen (Bandit B310 remediation) and the guard that keeps it in use."""
import ast
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import cdb_safe_http  # noqa: E402
from cdb_safe_http import safe_urlopen  # noqa: E402


class TestSchemeValidation:
    @pytest.mark.parametrize("url", ["https://example.com/feed.json", "http://example.com/x", "HTTPS://EXAMPLE.COM/", "Http://example.com"])
    def test_http_and_https_are_delegated_unchanged(self, url):
        with mock.patch("urllib.request.urlopen", return_value="RESPONSE") as m:
            assert safe_urlopen(url, timeout=7) == "RESPONSE"
        m.assert_called_once_with(url, timeout=7)

    def test_request_objects_are_validated_by_their_full_url(self):
        req = urllib.request.Request("https://api.example.com/v1", headers={"A": "b"}, method="POST")
        with mock.patch("urllib.request.urlopen", return_value="OK") as m:
            assert safe_urlopen(req, b"data", timeout=3) == "OK"
        m.assert_called_once_with(req, b"data", timeout=3)

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd", "ftp://example.com/x", "data:text/plain;base64,QQ==", "javascript:alert(1)",
        "gopher://example.com", "jar:https://example.com!/", "//example.com/protocol-relative", "/etc/passwd", "", "example.com/no-scheme",
    ])
    def test_every_other_scheme_is_refused_before_any_network_or_file_access(self, url):
        with mock.patch("urllib.request.urlopen") as m:
            with pytest.raises(urllib.error.URLError):
                safe_urlopen(url)
        m.assert_not_called()

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "data:text/plain;base64,QQ=="])
    def test_request_objects_with_a_disallowed_scheme_are_refused_too(self, url):
        with mock.patch("urllib.request.urlopen") as m:
            with pytest.raises(urllib.error.URLError):
                safe_urlopen(urllib.request.Request(url))
        m.assert_not_called()

    def test_a_refused_scheme_is_an_oserror_so_existing_network_error_handlers_catch_it(self):
        assert issubclass(urllib.error.URLError, OSError)
        with pytest.raises(OSError):
            safe_urlopen("file:///etc/hosts")

    def test_the_allow_list_can_be_narrowed_per_call(self):
        with mock.patch("urllib.request.urlopen") as m:
            with pytest.raises(urllib.error.URLError):
                safe_urlopen("http://example.com", allowed_schemes=frozenset({"https"}))
            m.assert_not_called()
            safe_urlopen("https://example.com", allowed_schemes=frozenset({"https"}))
            m.assert_called_once()

    def test_the_default_allow_list_is_exactly_http_and_https(self):
        assert cdb_safe_http.ALLOWED_SCHEMES == frozenset({"http", "https"})

    def test_existing_tests_that_patch_urllib_request_urlopen_keep_working(self):
        # the helper looks urlopen up at call time, so a patch on urllib.request.urlopen is honoured
        sentinel = object()
        with mock.patch("urllib.request.urlopen", return_value=sentinel):
            assert safe_urlopen("https://example.com") is sentinel


def _direct_urlopen_calls(path: Path):
    """Line numbers of calls to <anything>.urlopen(...) or urlopen(...) in a script (AST, so comments and strings never match)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            if name == "urlopen" and "nosec B310" not in lines[node.lineno - 1]:
                hits.append(node.lineno)
    return hits


@pytest.mark.parametrize("path", sorted(SCRIPTS.glob("*.py")), ids=lambda p: p.name)
def test_scripts_never_call_urlopen_directly_use_cdb_safe_http(path):
    """Regression guard for Bandit B310: any new network fetch in scripts/ must go through safe_urlopen.

    A direct call is only accepted with an explicit, justified `# nosec B310` on the same line (existing, reviewed sites).
    """
    if path.name == "cdb_safe_http.py":
        pytest.skip("the helper itself is the single audited call")
    assert _direct_urlopen_calls(path) == [], (
        f"{path.name}: use `from cdb_safe_http import safe_urlopen` instead of calling urlopen directly")


def test_every_script_that_uses_safe_urlopen_imports_it_with_the_documented_fallback():
    users = [p for p in SCRIPTS.glob("*.py") if p.name != "cdb_safe_http.py" and re.search(r"\bsafe_urlopen\(", p.read_text(encoding="utf-8"))]
    assert len(users) >= 40, "expected the remediated scripts to use the helper"
    for p in users:
        text = p.read_text(encoding="utf-8")
        assert "from cdb_safe_http import safe_urlopen" in text and "from scripts.cdb_safe_http import safe_urlopen" in text, p.name
