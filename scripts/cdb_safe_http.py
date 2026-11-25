"""Scheme-validated wrapper around urllib's urlopen (remediates Bandit B310).

Why this exists: ``urllib.request.urlopen`` also opens ``file:``, ``ftp:`` and other schemes, so a URL that is ever
influenced by feed data, configuration or an environment variable can read local files or reach unintended
services. Bandit B310 ("Audit url open for permitted schemes") flags every call for that reason.

``safe_urlopen`` checks the scheme against an explicit allow-list (default: http and https) and only then delegates
to ``urllib.request.urlopen`` with identical arguments and return value, so behaviour is unchanged for every
legitimate URL. A disallowed scheme raises ``urllib.error.URLError`` (a subclass of ``OSError``), which is what the
existing network-error handlers in these scripts already catch.

The single ``# nosec B310`` below is the audited place where the scheme has just been validated; call sites must use
this helper instead of calling ``urlopen`` directly (enforced by tests/test_cdb_safe_http.py).
"""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request

ALLOWED_SCHEMES = frozenset({"http", "https"})


def _target_url(target) -> str:
    """The URL of a str or urllib.request.Request, as a string."""
    full_url = getattr(target, "full_url", None)
    return full_url if isinstance(full_url, str) else str(target)


def safe_urlopen(target, *args, allowed_schemes=ALLOWED_SCHEMES, **kwargs):
    """``urllib.request.urlopen(target, *args, **kwargs)`` after validating the URL scheme."""
    scheme = urllib.parse.urlsplit(_target_url(target)).scheme.lower()
    if scheme not in allowed_schemes:
        raise urllib.error.URLError(
            f"refusing to open URL with scheme {scheme!r}; allowed schemes: {sorted(allowed_schemes)}"
        )
    return urllib.request.urlopen(target, *args, **kwargs)  # nosec B310 -- scheme validated against the allow-list above
