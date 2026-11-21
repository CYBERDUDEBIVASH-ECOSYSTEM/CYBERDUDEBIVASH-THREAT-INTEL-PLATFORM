"""Shared test helper: model reports the bounded publisher has already PUT.

STAGE 3.5.1 (scripts/r2_reports_integrity.py) owes R2 delivery only for
in-window, TLP-publishable reports that were *rendered* when the publisher
ran: either an HTML file exists on the runner, or the publisher's state
records an ``html_sha256`` for the id.  Anything else is a late render owned
by STAGE 5.4.0b/5.4.0c and verified at 5.4.1/5.8.1c.  Fixtures that expect the
gate to verify a report must therefore mark it published, as production does.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS = str(Path(__file__).resolve().parent.parent / "scripts")


def mark_published(monkeypatch, tmp_path, rows):
    """Record ``rows`` ([(report id, report path)]) in a temp publish-state file
    and point the publisher module at it.  Merges with earlier calls.  Returns
    the publisher module so callers can patch further attributes."""
    if _SCRIPTS not in sys.path:
        sys.path.insert(0, _SCRIPTS)
    import r2_report_publisher as pub  # the module name the gate itself imports

    state_path = Path(tmp_path) / "r2_report_publish_state.json"
    state = (json.loads(state_path.read_text())
             if state_path.exists() else {"schema_version": "1.0", "items": {}})
    for report_id, path in rows:
        state["items"][report_id] = {"html_sha256": "0" * 64,
                                     "html_key": str(path).lstrip("/")}
    state_path.write_text(json.dumps(state))
    monkeypatch.setattr(pub, "STATE_PATH", state_path)
    return pub
