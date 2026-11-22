"""Render locally missing, advertised dossiers before the bounded R2 publisher."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile

import generate_intel_reports as renderer
import r2_report_publisher as publisher
from r2_cost_guard import R2Budgets
from report_chronology_integrity import owned_report_path


def main() -> int:
    try:
        items = publisher.load_verified_publish_feed(publisher.FEED_JSON)
        state = publisher.load_publish_state()
        allowed, _ = publisher.apply_tlp_gate(items, state)
        candidates = publisher.build_publish_candidates(
            allowed, publisher.report_window_hours(), datetime.now(timezone.utc))
        pending = {}
        for candidate in candidates:
            item = candidate["item"]
            ident = candidate["id"]
            url = item.get("report_url") or item.get("internal_report_url") or ""
            path = owned_report_path(url, ident)
            if path is None:
                continue
            key = path.lstrip("/")
            prior = state["items"].get(ident, {})
            if (publisher.REPO_ROOT / key).is_file() or (
                    prior.get("html_key") == key and prior.get("html_sha256")):
                continue
            if renderer.rel_report_path(item) != publisher.REPO_ROOT / key or ident in pending:
                raise ValueError("Report destination is ambiguous or disagrees with the feed")
            pending[ident] = (item, path)

        if len(pending) > R2Budgets.from_env().max_report_writes_per_run:
            raise ValueError("Missing dossiers exceed the existing report upload budget")
        if pending:
            # The renderer writes validation results to its input. Give it a
            # private subset, preserving the authoritative feed byte-for-byte.
            with tempfile.TemporaryDirectory(prefix="sentinel-report-input-") as directory:
                manifest = Path(directory) / "reports.json"
                manifest.write_text(json.dumps({"advisories": [row for row, _ in pending.values()]}),
                                    encoding="utf-8")
                if renderer.main(["--manifest", str(manifest)]) != 0:
                    raise ValueError("Dossier rendering failed")
                rendered = {row["id"]: row.get("report_url")
                            for row in json.loads(manifest.read_text(encoding="utf-8"))["advisories"]}
                for ident, (_, path) in pending.items():
                    if rendered.get(ident) != path or not (publisher.REPO_ROOT / path.lstrip("/")).is_file():
                        raise ValueError("Renderer did not produce the advertised dossier")
        print(f"Current dossier preparation complete: {len(pending)} rendered locally")
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"::error::Current dossier preparation failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
