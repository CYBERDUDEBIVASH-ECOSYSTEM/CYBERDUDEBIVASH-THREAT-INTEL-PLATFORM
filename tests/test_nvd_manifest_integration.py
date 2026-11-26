"""Isolated publisher integration test; no production records or network writes."""
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_nvd_scoped_publication_policy import projection

ROOT = Path(__file__).resolve().parents[1]


class NvdManifestIntegrationTests(unittest.TestCase):
    def test_actual_manifest_generator(self):
        with tempfile.TemporaryDirectory(prefix="apex-nvd-fixture-") as tmp:
            root = Path(tmp)
            date = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            row = projection()
            for key in ("published_at", "publication_timestamp", "timestamp",
                        "retrieval_timestamp", "source_modified_at"):
                row[key] = date
            # Synthetic test fixture only. Never use these flags to promote a
            # real review-only record, or use this workspace for publication.
            denied = dict(row, id="intel--fedcba9876543210", tlp="TLP:RED")
            raw = [row, denied]
            for rel in ("api/feed.json", "data/stix/feed_manifest.json"):
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(raw), encoding="utf-8")
            before = (root / "data/stix/feed_manifest.json").read_bytes()
            bootstrap = (
                "import runpy,sys,socket;"
                "def_placeholder=0;"
                "sys.addaudithook(lambda event,args: "
                "(_ for _ in ()).throw(RuntimeError('network denied in fixture')) "
                "if event.startswith('socket.') else None);"
                "runpy.run_path(sys.argv[1],run_name='__main__')"
            )
            env = {k: v for k, v in os.environ.items()
                   if k.upper() in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "HOME", "USERPROFILE")}
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", bootstrap,
                 str(ROOT / "scripts/generate_api_manifests.py")],
                cwd=root, env=env, capture_output=True, timeout=60,
                encoding="utf-8", errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            directory = root / "api/v1/intel"
            registry = json.loads((directory / "manifest.json").read_bytes())
            for name in ("latest", "latest_pro", "top10", "apex"):
                data = json.loads((directory / (name + ".json")).read_bytes())
                checksum = data.pop("sha256")
                encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), checksum)
                self.assertEqual(registry["bundles"][name]["sha256"], checksum)
                self.assertEqual(data["count"], 1)
                item, = data["items"]
                self.assertEqual(item["id"], row["id"])
                self.assertEqual(item["tlp"], "TLP:CLEAR")
                self.assertEqual(item["tlp_assignment"], "policy_first_party_public_source")
                self.assertIsNone(item["severity"])
                self.assertIsNone(item["risk_score"])
            self.assertEqual((root / "data/stix/feed_manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
