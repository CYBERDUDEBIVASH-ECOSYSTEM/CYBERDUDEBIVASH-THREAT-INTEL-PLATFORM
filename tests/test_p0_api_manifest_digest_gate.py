"""Offline subprocess regression tests for the immutable API manifest gate."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


VALIDATOR = Path(__file__).resolve().parents[1] / "scripts" / "validate_api_manifests.py"


class ManifestDigestGateTests(unittest.TestCase):
    def run_fixture(self, mutation=None, ai=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            shutil.copyfile(VALIDATOR, scripts / VALIDATOR.name)
            # Isolate the digest gate from homepage asset discovery.
            (scripts / "homepage_source.py").write_text(
                "from pathlib import Path\ndef read_text_for_inspection(path):\n"
                "    return Path(path).read_text(encoding='utf-8')\n",
                encoding="utf-8",
            )
            (root / "index.html").write_text(
                "window.EMBEDDED_INTEL = [];", encoding="utf-8"
            )
            out = root / "api" / "v1" / "intel"
            out.mkdir(parents=True)
            payload = {"schema_version": "1.0", "count": 1,
                       "items": [{"id": "synthetic-test", "title": "é" * 90}]}
            digest = hashlib.sha256(json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")).hexdigest()
            payload["sha256"] = digest
            registry = {"bundles": {key: {"sha256": digest}
                                    for key in ("latest", "top10", "apex")}}
            if mutation:
                mutation(payload, registry)
            for key in ("latest", "top10", "apex"):
                (out / (key + ".json")).write_text(
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    encoding="utf-8",
                )
            (out / "manifest.json").write_text(json.dumps(registry), encoding="utf-8")
            if ai:
                (out / "ai_summary.json").write_text(
                    json.dumps({"campaigns": [{}]}), encoding="utf-8"
                )
            return subprocess.run(
                [sys.executable, str(scripts / VALIDATOR.name)], cwd=root,
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )

    def test_valid_digest_and_six_checks(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CHECKS PASSED: 6/6", result.stdout)

    def test_optional_ai_counts_as_seventh_check(self):
        result = self.run_fixture(ai=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CHECKS PASSED: 7/7", result.stdout)

    def assert_digest_rejected(self, mutation):
        result = self.run_fixture(mutation)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("digest mismatch", result.stdout)
        self.assertIn("CHECKS PASSED: 5/6", result.stdout)

    def test_tampered_payload(self):
        self.assert_digest_rejected(
            lambda payload, registry: payload["items"][0].update(title="x" * 90)
        )

    def test_tampered_registry_digest(self):
        self.assert_digest_rejected(
            lambda payload, registry: registry["bundles"]["latest"].update(sha256="0" * 64)
        )

    def test_missing_embedded_digest(self):
        self.assert_digest_rejected(lambda payload, registry: payload.pop("sha256"))

    def test_matching_but_forged_registry_and_embedded_digests(self):
        def mutate(payload, registry):
            payload["sha256"] = "0" * 64
            registry["bundles"]["latest"]["sha256"] = "0" * 64
        self.assert_digest_rejected(mutate)


if __name__ == "__main__":
    unittest.main()
