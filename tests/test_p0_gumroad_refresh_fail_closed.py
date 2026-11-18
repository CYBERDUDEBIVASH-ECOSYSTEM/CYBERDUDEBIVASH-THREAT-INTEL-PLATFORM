"""Offline tests: zero Gumroad writes/requests by default, one-SKU live authority."""
import io
import os
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gumroad_auto_refresh as gm

SKU = "DETECTION_TEST_SKU_01"
TOKEN = "FAKE_NEVER_VALID_TOKEN"


def env(dry="true", approved=SKU, token=TOKEN):
    return {"GUMROAD_DRY_RUN": dry, "GUMROAD_APPROVED_PRODUCT_IDS": approved,
            "GUMROAD_ACCESS_TOKEN": token, "FEED_PATH": "offline.test"}


def item():
    return {"title": "Test CVE", "severity": "HIGH", "risk_score": 5}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.limit = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit):
        self.limit = limit
        return self.payload[:limit]


class TestGumroadP0(unittest.TestCase):
    def test_direct_cli_defaults_to_zero_network_offline(self):
        with patch.dict(os.environ, {"GUMROAD_ACCESS_TOKEN": TOKEN}, clear=True), \
             patch.object(gm, "load_feed", return_value=[item()]), \
             patch.object(gm, "list_products") as listing, \
             patch.object(gm, "update_product_description") as update:
            self.assertEqual(gm.main(), 0)
            listing.assert_not_called()
            update.assert_not_called()

    def test_explicit_dry_run_never_lists_products_or_sales(self):
        with patch.dict(os.environ, env(), clear=True), \
             patch.object(gm, "load_feed", return_value=[item()]), \
             patch.object(gm, "gm_request", side_effect=AssertionError("unexpected HTTP")) as req, \
             patch.object(gm, "list_products") as listing:
            self.assertEqual(gm.main(), 0)
            req.assert_not_called()
            listing.assert_not_called()

    def test_missing_live_authority_denied_before_http(self):
        for setting in (env("false", token=""), env("false", approved=""),
                        env("false", approved="one,two"),
                        env("false", approved="bad/../id")):
            with patch.dict(os.environ, setting, clear=True), \
                 patch.object(gm, "load_feed", return_value=[item()]), \
                 patch.object(gm, "list_products") as listing:
                self.assertEqual(gm.main(), 2)
                listing.assert_not_called()

    def test_empty_feed_fails_before_any_provider_access(self):
        with patch.dict(os.environ, env("false"), clear=True), \
             patch.object(gm, "load_feed", return_value=[]), \
             patch.object(gm, "list_products") as listing:
            self.assertEqual(gm.main(), 1)
            listing.assert_not_called()

    def test_only_one_explicit_published_detection_pack_is_mutated(self):
        products = [
            {"id": SKU, "name": "Sentinel APEX Detection Pack -- sample", "published": True},
            {"id": "UNRELATED", "name": "Subscription tier", "published": True},
            {"id": "OTHER", "name": "Sentinel APEX Detection Pack -- other", "published": True},
        ]
        with patch.dict(os.environ, env("false"), clear=True), \
             patch.object(gm, "load_feed", return_value=[item()]), \
             patch.object(gm, "list_products", return_value=products), \
             patch.object(gm, "update_product_description", return_value=True) as update:
            self.assertEqual(gm.main(), 0)
            update.assert_called_once()
            self.assertEqual(update.call_args.args[1], SKU)
            self.assertFalse(update.call_args.kwargs["dry_run"])

    def test_duplicate_unlisted_or_unrelated_sku_never_written(self):
        sample = {"id": SKU, "name": "Sentinel APEX Detection Pack -- sample",
                  "published": True}
        for products in ([sample, dict(sample)],
                         [{"id": SKU, "name": "Subscription Tier", "published": True}],
                         [{"id": SKU, "name": sample["name"], "published": False}], []):
            with patch.dict(os.environ, env("false"), clear=True), \
                 patch.object(gm, "load_feed", return_value=[item()]), \
                 patch.object(gm, "list_products", return_value=products), \
                 patch.object(gm, "update_product_description") as update:
                self.assertNotEqual(gm.main(), 0)
                update.assert_not_called()

    def test_live_writer_error_never_false_green(self):
        products = [{"id": SKU, "name": "Sentinel APEX Detection Pack -- sample", "published": True}]
        with patch.dict(os.environ, env("false"), clear=True), \
             patch.object(gm, "load_feed", return_value=[item()]), \
             patch.object(gm, "list_products", return_value=products), \
             patch.object(gm, "update_product_description", return_value=False):
            self.assertEqual(gm.main(), 1)

    def test_request_scope_rejects_invalid_methods_paths_and_payloads(self):
        bad = [("GET", "https://evil.test/v2/products", None),
               ("GET", "/products/../admin", None),
               ("DELETE", "/products/" + SKU, None),
               ("PUT", "/products/%2Fadmin", {"description": "x"}),
               ("PUT", "/products/" + SKU, {"enabled": "true"}),
               ("PUT", "/products/" + SKU, {"description": "x" * (gm.MAX_DESC_CHARS + 1)})]
        with patch.object(gm, "_open_gumroad") as opener:
            for method,path,data in bad:
                self.assertFalse(gm.gm_request(TOKEN, method, path, data)["success"])
            opener.assert_not_called()

    def test_redirect_to_foreign_host_denied_and_opener_host_fixed(self):
        handler = gm._RejectGumroadRedirect()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(
                urllib.request.Request("https://api.gumroad.com/v2/products"),
                None, 302, "Found", {}, "https://evil.test/capture",
            )
        class FakeOpener:
            def open(self, req, timeout):
                self.req = req
                self.timeout = timeout
                return object()
        fake = FakeOpener()
        with patch.object(gm.urllib.request, "build_opener", return_value=fake) as build:
            good = urllib.request.Request("https://api.gumroad.com/v2/products")
            gm._open_gumroad(good, timeout=3)
            self.assertEqual(fake.req.full_url, good.full_url)
            self.assertEqual(fake.timeout, 3)
            self.assertIsInstance(build.call_args.args[0], gm._RejectGumroadRedirect)
        with patch.object(gm.urllib.request, "build_opener") as build:
            with self.assertRaises(ValueError):
                gm._open_gumroad(urllib.request.Request("https://evil.test/x"))
            build.assert_not_called()

    def test_bounded_response_and_invalid_json_shape_fail_closed(self):
        oversized = FakeResponse(b"X" * (gm.GUMROAD_MAX_API_BYTES + 1))
        invalid = FakeResponse(b"[]")
        valid = FakeResponse(b'{"success":true,"products":[]}')
        with patch.object(gm, "_open_gumroad", side_effect=[oversized, invalid, valid]):
            self.assertFalse(gm.gm_request(TOKEN, "GET", "/products")["success"])
            self.assertEqual(oversized.limit, gm.GUMROAD_MAX_API_BYTES + 1)
            self.assertFalse(gm.gm_request(TOKEN, "GET", "/products")["success"])
            self.assertTrue(gm.gm_request(TOKEN, "GET", "/products")["success"])

    def test_provider_error_body_and_token_never_logged(self):
        error = urllib.error.HTTPError(
            "https://api.gumroad.com/v2/products", 429, "Denied", {},
            io.BytesIO(b"FAKE_NEVER_VALID_TOKEN PRIVATE_UPSTREAM_BODY"),
        )
        with patch.object(gm, "_open_gumroad", side_effect=error):
            with self.assertLogs("sentinel.gumroad_refresh", level="ERROR") as logs:
                self.assertFalse(gm.gm_request(TOKEN, "GET", "/products")["success"])
        self.assertNotIn(TOKEN, "|".join(logs.output))
        self.assertNotIn("PRIVATE_UPSTREAM_BODY", "|".join(logs.output))

    def test_workflow_manual_main_only_offline_default(self):
        workflow = (ROOT / ".github/workflows/gumroad-refresh.yml").read_text(encoding="utf-8")
        self.assertIn("default: 'true'", workflow)
        self.assertIn("APPROVE_ONE_DETECTION_PACK_UPDATE", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertNotRegex(workflow, r"(?m)^  (schedule|push|workflow_run):")
        self.assertIn("GUMROAD_APPROVED_PRODUCT_IDS:", workflow)


if __name__ == "__main__":
    unittest.main()
