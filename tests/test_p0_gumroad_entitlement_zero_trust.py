"""Offline zero-trust Gumroad license and customer-provisioning regression tests."""
import asyncio
import copy
import logging

import httpx
import pytest

from agent.fulfillment.gumroad_purchase_policy import verified_purchase
from agent.fulfillment import gumroad_handler
from agent.sdk import sentinel_guards

PRODUCT = "enterprise-test-product"
SELLER = "enterprise-test-seller"
LICENSE = "TEST-LICENSE-NONPRODUCTION-0001"
SALE = "test-sale-001"
EMAIL = "buyer@example.test"


def response_data():
    return {
        "success": True,
        "purchase": {
            "product_id": PRODUCT,
            "license_key": LICENSE,
            "sale_id": SALE,
            "seller_id": SELLER,
            "email": EMAIL,
            "refunded": False,
            "disputed": False,
            "chargebacked": False,
            "subscription_ended_at": None,
            "subscription_cancelled_at": None,
            "subscription_failed_at": None,
        },
    }


def webhook_payload():
    return {
        "product_id": PRODUCT, "license_key": LICENSE,
        "sale_id": SALE, "email": EMAIL,
        "full_name": "Untrusted webhook name",
    }


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return copy.deepcopy(self.data)


class FakeClient:
    def __init__(self, data, error=None):
        self.data = data
        self.error = error
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def post(self, url, *, data, timeout):
        self.calls.append((url, dict(data), timeout))
        if self.error:
            raise self.error
        return FakeResponse(self.data)


def configure_enterprise(monkeypatch):
    monkeypatch.setenv("GUMROAD_ENTERPRISE_PRODUCT_ID", PRODUCT)
    monkeypatch.setenv("GUMROAD_ENTERPRISE_SELLER_ID", SELLER)


def test_active_provider_receipt_accepted_by_pure_policy():
    purchase = verified_purchase(response_data(), product_id=PRODUCT, license_key=LICENSE)
    assert purchase is not None
    assert purchase["sale_id"] == SALE


@pytest.mark.parametrize("flag", ["refunded", "disputed", "chargebacked"])
def test_inactive_purchase_status_never_grants_access(flag):
    data = response_data()
    data["purchase"][flag] = True
    assert verified_purchase(data, product_id=PRODUCT, license_key=LICENSE) is None


@pytest.mark.parametrize("field", [
    "subscription_ended_at", "subscription_cancelled_at", "subscription_failed_at"
])
def test_ended_subscription_never_grants_access(field):
    data = response_data()
    data["purchase"][field] = "2026-11-18T06:00:00Z"
    assert verified_purchase(data, product_id=PRODUCT, license_key=LICENSE) is None


@pytest.mark.parametrize("missing", ["refunded", "disputed", "chargebacked", "sale_id"])
def test_missing_required_provider_authority_fails_closed(missing):
    data = response_data()
    del data["purchase"][missing]
    assert verified_purchase(data, product_id=PRODUCT, license_key=LICENSE) is None


def test_cross_product_or_cross_license_spoof_and_malformed_success_are_denied():
    for field, value in [("product_id", "attacker-product"), ("license_key", "other-key")]:
        data = response_data()
        data["purchase"][field] = value
        assert verified_purchase(data, product_id=PRODUCT, license_key=LICENSE) is None
    for data in [None, {"success": "true", "purchase": response_data()["purchase"]},
                 {"success": True, "purchase": []},
                 {"success": True}, {"success": False, "purchase": response_data()["purchase"]}]:
        assert verified_purchase(data, product_id=PRODUCT, license_key=LICENSE) is None


def test_fulfillment_without_durable_verified_sale_writer_does_not_even_call_provider(
        monkeypatch, caplog):
    configure_enterprise(monkeypatch)
    monkeypatch.delattr(gumroad_handler.SUBSCRIPTION_CORE,
                        "provision_verified_sale", raising=False)
    fake = FakeClient(response_data())
    monkeypatch.setattr(gumroad_handler.httpx, "AsyncClient", lambda **_kw: fake)
    caplog.set_level(logging.WARNING)
    result = asyncio.run(gumroad_handler.GumroadFulfillment().process_purchase(webhook_payload()))
    assert result is None
    assert fake.calls == []
    assert "P0_FULFILLMENT_HOLD" in caplog.text
    assert LICENSE not in caplog.text


def test_unconfigured_or_incorrect_enterprise_sku_is_denied_without_network(
        monkeypatch):
    monkeypatch.delenv("GUMROAD_ENTERPRISE_PRODUCT_ID", raising=False)
    monkeypatch.delenv("GUMROAD_ENTERPRISE_SELLER_ID", raising=False)
    fake = FakeClient(response_data())
    monkeypatch.setattr(gumroad_handler.httpx, "AsyncClient", lambda **_kw: fake)
    result = asyncio.run(gumroad_handler.GumroadFulfillment().process_purchase(webhook_payload()))
    assert result is None
    assert fake.calls == []


@pytest.mark.parametrize("change", [
    ("refunded", True), ("chargebacked", True),
    ("subscription_ended_at", "2026-11-18T06:00:00Z"),
    ("seller_id", "another-seller"),
    ("sale_id", "another-sale"),
    ("email", "another@example.test"),
])
def test_invalid_gumroad_receipt_cannot_reach_writer(monkeypatch, change):
    configure_enterprise(monkeypatch)
    data = response_data()
    data["purchase"][change[0]] = change[1]
    fake = FakeClient(data)
    monkeypatch.setattr(gumroad_handler.httpx, "AsyncClient", lambda **_kw: fake)
    calls = []
    monkeypatch.setattr(gumroad_handler.SUBSCRIPTION_CORE,
                        "provision_verified_sale",
                        lambda **kwargs: calls.append(kwargs) or "TEST-KEY",
                        raising=False)
    result = asyncio.run(gumroad_handler.GumroadFulfillment().process_purchase(webhook_payload()))
    assert result is None
    assert calls == []


def test_approved_purchase_passes_only_to_explicit_verified_sale_writer(monkeypatch):
    configure_enterprise(monkeypatch)
    fake = FakeClient(response_data())
    monkeypatch.setattr(gumroad_handler.httpx, "AsyncClient", lambda **_kw: fake)
    calls = []
    monkeypatch.setattr(gumroad_handler.SUBSCRIPTION_CORE,
                        "provision_verified_sale",
                        lambda **kwargs: calls.append(kwargs) or "TEST-KEY-ONLY",
                        raising=False)
    result = asyncio.run(gumroad_handler.GumroadFulfillment().process_purchase(webhook_payload()))
    assert result == "TEST-KEY-ONLY"
    assert calls == [{
        "sale_id": SALE, "product_id": PRODUCT, "owner": EMAIL, "tier": "enterprise"
    }]
    assert len(fake.calls) == 1
    assert fake.calls[0][1]["increment_uses_count"] == "false"


class ExampleSDKClient:
    def __init__(self):
        self.license_key = LICENSE
        self.is_authenticated = True

    @sentinel_guards.apex_license_guard(product_id=PRODUCT)
    async def premium(self):
        return "TEST-ACCESS"


def test_sdk_prior_boolean_cannot_bypass_offline_license_failure(monkeypatch, caplog):
    fake = FakeClient(response_data(), error=httpx.ConnectError("offline"))
    monkeypatch.setattr(sentinel_guards.httpx, "AsyncClient", lambda **_kw: fake)
    client = ExampleSDKClient()
    caplog.set_level(logging.WARNING)
    with pytest.raises(ConnectionError):
        asyncio.run(client.premium())
    assert client.is_authenticated is False
    assert LICENSE not in caplog.text


def test_sdk_refunded_license_is_denied_even_if_provider_success_true(monkeypatch, caplog):
    data = response_data()
    data["purchase"]["refunded"] = True
    fake = FakeClient(data)
    monkeypatch.setattr(sentinel_guards.httpx, "AsyncClient", lambda **_kw: fake)
    client = ExampleSDKClient()
    caplog.set_level(logging.WARNING)
    with pytest.raises(PermissionError):
        asyncio.run(client.premium())
    assert client.is_authenticated is False
    assert LICENSE not in caplog.text


def test_sdk_active_license_requires_current_provider_receipt(monkeypatch):
    fake = FakeClient(response_data())
    monkeypatch.setattr(sentinel_guards.httpx, "AsyncClient", lambda **_kw: fake)
    client = ExampleSDKClient()
    client.is_authenticated = False
    assert asyncio.run(client.premium()) == "TEST-ACCESS"
    assert client.is_authenticated is True
    assert fake.calls[0][1]["increment_uses_count"] == "false"
