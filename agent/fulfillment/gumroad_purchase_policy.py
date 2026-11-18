"""Gumroad purchase-state authority for Enterprise/Sentinel license checks.

Successful license-key lookup is not by itself proof of an active entitlement.
Gumroad's verified response includes purchase identity, refund/dispute status,
and membership-end timestamps. This module performs no network or registry I/O.

A valid purchase response is still NOT proof of a new, unprocessed payment.
Durable provider-event deduplication and authenticated onboarding remain
separate mandatory gates before live customer provisioning can be certified.
"""
from collections.abc import Mapping


_INACTIVE_FLAGS = ("refunded", "disputed", "chargebacked")
_INACTIVE_TIMESTAMPS = (
    "subscription_ended_at", "subscription_cancelled_at",
    "subscription_failed_at",
)


def verified_purchase(verification, *, product_id, license_key):
    """Return the provider purchase only when its active-state proof is complete.

    Missing/malformed state is denied, rather than treated as an active sale.
    Product and key values must come from a trusted caller, not the response.
    """
    if (not isinstance(product_id, str) or not product_id.strip()
            or not isinstance(license_key, str) or not license_key.strip()
            or not isinstance(verification, Mapping)
            or verification.get("success") is not True):
        return None
    purchase = verification.get("purchase")
    if not isinstance(purchase, Mapping):
        return None
    if purchase.get("product_id") != product_id:
        return None
    if purchase.get("license_key") != license_key:
        return None
    sale_id = purchase.get("sale_id")
    if not isinstance(sale_id, str) or not sale_id.strip():
        return None
    if any(purchase.get(field) is not False for field in _INACTIVE_FLAGS):
        return None
    if any(purchase.get(field) is not None for field in _INACTIVE_TIMESTAMPS):
        return None
    return dict(purchase)
