#!/usr/bin/env python3
"""
gumroad_handler.py - CYBERDUDEBIVASH(R) SENTINEL APEX v44.0
GUMROAD PURCHASE FULFILLMENT & API PROVISIONING
Founder & CEO - CyberDudeBivash Pvt. Ltd.

This module automates the bridge between a Gumroad sale and the 
Sentinel APEX Enterprise SaaS environment.
"""

import json
import os
import httpx
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from agent.subscription_manager import SUBSCRIPTION_CORE
from agent.fulfillment.gumroad_purchase_policy import verified_purchase

class GumroadFulfillment:
    def __init__(self):
        self.access_token = os.getenv("GUMROAD_ACCESS_TOKEN")
        self.authority = "CYBERDUDEBIVASH OFFICIAL"

    async def process_purchase(self, payload: Dict[str, Any]) -> Optional[str]:
        """Verify provider purchase state before any enterprise key operation.

        This does NOT yet provide durable per-sale replay idempotency, a
        payment-collection receipt, or a transactional KV entitlement write.
        Do not certify live automatic fulfillment until those separate controls
        are tested end-to-end.
        """
        if not isinstance(payload, dict):
            logging.warning("Fulfillment Declined: Malformed purchase event")
            return None

        product_id = payload.get("product_id")
        license_key = payload.get("license_key")
        event_sale = payload.get("sale_id")
        event_email = payload.get("email")
        expected_product = os.getenv("GUMROAD_ENTERPRISE_PRODUCT_ID", "").strip()
        expected_seller = os.getenv("GUMROAD_ENTERPRISE_SELLER_ID", "").strip()

        # The caller MUST NOT choose the product that confers Enterprise tier.
        if (not expected_product or not expected_seller
                or not isinstance(product_id, str)
                or product_id != expected_product
                or not isinstance(license_key, str) or not license_key.strip()
                or not isinstance(event_sale, str) or not event_sale.strip()
                or not isinstance(event_email, str) or not event_email.strip()):
            logging.warning("Fulfillment Declined: Missing or unapproved purchase authority")
            return None

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.gumroad.com/v2/licenses/verify",
                    data={
                        "product_id": expected_product,
                        "license_key": license_key,
                        # A webhook retry must not consume an additional license use.
                        "increment_uses_count": "false",
                    },
                    timeout=10.0,
                )
                response.raise_for_status()
                verification = response.json()

            purchase = verified_purchase(
                verification, product_id=expected_product,
                license_key=license_key,
            )
            if purchase is None:
                logging.warning("Fulfillment Declined: License or purchase is inactive")
                return None
            if purchase.get("seller_id") != expected_seller:
                logging.warning("Fulfillment Declined: Provider seller mismatch")
                return None
            if purchase.get("sale_id") != event_sale:
                logging.warning("Fulfillment Declined: Provider sale mismatch")
                return None
            provider_email = purchase.get("email")
            if (not isinstance(provider_email, str)
                    or not provider_email.strip()
                    or "@" not in provider_email
                    or any(char.isspace() for char in provider_email)
                    or provider_email.casefold() != event_email.strip().casefold()):
                logging.warning("Fulfillment Declined: Provider purchaser mismatch")
                return None

            # Source check is NOT durable replay prevention; this must remain
            # a release HOLD until sale-id uniqueness is enforced transactionally.
            new_api_key = SUBSCRIPTION_CORE.provision_tenant(
                name=provider_email, tier="enterprise",
            )
            logging.info("Fulfillment: Provider purchase verified and credential created")
            return new_api_key
        except Exception as exc:
            # Provider errors and storage failures must not leak license, key,
            # buyer data, access tokens, or raw response bodies into CI logs.
            logging.error("Fulfillment Failed: %s", type(exc).__name__)
            return None

# Global Instance
FULFILLMENT_HANDLER = GumroadFulfillment()