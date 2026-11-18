import functools
import asyncio
import httpx
import logging
from typing import Callable, Any
from agent.fulfillment.gumroad_purchase_policy import verified_purchase

logger = logging.getLogger("CDB_LICENSE_GUARD")

def apex_license_guard(product_id: str):
    """
    Decorator: Gates functions behind a valid CyberDudeBivash Gumroad License.
    MANDATE: Non-blocking, 0 Regression, 2026-Tier Verification.
    """
    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        async def async_wrapper(self, *args, **kwargs):
            # 1. Retrieve license from the Client instance
            license_key = getattr(self, 'license_key', None)
            
            if not license_key:
                raise PermissionError("Access Denied: No license key provided for APEX features.")

            # 2. Require a CURRENT provider receipt, not a writable in-memory
            # flag from a prior session. No unsigned/unbounded offline grace.
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        "https://api.gumroad.com/v2/licenses/verify",
                        data={
                            "product_id": product_id,
                            "license_key": license_key,
                            "increment_uses_count": "false",
                        },
                        timeout=5.0,
                    )
                    response.raise_for_status()
                    data = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                self.is_authenticated = False
                logger.warning("License verifier unavailable or invalid (%s)", type(exc).__name__)
                raise ConnectionError(
                    "Enterprise license cannot be verified; access denied."
                ) from None

            if verified_purchase(
                data, product_id=product_id, license_key=license_key
            ) is None:
                self.is_authenticated = False
                logger.warning("Inactive or unverifiable Enterprise license rejected")
                raise PermissionError(
                    "Access Denied: Invalid or expired Sentinel APEX license."
                )

            # 3. Success: Mark client as authenticated and execute elite feature
            self.is_authenticated = True
            return await func(self, *args, **kwargs)

        return async_wrapper
    return decorator