#!/usr/bin/env python3
"""
license_validator.py - CYBERDUDEBIVASH(R) SENTINEL APEX v44.0
ZERO-TRUST LICENSE INTERCEPTOR
Founder & CEO - CyberDudeBivash Pvt. Ltd.
"""

import json
import os
from datetime import datetime

class CDBLicenseValidator:
    def __init__(self):
        self.tenant_store = "data/sovereign/tenants.json"
        self._initialize_registry()

    def _initialize_registry(self):
        """Do not create credentials during import or on missing state.

        A missing, unreadable or unprovisioned registry is an authorization
        failure, not a reason to seed a predictable Enterprise credential.
        Validated provisioning must create the registry through an explicitly
        authenticated, auditable path. Existing persisted keys are unchanged.
        """
        return None

    def is_valid(self, api_key: str) -> bool:
        """Validates API Key against the Sovereign Registry."""
        if not api_key:
            return False
        try:
            with open(self.tenant_store, "r") as f:
                tenants = json.load(f)
                if api_key in tenants:
                    t = tenants[api_key]
                    expiry = datetime.fromisoformat(t["expires"])
                    return t["status"] == "active" and datetime.now() < expiry
        except Exception:
            return False
        return False

# Global instance for API Middleware
LICENSE_VALIDATOR = CDBLicenseValidator()