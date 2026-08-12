"""
pan_auth.py
API key acquisition for the PAN-OS / Panorama XML and REST APIs.

Confirmed from Palo Alto Networks documentation
(docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/generate-api-key):
    POST /api/?type=keygen with a form-encoded user/password returns an API
    key. The same mechanism is used against a firewall or a Panorama
    appliance -- there is no separate REST-specific keygen endpoint.

Key delivery differs by API surface (both confirmed):
    XML API  -- key=<key> query parameter OR X-PAN-KEY header
    REST API -- X-PAN-KEY header only (no documented query-parameter form)

By default PAN-OS API keys never expire (API Key Lifetime = 0, confirmed at
docs.paloaltonetworks.com/pan-os/11-1/.../configure-api-key-lifetime). This
client does not attempt to pre-detect expiry -- if a target device has an
explicit lifetime configured, a failed call will surface and a new key must
be generated.

NOT CONFIRMED: the literal XML response body of a successful type=keygen
call. No docs.paloaltonetworks.com page found during research shows the
full <response>...<key>...</key> response for keygen specifically -- only
the request side is documented. The parsing below (./result/key) follows
the general XML API response envelope that IS confirmed elsewhere (the
status="success"/"error" attribute and a <result> child, per the retrieve-logs
job-id example) plus the extremely well-established PAN-OS convention for
where the key appears, but this exact path has not been verified against an
official response example. Confirm against a live device on first
use -- see pan_api_research.md, "Items That Must Be Confirmed."

One PanAuthClient instance is scoped to ONE device (a single firewall's
management hostname, or Panorama's own hostname) since PAN-OS API keys are
generated per-device against that device's own admin account.

Drata SA Team
"""

from __future__ import annotations

import logging
from typing import Optional
from xml.etree import ElementTree

import requests

logger = logging.getLogger(__name__)


class PanAuthError(Exception):
    """Raised when a device rejects credentials or returns a keygen error."""


class PanAuthClient:
    """Generates and caches a single API key for one PAN-OS/Panorama host."""

    def __init__(self, host: str, username: str, password: str, verify_tls: bool = True) -> None:
        self.host = host
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._api_key: Optional[str] = None

    def api_key(self) -> str:
        if self._api_key is None:
            self._api_key = self._generate_key()
        return self._api_key

    def invalidate(self) -> None:
        """Drop the cached key so the next api_key() call regenerates it.

        Used by PanBaseConnector's one-shot re-auth path when a call fails
        with what looks like a stale/expired key.
        """
        self._api_key = None

    def xml_api_headers(self) -> dict:
        """XML API: X-PAN-KEY header (key=<key> query param is also documented as valid)."""
        return {"X-PAN-KEY": self.api_key()}

    def rest_api_headers(self) -> dict:
        """REST API: X-PAN-KEY header is the only documented delivery method."""
        return {"X-PAN-KEY": self.api_key()}

    def _generate_key(self) -> str:
        resp = requests.post(
            f"https://{self.host}/api/",
            data={"type": "keygen", "user": self._username, "password": self._password},
            verify=self._verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        root = ElementTree.fromstring(resp.text)
        if root.get("status") != "success":
            raise PanAuthError(f"keygen failed for {self.host}: {resp.text}")

        key = root.findtext("./result/key")
        if not key:
            logger.error(
                "keygen for %s returned status=success but no <result><key> "
                "was found at the expected path -- this path is UNVERIFIED "
                "against official docs (see pan_auth.py module docstring). "
                "Raw response: %s",
                self.host, resp.text,
            )
            raise PanAuthError(f"keygen response for {self.host} had no <key> at ./result/key: {resp.text}")
        return key
