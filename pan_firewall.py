"""
pan_firewall.py
Evidence-retrieval methods for a single PAN-OS firewall or Panorama host.

Maps each piece of evidence typically gathered manually for a compliance
audit to the confirmed API surface for it — see pan_api_research.md for
full citations and the "Items That Must Be Confirmed" list of gaps this
file's docstrings flag inline.

    License status (URL Filtering, DNS Security)          -> XML API, type=op
    URL Filtering / Anti-Spyware (DNS Security) profiles   -> REST API, Objects
    Security policy rules (incl. applications)             -> REST API, Policies
    Traffic / URL Filtering logs                           -> XML API, type=log
    DNS Security activity                                  -> XML API, type=log&log-type=threat
                                                               (no dedicated DNS log-type exists
                                                               on PAN-OS 11.1/11.2 — that arrives
                                                               only in 12.1+)

Drata SA Team
"""

import logging
from typing import Optional
from xml.etree import ElementTree

from pan_base import PanBaseConnector

logger = logging.getLogger(__name__)


class PanFirewallConnector(PanBaseConnector):
    """
    One instance per PAN-OS host: an individual firewall's management
    hostname, or Panorama's own hostname (for Panorama's own device-group
    definitions, or to proxy op/config-get calls to a managed firewall via
    `target=<serial>`).
    """

    # ------------------------------------------------------------------
    # License status — XML API only; no REST equivalent is documented
    # ------------------------------------------------------------------

    def get_license_info(self, target: Optional[str] = None) -> list:
        """
        Returns parsed license/subscription entries from `request license info`.

        CONFIRMED: type=op is the only documented API surface for license
        status (no REST License resource exists); the CLI command name and
        its presence on both the PAN-OS 11.1 and 11.2 CLI hierarchies is
        confirmed.

        NOT CONFIRMED: the literal XML request body below. Palo Alto's
        documented method to obtain it is `debug cli on` followed by running
        the command live on a device, which echoes the exact XML — no
        docs.paloaltonetworks.com page publishes this string. The shape used
        here follows the standard PAN-OS convention for zero-argument
        operational subcommands but has NOT been independently verified for
        this specific command.

        NOT CONFIRMED: the exact `Feature` string PAN-OS uses for the DNS
        Security subscription line (the one official KB sample response
        found did not include a DNS Security entry). "PAN-DB URL Filtering"
        is confirmed as the URL Filtering feature string.

        CONFIRM AGAINST A LIVE FIREWALL before trusting this in
        production — see pan_api_research.md.
        """
        cmd = "<request><license><info/></license></request>"
        root = self._xml_op(cmd, target=target)
        logger.info(
            "get_license_info raw response (verify structure manually — "
            "parsing below is UNCONFIRMED against official docs): %s",
            ElementTree.tostring(root, encoding="unicode"),
        )

        entries = []
        for entry in root.findall("./result/licenses/entry"):
            entries.append({
                "feature":     entry.findtext("feature"),
                "description": entry.findtext("description"),
                "serial":      entry.findtext("serial"),
                "issued":      entry.findtext("issued"),
                "expires":     entry.findtext("expires"),
                # Confirmed via pan-os-python + a real captured VM-50 response
                # (pan_api_research.md section 2): "expired" is the literal
                # string "yes"/"no", not a native bool -- convert it rather
                # than passing the raw string through.
                "expired":     entry.findtext("expired") == "yes",
                "authcode":    entry.findtext("authcode"),
            })
        if not entries:
            logger.warning(
                "get_license_info parsed zero entries — the <licenses><entry> "
                "path is UNVERIFIED against official docs; inspect the raw "
                "response logged above and adjust parsing if the actual shape differs."
            )
        return entries

    # ------------------------------------------------------------------
    # Security Profiles — REST API, confirmed resource paths
    # ------------------------------------------------------------------

    def get_url_filtering_profiles(self, location: str, vsys: Optional[str] = None, device_group: Optional[str] = None) -> list:
        """
        GET /restapi/{version}/Objects/URLFilteringSecurityProfiles
        CONFIRMED resource path (docs.paloaltonetworks.com/pan-os/11-1/.../access-the-rest-api).

        `location` must be a value PAN-OS documents for the target host type:
        firewall — predefined | shared (Objects only) | vsys | panorama-pushed;
        Panorama — shared | device-group.
        `panorama-pushed` is confirmed valid ONLY when called directly against
        a firewall's own REST endpoint, not Panorama's.
        """
        params = self._location_params(location, vsys, device_group)
        data = self._rest_get("Objects/URLFilteringSecurityProfiles", params=params)
        return data.get("result", {}).get("entry", [])

    def get_dns_security_profiles(self, location: str, vsys: Optional[str] = None, device_group: Optional[str] = None) -> list:
        """
        GET /restapi/{version}/Objects/AntiSpywareSecurityProfiles

        CONFIRMED: DNS Security has no standalone profile object in PAN-OS —
        it is configured inside the Anti-Spyware profile
        (docs.paloaltonetworks.com/network-security/.../security-profile-dns-security).
        This returns full Anti-Spyware profile entries; the DNS-Security-
        specific sub-fields within each entry are NOT confirmed by an
        official field-name reference — inspect a live response against the
        target firewall's own /restapi-doc before parsing specific
        DNS-related sub-fields.
        """
        params = self._location_params(location, vsys, device_group)
        data = self._rest_get("Objects/AntiSpywareSecurityProfiles", params=params)
        return data.get("result", {}).get("entry", [])

    # ------------------------------------------------------------------
    # Security Policy Rules — REST API, confirmed resource paths
    # ------------------------------------------------------------------

    def get_security_rules(self, location: str, vsys: Optional[str] = None, device_group: Optional[str] = None) -> list:
        """
        Firewall-local rules (location=vsys) or Panorama-pushed rules as seen
        on the firewall itself (location=panorama-pushed).
        CONFIRMED resource: Policies/SecurityRules
        (docs.paloaltonetworks.com/pan-os/11-1/.../methods-supported-rest-api).
        location=panorama-pushed is documented as valid ONLY when calling a
        firewall's own REST endpoint directly, NOT Panorama's.

        Response entries confirmed to include an `application` field
        (list of attached applications). The field name for an attached
        URL Filtering profile is NOT confirmed by any official example —
        verify against the live device's /restapi-doc.
        """
        params = self._location_params(location, vsys, device_group)
        data = self._rest_get("Policies/SecurityRules", params=params)
        return data.get("result", {}).get("entry", [])

    def get_security_pre_rules(self, device_group: str) -> list:
        """
        Panorama device-group Pre Rules (evaluated before local firewall rules).
        CONFIRMED: docs.paloaltonetworks.com/pan-os/11-1/.../work-with-policy-rules-on-panorama-rest-api
        Call against Panorama's own host.
        """
        data = self._rest_get("Policies/SecurityPreRules", params={"location": "device-group", "device-group": device_group})
        return data.get("result", {}).get("entry", [])

    def get_security_post_rules(self, device_group: str) -> list:
        """
        Panorama device-group Post Rules (evaluated after local firewall rules).
        CONFIRMED: docs.paloaltonetworks.com/pan-os/11-1/.../work-with-policy-rules-on-panorama-rest-api
        Call against Panorama's own host.
        """
        data = self._rest_get("Policies/SecurityPostRules", params={"location": "device-group", "device-group": device_group})
        return data.get("result", {}).get("entry", [])

    # ------------------------------------------------------------------
    # Logs — XML API only; REST API has zero documented log capability
    # ------------------------------------------------------------------

    def get_traffic_logs(self, query: Optional[str] = None, nlogs: Optional[int] = None) -> list:
        """
        CONFIRMED: log-type=traffic via the type=log async job flow
        (docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs).
        """
        root = self._xml_log_retrieve("traffic", query=query, nlogs=nlogs)
        return self._parse_log_entries(root)

    def get_url_filtering_logs(self, query: Optional[str] = None, nlogs: Optional[int] = None) -> list:
        """CONFIRMED: log-type=url via the same async job flow."""
        root = self._xml_log_retrieve("url", query=query, nlogs=nlogs)
        return self._parse_log_entries(root)

    def get_dns_threat_logs(self, query: Optional[str] = None, nlogs: Optional[int] = None) -> list:
        """
        DNS Security activity on PAN-OS 11.1.13 / 11.2.10-H3 has NO dedicated
        log-type — that arrives only in PAN-OS 12.1+. CONFIRMED: Palo Alto's
        own guidance is to query the Threat log (log-type=threat) instead —
        "Palo Alto Networks recommends viewing logs for malicious DNS
        requests as threat logs instead of DNS Security logs"
        (docs.paloaltonetworks.com/pan-os/10-1/.../dns-security-data-collection-and-logging).

        NOT CONFIRMED: the exact filter/category value to isolate DNS-related
        entries within the Threat log. `query` should be supplied once that
        filter is confirmed against a live device's Monitor > Logs > Threat
        tab (whose filter syntax the API's `query` parameter is documented to
        mirror). Calling this with no query returns ALL threat log entries,
        not DNS-specific ones.
        """
        if query is None:
            logger.warning(
                "get_dns_threat_logs called with no query filter — this "
                "returns ALL threat log entries, not just DNS Security ones. "
                "The correct filter value is an unconfirmed gap (see "
                "pan_api_research.md section 5); confirm it against a live "
                "device before treating results as DNS-specific evidence."
            )
        root = self._xml_log_retrieve("threat", query=query, nlogs=nlogs)
        return self._parse_log_entries(root)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _location_params(location: str, vsys: Optional[str], device_group: Optional[str]) -> dict:
        params = {"location": location}
        if vsys:
            params["vsys"] = vsys
        if device_group:
            params["device-group"] = device_group
        return params

    @staticmethod
    def _parse_log_entries(root: ElementTree.Element) -> list:
        """
        Converts each <entry> under result/log/logs into a flat dict of its
        child tag -> text.

        CONFIRMED: a <log> node is present in the result once a log job has
        finished (absent while pending). NOT CONFIRMED verbatim in an
        official quoted example: the exact nested path to individual entries
        beneath <log> — result/log/logs/entry is the standard PAN-OS XML
        log-export shape used here, but was not found as a byte-for-byte
        quoted example in this research pass. If this returns nothing on a
        job that should have entries, inspect the raw response and adjust
        the xpath.
        """
        entries = []
        for entry in root.findall("./result/log/logs/entry"):
            entries.append({child.tag: (child.text or "") for child in entry})
        return entries
