"""
pan_base.py
Base connector for the PAN-OS / Panorama REST and XML API surfaces.

Confirmed from Palo Alto Networks documentation:
    REST API base URL:  https://<host>/restapi/<version>/<resource-uri>
        (docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/
         get-started-with-the-pan-os-rest-api/access-the-rest-api)
    XML API base URL:   https://<host>/api/?type=<type>&...
        (docs.paloaltonetworks.com/ngfw/api/getting-started/
         structure-of-a-pan-os-xml-api-request)

REST API version segment is confirmed as "v11.0" even on the page documenting
it as the PAN-OS 11.1 resource set -- Palo Alto's REST version-in-URL number
does not track the PAN-OS release number 1:1. No PAN-OS 11.2-specific REST
version segment was found documented; v11.0 is used for both target versions
per pan_api_research.md.

Retry logic: a bounded loop (not recursion), 429 respects Retry-After, 5xx
uses exponential backoff, other 4xx errors are not retried.

Drata SA Team
"""

import logging
import time
from typing import Callable, Dict, Optional, Union
from xml.etree import ElementTree

import requests

from pan_auth import PanAuthClient

logger = logging.getLogger(__name__)

REST_API_VERSION = "v11.0"  # confirmed segment; see module docstring and pan_api_research.md section 3

_MAX_RETRIES = 5
_BACKOFF_BASE = 2  # seconds; doubles each retry for 5xx

# PAN-OS's XML API returns HTTP 200 with a status="error" envelope even for
# a bad/expired key (confirmed convention; the exact message text for this
# specific case is NOT confirmed by any official example in pan_api_research.md
# section 1 — this is a best-effort keyword heuristic, not a documented contract).
_AUTH_ERROR_KEYWORDS = ("invalid credential", "invalid key", "expired", "session timed out")


def _looks_like_auth_error(response_text: str) -> bool:
    lowered = response_text.lower()
    return any(keyword in lowered for keyword in _AUTH_ERROR_KEYWORDS)


class PanXmlApiError(Exception):
    """Raised when the PAN-OS XML API returns status="error"."""


class PanBaseConnector:
    """
    One instance per PAN-OS host -- an individual firewall's management
    hostname, or Panorama's own hostname. Provides both REST (_rest_get)
    and XML (_xml_request / _xml_op / _xml_config_get / _xml_log_*) call
    primitives against that single host.
    """

    def __init__(self, host: str, auth: PanAuthClient, verify_tls: Union[bool, str] = True) -> None:
        self.host = host
        self.auth = auth
        self.verify_tls = verify_tls
        self.session = requests.Session()

    # ------------------------------------------------------------------
    # REST API
    # ------------------------------------------------------------------

    def _rest_get(self, resource_uri: str, params: Optional[Dict] = None) -> dict:
        """
        GET https://<host>/restapi/{REST_API_VERSION}/<resource_uri>
        Key delivery confirmed: X-PAN-KEY header
        (docs.paloaltonetworks.com/pan-os/11-1/.../pan-os-rest-api-request-response-structure).
        """
        url = f"https://{self.host}/restapi/{REST_API_VERSION}/{resource_uri.lstrip('/')}"
        return self._get_with_retry(url, header_fn=self.auth.rest_api_headers, params=params)

    def _get_with_retry(self, url: str, header_fn: Callable[[], Dict[str, str]], params: Optional[Dict] = None) -> dict:
        """
        header_fn is called fresh on every attempt (not just once) so a
        one-shot re-auth (see reauthed below) actually picks up the
        regenerated key on its retry rather than resending the stale one.
        """
        reauthed = False
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = self.session.get(url, headers=header_fn(), params=params, timeout=30, verify=self.verify_tls)

            if resp.status_code in {401, 403} and not reauthed:
                logger.warning(
                    "HTTP %d from %s — treating as a stale/invalid API key, "
                    "regenerating once and retrying (attempt %d/%d)",
                    resp.status_code, url, attempt, _MAX_RETRIES,
                )
                self.auth.invalidate()
                reauthed = True
                continue

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                logger.warning("Rate limited by %s — waiting %ss (attempt %d/%d)", url, wait, attempt, _MAX_RETRIES)
                time.sleep(wait)
                continue

            if resp.status_code in {500, 502, 503, 504}:
                wait = _BACKOFF_BASE ** attempt
                logger.warning("HTTP %d from %s — retrying in %ss (attempt %d/%d)", resp.status_code, url, wait, attempt, _MAX_RETRIES)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()

        resp.raise_for_status()
        return {}  # unreachable; satisfies type checker

    # ------------------------------------------------------------------
    # XML API
    # ------------------------------------------------------------------

    def _xml_request(self, params: Dict[str, str]) -> ElementTree.Element:
        """
        POST https://<host>/api/ with the given type=... params plus the API key.
        Response envelope (status="success"|"error" attribute, <result> child)
        confirmed via the retrieve-logs job-id example
        (docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs).
        Raises PanXmlApiError on status="error".
        """
        url = f"https://{self.host}/api/"
        reauthed = False

        for attempt in range(1, _MAX_RETRIES + 1):
            body = dict(params)
            body["key"] = self.auth.api_key()
            resp = self.session.post(url, data=body, timeout=60, verify=self.verify_tls)

            if resp.status_code in {401, 403} and not reauthed:
                logger.warning(
                    "HTTP %d from %s — treating as a stale/invalid API key, "
                    "regenerating once and retrying (attempt %d/%d)",
                    resp.status_code, url, attempt, _MAX_RETRIES,
                )
                self.auth.invalidate()
                reauthed = True
                continue

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 10))
                logger.warning("Rate limited by %s — waiting %ss (attempt %d/%d)", url, wait, attempt, _MAX_RETRIES)
                time.sleep(wait)
                continue

            if resp.status_code in {500, 502, 503, 504}:
                wait = _BACKOFF_BASE ** attempt
                logger.warning("HTTP %d from %s — retrying in %ss (attempt %d/%d)", resp.status_code, url, wait, attempt, _MAX_RETRIES)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            root = ElementTree.fromstring(resp.text)
            if root.get("status") == "error":
                if not reauthed and _looks_like_auth_error(resp.text):
                    logger.warning(
                        "status=error from %s looks like a stale/invalid API key "
                        "(heuristic match, see _AUTH_ERROR_KEYWORDS) — regenerating "
                        "once and retrying (attempt %d/%d): %s",
                        url, attempt, _MAX_RETRIES, resp.text,
                    )
                    self.auth.invalidate()
                    reauthed = True
                    continue
                raise PanXmlApiError(f"{url} (params={params.get('type')}/{params.get('action') or params.get('log-type')}) returned status=error: {resp.text}")
            return root

        resp.raise_for_status()
        raise PanXmlApiError("unreachable")

    def _xml_op(self, cmd_xml: str, target: Optional[str] = None) -> ElementTree.Element:
        """
        type=op operational command. If `target` (a managed firewall's serial
        number) is supplied and this connector is pointed at Panorama, the
        request is proxied to that firewall — confirmed:
        docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api
        """
        params = {"type": "op", "cmd": cmd_xml}
        if target:
            params["target"] = target
        return self._xml_request(params)

    def _xml_config_get(self, xpath: str, action: str = "get", target: Optional[str] = None) -> ElementTree.Element:
        """
        type=config, action=get (candidate config) or action=show (active/running config).
        `target` proxies through Panorama to a managed firewall's serial number —
        confirmed to work with action=get
        (docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api).
        action=show combined with target was NOT found with an explicit worked
        example in official docs — treat that combination as unconfirmed.
        """
        params = {"type": "config", "action": action, "xpath": xpath}
        if target:
            params["target"] = target
        return self._xml_request(params)

    def _xml_log_submit(self, log_type: str, query: Optional[str] = None, nlogs: Optional[int] = None) -> str:
        """
        Submits a type=log job. Returns the job ID.
        Confirmed: docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/retrieve-logs
        """
        root = self._xml_request({
            k: v for k, v in {
                "type": "log",
                "log-type": log_type,
                "query": query,
                "nlogs": str(nlogs) if nlogs else None,
            }.items() if v is not None
        })
        job_id = root.findtext("./result/job")
        if not job_id:
            raise PanXmlApiError(f"log submit (log-type={log_type}) response had no <job>: {ElementTree.tostring(root, encoding='unicode')}")
        return job_id

    def _xml_log_poll(self, job_id: str) -> Optional[ElementTree.Element]:
        """
        Polls a submitted log job. Returns None while the job is still
        pending, or the <response> root once the job has finished.

        Primary completion signal: result/job/status == "FIN" — this is
        what the reference client (pan-python's xapi.py) actually checks,
        not <log> presence. A job matching zero log entries can legitimately
        finish (status=FIN) without ever populating <log>; relying on
        <log>-presence alone would poll forever on a valid empty result set.
        See pan_api_research.md section 5.

        Falls back to the <log>-presence heuristic only if <status> is
        absent from the response (defensive — official docs only describe
        that heuristic in prose, so keep it as a fallback rather than
        dropping it outright).
        """
        root = self._xml_request({"type": "log", "action": "get", "job-id": job_id})
        status = root.findtext("./result/job/status")
        if status is not None:
            return root if status == "FIN" else None
        if root.find("./result/log") is None:
            return None
        return root

    def _xml_log_retrieve(
        self,
        log_type: str,
        query: Optional[str] = None,
        nlogs: Optional[int] = None,
        poll_interval_seconds: float = 3.0,
        max_wait_seconds: float = 120.0,
    ) -> ElementTree.Element:
        """Convenience wrapper: submit + poll-until-finished in one call."""
        job_id = self._xml_log_submit(log_type, query=query, nlogs=nlogs)
        waited = 0.0
        while waited < max_wait_seconds:
            result = self._xml_log_poll(job_id)
            if result is not None:
                return result
            time.sleep(poll_interval_seconds)
            waited += poll_interval_seconds
        raise TimeoutError(f"log job {job_id} (log-type={log_type}) did not finish within {max_wait_seconds}s")
