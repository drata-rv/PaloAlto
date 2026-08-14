"""
pan_drata_publisher.py
Pushes normalised PAN-OS/Panorama compliance records to a Drata Custom
Connection. This module is schema-agnostic -- it has no PAN-specific
logic, so it's the same shape used by Drata's other custom connections.

Uses the direct upsert endpoint from the Custom Data Records API:
    POST /custom-connections/{connectionId}/resources/{resourceId}/records
         body: {"data": [...]}
         -- records with matching IDs are updated; new records are created;
            records not included in the payload are left untouched.

This is an additive upsert, not a full replacement. Records for evidence
that fails collection on a given run are preserved from the previous run
rather than deleted.

All normalized PAN records publish to a single PAN_DRATA_RESOURCE_ID -- one
resource, not one per evidence type. Simpler to operate, and every record
already carries `evidenceType` so downstream Drata rules can still filter
by resource type within that one resource.

Required environment variables:
    DRATA_API_KEY            -- API key from Drata Settings → API Keys (used as Bearer token)
    PAN_DRATA_CONNECTION_ID  -- Custom Connection ID (visible in Drata app URL or API)
    PAN_DRATA_RESOURCE_ID    -- Resource ID within the connection
                                Retrieve with:
                                GET /custom-connections/{connectionId}?expand[]=customResources

The connection/resource vars are PAN_-prefixed (DRATA_API_KEY is not) so
this can be deployed alongside another Drata custom connection in a shared
Azure Function App without colliding on App Settings names -- see
pan_main.py's module docstring.

Drata SA Team
"""

import logging
import os
from typing import List

import requests

logger = logging.getLogger(__name__)

_DRATA_BASE = "https://public-api.drata.com/public"
_BATCH_SIZE = 500


class DrataPublisher:
    def __init__(self) -> None:
        self._url = (
            f"{_DRATA_BASE}/custom-connections/{os.environ['PAN_DRATA_CONNECTION_ID']}"
            f"/resources/{os.environ['PAN_DRATA_RESOURCE_ID']}/records"
        )
        self._http = requests.Session()
        self._http.headers.update({
            "Authorization": f"Bearer {os.environ['DRATA_API_KEY']}",
            "Content-Type":  "application/json",
        })

    def publish(self, records: List[dict]) -> None:
        """
        Upsert records in batches of 500. Skips if records list is empty.
        """
        if not records:
            logger.warning("publish_skipped — no records to upload")
            return

        batches = [records[i : i + _BATCH_SIZE] for i in range(0, len(records), _BATCH_SIZE)]
        logger.info("drata_publish_start total_records=%d batches=%d", len(records), len(batches))

        for i, batch in enumerate(batches, 1):
            resp = self._http.post(self._url, json={"data": batch})
            resp.raise_for_status()
            logger.info("drata_batch_ok batch=%d/%d records=%d", i, len(batches), len(batch))

        logger.info("drata_publish_complete total_records=%d", len(records))
