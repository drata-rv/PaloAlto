"""
test_schema.py
Validates every normalizer in pan_drata_schemas.py against schema.json --
the JSON Schema submitted to Drata to create this connector's Custom
Connection resource. Exists so the two can't silently drift apart: if a
normalizer starts emitting a field schema.json doesn't declare (or the
wrong type), this fails loudly instead of surfacing as a 400 from Drata's
API the first time a real record gets published.

Builds one real record per evidenceType from the same fixtures the other
normalizer tests use, plus the zero-log-entries edge case, then validates
each against schema.json with the `jsonschema` library (test-only
dependency -- see requirements-dev.txt, not requirements.txt; the
connector itself never imports jsonschema at runtime).
"""

import json
import os
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import jsonschema

import pan_drata_schemas as schemas
from tests._helpers import load_fixture

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schema.json")

DEVICE = SimpleNamespace(
    id="fw-1", hostname="fw-1.suncoast.internal", site="Jacksonville",
    managed_by="DIRECT", scope="FIREWALL", device_group=None,
)
DG_DEVICE = SimpleNamespace(
    id="dg-1", hostname="panorama.suncoast.internal", site="UNSPECIFIED",
    managed_by="PANORAMA", scope="DEVICE_GROUP", device_group="suncoast-azure-dg",
)
RUN_TS = "2026-09-25T00:00:00+00:00"
WINDOW_START = "2026-09-24T00:00:00Z"
WINDOW_END = "2026-09-25T00:00:00Z"


def _rest_entries(fixture_name):
    return json.loads(load_fixture(fixture_name))["result"]["entry"]


def _xml_entries(fixture_name, xpath):
    root = ET.fromstring(load_fixture(fixture_name))
    return [{c.tag: c.text for c in e} for e in root.findall(xpath)]


class TestSchemaMatchesNormalizers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_SCHEMA_PATH) as f:
            cls.schema = json.load(f)
        cls.validator = jsonschema.Draft7Validator(cls.schema)

    def _assert_valid(self, record):
        errors = list(self.validator.iter_errors(record))
        if errors:
            messages = "; ".join(f"{e.message} (path: {list(e.path)})" for e in errors)
            self.fail(f"record {record.get('id')!r} failed schema.json: {messages}")

    def test_license_records(self):
        for entry in _xml_entries("license_response_vm50.xml", "./result/licenses/entry"):
            self._assert_valid(schemas.normalize_license(entry, DEVICE, RUN_TS))

    def test_url_filtering_profile_record(self):
        for entry in _rest_entries("url_filtering_profile_response.json"):
            self._assert_valid(schemas.normalize_url_filtering_profile(entry, DEVICE, RUN_TS))

    def test_dns_security_profile_record(self):
        for entry in _rest_entries("dns_security_profile_response.json"):
            self._assert_valid(schemas.normalize_dns_security_profile(entry, DEVICE, RUN_TS))

    def test_security_rule_records_all_scopes(self):
        for entry in _rest_entries("security_rules_response.json"):
            self._assert_valid(schemas.normalize_security_rule(entry, DEVICE, RUN_TS, rule_scope="LOCAL"))
        for entry in _rest_entries("security_pre_rules_response.json"):
            self._assert_valid(schemas.normalize_security_rule(entry, DG_DEVICE, RUN_TS, rule_scope="PRE_RULE"))
        for entry in _rest_entries("security_post_rules_response.json"):
            self._assert_valid(schemas.normalize_security_rule(entry, DG_DEVICE, RUN_TS, rule_scope="POST_RULE"))

    def test_log_summary_records(self):
        entries = _xml_entries("log_job_poll_finished_with_results.xml", "./result/log/logs/entry")
        self._assert_valid(schemas.normalize_traffic_log_summary(entries, DEVICE, RUN_TS, WINDOW_START, WINDOW_END))
        self._assert_valid(schemas.normalize_url_filtering_log_summary(entries, DEVICE, RUN_TS, WINDOW_START, WINDOW_END))
        self._assert_valid(schemas.normalize_dns_threat_log_summary(entries, DEVICE, RUN_TS, WINDOW_START, WINDOW_END))

    def test_log_summary_zero_entries_record(self):
        """Empty log window is still a valid, schema-conformant record -- existence-is-evidence."""
        self._assert_valid(schemas.normalize_dns_threat_log_summary([], DEVICE, RUN_TS, WINDOW_START, WINDOW_END))

    def test_schema_has_display_name_candidate(self):
        """Drata requires >=1 top-level string/number property for the display name."""
        props = self.schema["properties"]
        self.assertIn("name", props)
        self.assertEqual(props["name"]["type"], "string")


if __name__ == "__main__":
    unittest.main()
