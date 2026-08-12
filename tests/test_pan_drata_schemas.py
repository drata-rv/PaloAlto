import json
import unittest
from types import SimpleNamespace

from tests._helpers import load_fixture

import pan_drata_schemas as schemas

RUN_TS = "2026-08-12T00:00:00+00:00"


def _device(**overrides):
    defaults = dict(
        id="fw-site-a-1",
        hostname="fw-1.example.internal",
        site="Site-A",
        managed_by="DIRECT",
        scope="FIREWALL",
        device_group=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _rest_entries(fixture_name):
    return json.loads(load_fixture(fixture_name))["result"]["entry"]


class TestNormalizeLicense(unittest.TestCase):
    def test_non_expired_is_compliant_and_keeps_authcode_when_present(self):
        entry = {
            "feature": "PAN-DB URL Filtering", "description": "URL Filtering",
            "serial": "SN1", "issued": "March 24, 2017", "expires": "Never",
            "expired": False, "authcode": "I1234567",
        }
        record = schemas.normalize_license(entry, _device(), RUN_TS)
        self.assertEqual(record["status"], "COMPLIANT")
        self.assertEqual(record["authcode"], "I1234567")
        self.assertEqual(record["id"], "fw-site-a-1:license:PAN-DB URL Filtering")
        self.assertEqual(record["service"], "pan_firewall")
        self.assertEqual(record["site"], "Site-A")

    def test_expired_is_noncompliant(self):
        entry = {"feature": "DNS Security", "expired": True, "authcode": None}
        record = schemas.normalize_license(entry, _device(), RUN_TS)
        self.assertEqual(record["status"], "NONCOMPLIANT")

    def test_none_authcode_is_dropped_not_null(self):
        entry = {"feature": "PA-VM", "expired": False, "authcode": None}
        record = schemas.normalize_license(entry, _device(), RUN_TS)
        self.assertNotIn("authcode", record)


class TestNormalizeUrlFilteringProfile(unittest.TestCase):
    def test_configured_status_and_category_lists(self):
        entry = _rest_entries("url_filtering_profile_response.json")[0]
        record = schemas.normalize_url_filtering_profile(entry, _device(), RUN_TS)
        self.assertEqual(record["status"], "CONFIGURED")
        self.assertEqual(record["evidenceType"], "URL_FILTERING_PROFILE")
        self.assertEqual(record["blockedCategories"], ["malware", "phishing"])
        self.assertEqual(record["allowCategories"], ["business-and-economy"])


class TestNormalizeDnsSecurityProfile(unittest.TestCase):
    def test_uses_log_level_not_log_severity(self):
        entry = _rest_entries("dns_security_profile_response.json")[0]
        record = schemas.normalize_dns_security_profile(entry, _device(), RUN_TS)
        self.assertEqual(record["status"], "CONFIGURED")
        categories = record["dnsSecurityCategories"]
        self.assertEqual(len(categories), 3)
        malware = next(c for c in categories if c["category"] == "pan-dns-sec-malware")
        self.assertEqual(malware["logLevel"], "medium")
        self.assertEqual(malware["action"], "sinkhole")
        self.assertEqual(record["enabledCategoryCount"], 3)


class TestNormalizeSecurityRule(unittest.TestCase):
    def test_group_attachment_and_enabled_status(self):
        entry = _rest_entries("security_rules_response.json")[0]  # allow-web-outbound
        record = schemas.normalize_security_rule(entry, _device(), RUN_TS, rule_scope="LOCAL")
        self.assertEqual(record["status"], "ENABLED")
        self.assertEqual(record["ruleScope"], "LOCAL")
        self.assertEqual(record["securityProfileGroup"], ["default-profile-group"])
        self.assertNotIn("securityProfiles", record)

    def test_per_category_profile_attachment_and_disabled_status(self):
        entry = _rest_entries("security_rules_response.json")[1]  # block-known-bad
        record = schemas.normalize_security_rule(entry, _device(), RUN_TS, rule_scope="LOCAL")
        self.assertEqual(record["status"], "DISABLED")
        self.assertIsNone(record.get("securityProfileGroup"))
        self.assertEqual(record["securityProfiles"]["url-filtering"], ["default-url-filtering"])
        self.assertEqual(record["securityProfiles"]["spyware"], ["default-dns-security"])

    def test_pre_and_post_rule_scope_and_device_group_service(self):
        pre_entry = _rest_entries("security_pre_rules_response.json")[0]
        post_entry = _rest_entries("security_post_rules_response.json")[0]
        dg_device = _device(scope="DEVICE_GROUP", device_group="azure-dg", hostname="panorama.example.internal")

        pre_record = schemas.normalize_security_rule(pre_entry, dg_device, RUN_TS, rule_scope="PRE_RULE")
        post_record = schemas.normalize_security_rule(post_entry, dg_device, RUN_TS, rule_scope="POST_RULE")

        self.assertEqual(pre_record["ruleScope"], "PRE_RULE")
        self.assertEqual(post_record["ruleScope"], "POST_RULE")
        self.assertEqual(pre_record["service"], "panorama")
        self.assertEqual(pre_record["deviceGroup"], "azure-dg")


class TestLogSummaries(unittest.TestCase):
    def setUp(self):
        self.entries = [
            {"action": "allow"}, {"action": "deny"}, {"action": "deny"}, {"action": "allow"},
        ]

    def test_traffic_summary_counts_denies_as_affected(self):
        record = schemas.normalize_traffic_log_summary(
            self.entries, _device(), RUN_TS, "2026-08-12T00:00:00Z", "2026-08-12T01:00:00Z"
        )
        self.assertEqual(record["status"], "CONFIGURED")
        self.assertEqual(record["totalLogCount"], 4)
        self.assertEqual(record["affectedCount"], 2)
        self.assertEqual(record["actionBreakdown"], {"allow": 2, "deny": 2})

    def test_zero_entries_still_emits_one_record(self):
        record = schemas.normalize_traffic_log_summary(
            [], _device(), RUN_TS, "2026-08-12T00:00:00Z", "2026-08-12T01:00:00Z"
        )
        self.assertEqual(record["totalLogCount"], 0)
        self.assertEqual(record["affectedCount"], 0)
        self.assertEqual(record["status"], "CONFIGURED")

    def test_dns_threat_summary_affected_equals_total(self):
        entries = [{"category": "dns-c2"}, {"category": "dns-c2"}, {"category": "phishing"}]
        record = schemas.normalize_dns_threat_log_summary(
            entries, _device(), RUN_TS, "2026-08-12T00:00:00Z", "2026-08-12T01:00:00Z"
        )
        self.assertEqual(record["totalLogCount"], 3)
        self.assertEqual(record["affectedCount"], 3)
        self.assertEqual(record["categoryBreakdown"], {"dns-c2": 2, "phishing": 1})


if __name__ == "__main__":
    unittest.main()
