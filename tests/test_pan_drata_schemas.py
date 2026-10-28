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
            {"action": "allow", "receive_time": "2026/08/12 09:00:00"},
            {"action": "deny", "receive_time": "2026/08/12 09:05:00"},
            {"action": "deny", "receive_time": "2026/08/12 09:10:00"},
            {"action": "allow", "receive_time": "2026/08/12 09:02:00"},
        ]

    def test_traffic_summary_counts_non_allow_as_affected(self):
        record = schemas.normalize_traffic_log_summary(self.entries, _device(), RUN_TS)
        self.assertEqual(record["status"], "CONFIGURED")
        self.assertEqual(record["totalLogCount"], 4)
        self.assertEqual(record["affectedCount"], 2)
        self.assertEqual(record["actionBreakdown"], {"allow": 2, "deny": 2})

    def test_every_documented_non_allow_traffic_action_counts(self):
        # PAN's traffic-log table: allow, deny, drop, drop ICMP, reset client/server/both
        # (spaces in the doc table, hyphens in syslog/XML -- both must work).
        actions = ["allow", "deny", "drop", "drop ICMP", "reset client", "reset-server", "reset-both"]
        record = schemas.normalize_traffic_log_summary([{"action": a} for a in actions], _device(), RUN_TS)
        self.assertEqual(record["affectedCount"], 6)

    def test_url_summary_counts_every_non_allow_action(self):
        actions = ["allow", "alert", "block-url", "block-continue", "continue", "block-override", "override-lockout"]
        record = schemas.normalize_url_filtering_log_summary([{"action": a} for a in actions], _device(), RUN_TS)
        self.assertEqual(record["affectedCount"], 6)

    def test_window_comes_from_the_entries_not_the_run_time(self):
        record = schemas.normalize_traffic_log_summary(self.entries, _device(), RUN_TS)
        self.assertEqual(record["windowStart"], "2026/08/12 09:00:00")
        self.assertEqual(record["windowEnd"], "2026/08/12 09:10:00")

    def test_id_is_stable_across_runs(self):
        first = schemas.normalize_traffic_log_summary(self.entries, _device(), "2026-08-12T00:00:00+00:00")
        second = schemas.normalize_traffic_log_summary(self.entries, _device(), "2026-08-13T00:00:00+00:00")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["id"], "fw-site-a-1:traffic")

    def test_log_limit_reached_flags_a_capped_sample(self):
        capped = schemas.normalize_traffic_log_summary(self.entries, _device(), RUN_TS, sample_limit=4)
        under = schemas.normalize_traffic_log_summary(self.entries, _device(), RUN_TS, sample_limit=1000)
        self.assertIs(capped["logLimitReached"], True)
        self.assertIs(under["logLimitReached"], False)

    def test_zero_entries_still_emits_one_record(self):
        record = schemas.normalize_traffic_log_summary([], _device(), RUN_TS)
        self.assertEqual(record["totalLogCount"], 0)
        self.assertEqual(record["affectedCount"], 0)
        self.assertEqual(record["status"], "CONFIGURED")
        self.assertNotIn("windowStart", record)

    def test_dns_threat_summary_groups_by_thr_category_not_url_category(self):
        # On a threat-log entry `category` is the URL category ("any" for DNS
        # detections); the threat classification is `thr_category`.
        entries = [
            {"thr_category": "dns-c2", "category": "any"},
            {"thr_category": "dns-c2", "category": "any"},
            {"thr_category": "dns-malware", "category": "any"},
        ]
        record = schemas.normalize_dns_threat_log_summary(entries, _device(), RUN_TS)
        self.assertEqual(record["totalLogCount"], 3)
        self.assertEqual(record["affectedCount"], 3)
        self.assertEqual(record["categoryBreakdown"], {"dns-c2": 2, "dns-malware": 1})


class TestTolerantParsing(unittest.TestCase):
    def test_member_list_accepts_dict_list_and_string(self):
        self.assertEqual(schemas._member_list({"member": ["a", "b"]}), ["a", "b"])
        self.assertEqual(schemas._member_list(["a", "b"]), ["a", "b"])
        self.assertEqual(schemas._member_list("a"), ["a"])
        self.assertEqual(schemas._member_list({"member": "a"}), ["a"])
        self.assertIsNone(schemas._member_list(None))
        self.assertIsNone(schemas._member_list({}))

    def test_rule_with_bare_list_profile_group_does_not_raise(self):
        entry = {"@name": "r", "profile-setting": {"group": ["strict"]}}
        record = schemas.normalize_security_rule(entry, _device(), RUN_TS, rule_scope="LOCAL")
        self.assertEqual(record["securityProfileGroup"], ["strict"])

    def test_dns_profile_with_single_entry_object_does_not_raise(self):
        entry = {"@name": "p", "botnet-domains": {"dns-security-categories": {"entry": {"@name": "pan-dns-sec-cc", "action": "sinkhole"}}}}
        record = schemas.normalize_dns_security_profile(entry, _device(), RUN_TS)
        self.assertEqual(record["enabledCategoryCount"], 1)


class TestLocationInRecords(unittest.TestCase):
    def test_location_is_recorded_and_makes_ids_unique(self):
        in_vsys = {"@name": "default", "@location": "vsys"}
        pushed = {"@name": "default", "@location": "panorama-pushed"}
        a = schemas.normalize_url_filtering_profile(in_vsys, _device(), RUN_TS)
        b = schemas.normalize_url_filtering_profile(pushed, _device(), RUN_TS)
        self.assertEqual(a["location"], "vsys")
        self.assertEqual(b["location"], "panorama-pushed")
        self.assertNotEqual(a["id"], b["id"])

    def test_missing_location_is_omitted_not_null(self):
        record = schemas.normalize_url_filtering_profile({"@name": "default"}, _device(), RUN_TS)
        self.assertNotIn("location", record)


if __name__ == "__main__":
    unittest.main()
