import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree

from tests._helpers import load_fixture

from pan_firewall import PanFirewallConnector


def _stub_auth():
    auth = Mock()
    auth.api_key = Mock(return_value="KEY1")
    auth.rest_api_headers = Mock(return_value={"X-PAN-KEY": "KEY1"})
    auth.xml_api_headers = Mock(return_value={"X-PAN-KEY": "KEY1"})
    auth.invalidate = Mock()
    return auth


class TestGetLicenseInfo(unittest.TestCase):
    def setUp(self):
        self.conn = PanFirewallConnector(host="fw.example.internal", auth=_stub_auth())

    def test_parses_authcode_and_expired_bool(self):
        root = ElementTree.fromstring(load_fixture("license_response_vm50.xml"))
        with patch.object(self.conn, "_xml_op", return_value=root):
            entries = self.conn.get_license_info()

        self.assertEqual(len(entries), 2)

        pa_vm = entries[0]
        self.assertEqual(pa_vm["feature"], "PA-VM")
        self.assertIsNone(pa_vm["authcode"])
        self.assertIs(pa_vm["expired"], False)

        url_filtering = entries[1]
        self.assertEqual(url_filtering["feature"], "PAN-DB URL Filtering")
        self.assertEqual(url_filtering["authcode"], "I1234567")
        self.assertIs(url_filtering["expired"], True)


class TestParseLogEntries(unittest.TestCase):
    def setUp(self):
        self.conn = PanFirewallConnector(host="fw.example.internal", auth=_stub_auth())

    def test_parses_entries_from_finished_job(self):
        root = ElementTree.fromstring(load_fixture("log_job_poll_finished_with_results.xml"))
        entries = self.conn._parse_log_entries(root)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["type"], "TRAFFIC")
        self.assertEqual(entries[0]["subtype"], "start")
        self.assertEqual(entries[1]["subtype"], "deny")

    def test_zero_results_job_parses_to_empty_list_not_error(self):
        root = ElementTree.fromstring(load_fixture("log_job_poll_finished_zero_results.xml"))
        entries = self.conn._parse_log_entries(root)
        self.assertEqual(entries, [])


class TestGetDnsThreatLogs(unittest.TestCase):
    def test_uses_category_of_threatid_filter_when_supplied(self):
        conn = PanFirewallConnector(host="fw.example.internal", auth=_stub_auth())
        with patch.object(conn, "_xml_log_retrieve") as mock_retrieve, \
             patch.object(conn, "_parse_log_entries", return_value=[]):
            mock_retrieve.return_value = ElementTree.fromstring('<response status="success"/>')
            conn.get_dns_threat_logs(query="(category-of-threatid eq dns-c2)")
        mock_retrieve.assert_called_once_with(
            "threat", query="(category-of-threatid eq dns-c2)", nlogs=None
        )

    def test_warns_when_called_without_query(self):
        conn = PanFirewallConnector(host="fw.example.internal", auth=_stub_auth())
        with patch.object(conn, "_xml_log_retrieve") as mock_retrieve, \
             patch.object(conn, "_parse_log_entries", return_value=[]), \
             self.assertLogs("pan_firewall", level="WARNING") as cm:
            mock_retrieve.return_value = ElementTree.fromstring('<response status="success"/>')
            conn.get_dns_threat_logs()
        self.assertTrue(any("ALL threat log entries" in msg for msg in cm.output))


if __name__ == "__main__":
    unittest.main()
