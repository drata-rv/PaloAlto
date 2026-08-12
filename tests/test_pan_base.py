import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree

from tests._helpers import fake_response, load_fixture

from pan_base import PanBaseConnector, PanXmlApiError


def _stub_auth(keys=("KEY1",)):
    auth = Mock()
    auth.api_key = Mock(side_effect=list(keys) + [keys[-1]] * 10)
    auth.rest_api_headers = Mock(side_effect=lambda: {"X-PAN-KEY": auth.api_key()})
    auth.xml_api_headers = Mock(side_effect=lambda: {"X-PAN-KEY": auth.api_key()})
    auth.invalidate = Mock()
    return auth


class TestXmlLogPoll(unittest.TestCase):
    """Regression coverage for the result/job/status==FIN completion-check fix."""

    def setUp(self):
        self.conn = PanBaseConnector(host="fw.example.internal", auth=_stub_auth())

    def _poll_with_fixture(self, fixture_name):
        root = ElementTree.fromstring(load_fixture(fixture_name))
        with patch.object(self.conn, "_xml_request", return_value=root):
            return self.conn._xml_log_poll("18")

    def test_finished_with_zero_results_is_done_not_pending(self):
        # The exact bug this fixes: status=FIN with no <log> node must be
        # treated as DONE, not as "still pending" (which would poll forever).
        result = self._poll_with_fixture("log_job_poll_finished_zero_results.xml")
        self.assertIsNotNone(result)

    def test_in_progress_is_pending(self):
        result = self._poll_with_fixture("log_job_poll_inprogress.xml")
        self.assertIsNone(result)

    def test_finished_with_results_is_done(self):
        result = self._poll_with_fixture("log_job_poll_finished_with_results.xml")
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.find("./result/log"))

    def test_fallback_to_log_presence_when_status_absent(self):
        # Defensive fallback path: no <status> element at all.
        root = ElementTree.fromstring(
            '<response status="success"><result><log><logs count="0"/></log></result></response>'
        )
        with patch.object(self.conn, "_xml_request", return_value=root):
            self.assertIsNotNone(self.conn._xml_log_poll("18"))

        root_pending = ElementTree.fromstring('<response status="success"><result></result></response>')
        with patch.object(self.conn, "_xml_request", return_value=root_pending):
            self.assertIsNone(self.conn._xml_log_poll("18"))


class TestVerifyTls(unittest.TestCase):
    def test_accepts_bool(self):
        conn = PanBaseConnector(host="h", auth=_stub_auth(), verify_tls=False)
        self.assertFalse(conn.verify_tls)

    def test_accepts_ca_bundle_path(self):
        conn = PanBaseConnector(host="h", auth=_stub_auth(), verify_tls="/etc/pan/internal-ca.pem")
        self.assertEqual(conn.verify_tls, "/etc/pan/internal-ca.pem")


class TestRestGetRetry(unittest.TestCase):
    def setUp(self):
        self.conn = PanBaseConnector(host="fw.example.internal", auth=_stub_auth(("KEY1", "KEY2")))

    @patch("pan_base.time.sleep", return_value=None)
    @patch("requests.Session.get")
    def test_429_retries_and_succeeds(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            fake_response(429, headers={"Retry-After": "1"}),
            fake_response(200, json_data={"ok": True}),
        ]
        result = self.conn._rest_get("Objects/URLFilteringSecurityProfiles")
        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_once_with(1)

    @patch("pan_base.time.sleep", return_value=None)
    @patch("requests.Session.get")
    def test_5xx_backs_off_and_succeeds(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            fake_response(503),
            fake_response(200, json_data={"ok": True}),
        ]
        result = self.conn._rest_get("Objects/URLFilteringSecurityProfiles")
        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_once()

    @patch("requests.Session.get")
    def test_401_triggers_one_reauth_then_succeeds(self, mock_get):
        mock_get.side_effect = [
            fake_response(401),
            fake_response(200, json_data={"ok": True}),
        ]
        result = self.conn._rest_get("Objects/URLFilteringSecurityProfiles")
        self.assertEqual(result, {"ok": True})
        self.conn.auth.invalidate.assert_called_once()
        self.assertEqual(self.conn.auth.api_key.call_count, 2)

    @patch("requests.Session.get")
    def test_401_does_not_loop_forever_on_repeated_failure(self, mock_get):
        mock_get.side_effect = [fake_response(401), fake_response(401)]
        with self.assertRaises(Exception):
            self.conn._rest_get("Objects/URLFilteringSecurityProfiles")
        self.conn.auth.invalidate.assert_called_once()


class TestXmlRequestRetryAndReauth(unittest.TestCase):
    def setUp(self):
        self.conn = PanBaseConnector(host="fw.example.internal", auth=_stub_auth(("KEY1", "KEY2")))

    @patch("requests.Session.post")
    def test_status_error_raises_pan_xml_api_error(self, mock_post):
        mock_post.return_value = fake_response(
            200, text='<response status="error"><result><msg>Unknown command</msg></result></response>'
        )
        with self.assertRaises(PanXmlApiError):
            self.conn._xml_op("<request><license><info/></request>")

    @patch("requests.Session.post")
    def test_status_error_with_auth_keywords_triggers_reauth(self, mock_post):
        mock_post.side_effect = [
            fake_response(200, text='<response status="error"><result><msg>Invalid Credential</msg></result></response>'),
            fake_response(200, text='<response status="success"><result><ok/></result></response>'),
        ]
        root = self.conn._xml_op("<request><license><info/></request>")
        self.assertEqual(root.get("status"), "success")
        self.conn.auth.invalidate.assert_called_once()
        # key must be regenerated (not resent stale) on the retried request
        first_call_key = mock_post.call_args_list[0].kwargs["data"]["key"]
        second_call_key = mock_post.call_args_list[1].kwargs["data"]["key"]
        self.assertNotEqual(first_call_key, second_call_key)

    @patch("requests.Session.post")
    def test_http_401_triggers_reauth(self, mock_post):
        mock_post.side_effect = [
            fake_response(401),
            fake_response(200, text='<response status="success"><result><ok/></result></response>'),
        ]
        root = self.conn._xml_op("<request><license><info/></request>")
        self.assertEqual(root.get("status"), "success")
        self.conn.auth.invalidate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
