import unittest
from unittest.mock import patch

from tests._helpers import fake_response

from pan_auth import PanAuthClient, PanAuthError


class TestPanAuthClient(unittest.TestCase):
    def setUp(self):
        self.client = PanAuthClient(host="fw.example.internal", username="svc", password="secret")

    @patch("pan_auth.requests.post")
    def test_api_key_generated_once_and_cached(self, mock_post):
        mock_post.return_value = fake_response(
            200, text='<response status="success"><result><key>ABC123</key></result></response>'
        )
        self.assertEqual(self.client.api_key(), "ABC123")
        self.assertEqual(self.client.api_key(), "ABC123")
        mock_post.assert_called_once()

    @patch("pan_auth.requests.post")
    def test_invalidate_forces_regeneration(self, mock_post):
        mock_post.side_effect = [
            fake_response(200, text='<response status="success"><result><key>FIRST</key></result></response>'),
            fake_response(200, text='<response status="success"><result><key>SECOND</key></result></response>'),
        ]
        self.assertEqual(self.client.api_key(), "FIRST")
        self.client.invalidate()
        self.assertEqual(self.client.api_key(), "SECOND")
        self.assertEqual(mock_post.call_count, 2)

    @patch("pan_auth.requests.post")
    def test_generate_key_error_status_raises(self, mock_post):
        mock_post.return_value = fake_response(
            200, text='<response status="error"><result><msg>Invalid Credential</msg></result></response>'
        )
        with self.assertRaises(PanAuthError):
            self.client.api_key()

    @patch("pan_auth.requests.post")
    def test_generate_key_missing_key_element_raises(self, mock_post):
        mock_post.return_value = fake_response(
            200, text='<response status="success"><result><msg>no key here</msg></result></response>'
        )
        with self.assertRaises(PanAuthError):
            self.client.api_key()


if __name__ == "__main__":
    unittest.main()
