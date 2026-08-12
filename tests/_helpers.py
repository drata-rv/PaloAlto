"""Shared test helpers: fake requests.Response + fixture loading."""

import os
from unittest.mock import Mock

import requests

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


def fake_response(status_code: int, text: str = "", json_data=None, headers=None) -> Mock:
    """Mimics the subset of requests.Response behavior pan_base.py relies on."""
    resp = Mock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    resp.json = Mock(return_value=json_data if json_data is not None else {})

    def _raise():
        if status_code >= 400:
            raise requests.HTTPError(f"{status_code} error")

    resp.raise_for_status = Mock(side_effect=_raise)
    return resp
