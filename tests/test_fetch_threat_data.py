"""Tests for fetch_threat_data.py - IP geolocation lookups."""

import json
import sys
import os
from io import BytesIO
from unittest.mock import patch, MagicMock
from urllib.error import URLError

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fetch_threat_data import get_ip_info, process_file


class TestGetIpInfo:
    def test_ipapi_success(self):
        mock_data = {"ip": "8.8.8.8", "country": "US", "city": "Mountain View"}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("fetch_threat_data.urlopen", return_value=mock_resp):
            result = get_ip_info("8.8.8.8", "ipapi")

        assert result["ip"] == "8.8.8.8"
        assert result["country"] == "US"

    def test_ipinfo_success(self):
        mock_data = {"ip": "1.1.1.1", "country": "AU", "city": "Sydney"}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("fetch_threat_data.urlopen", return_value=mock_resp), \
             patch.dict(os.environ, {"IPINFO_TOKEN": "test_token"}):
            result = get_ip_info("1.1.1.1", "ipinfo")

        assert result["ip"] == "1.1.1.1"

    def test_url_error_returns_error_dict(self):
        with patch("fetch_threat_data.urlopen", side_effect=URLError("Connection refused")):
            result = get_ip_info("8.8.8.8", "ipapi")

        assert "error" in result
        assert result["ip"] == "8.8.8.8"

    def test_unknown_service_returns_empty(self):
        result = get_ip_info("8.8.8.8", "unknown_service")
        assert result == {}


class TestProcessFile:
    def test_reads_ips_from_file(self, tmp_path):
        ip_file = tmp_path / "ips.txt"
        ip_file.write_text("8.8.8.8\n1.1.1.1\n")

        mock_data = {"ip": "8.8.8.8", "country": "US"}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("fetch_threat_data.urlopen", return_value=mock_resp):
            results = process_file(str(ip_file))

        assert len(results) == 2

    def test_skips_comments_and_blank_lines(self, tmp_path):
        ip_file = tmp_path / "ips.txt"
        ip_file.write_text("# comment\n\n8.8.8.8\n  \n")

        mock_data = {"ip": "8.8.8.8"}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("fetch_threat_data.urlopen", return_value=mock_resp):
            results = process_file(str(ip_file))

        assert len(results) == 1
