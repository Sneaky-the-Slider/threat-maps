"""Tests for fetch_threat_data_greynoise.py - GreyNoise Community API."""

import json
import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fetch_threat_data_greynoise import query_greynoise, enrich_with_geo


class TestQueryGreynoise:
    def test_success_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ip": "1.2.3.4",
            "noise": True,
            "riot": False,
            "classification": "malicious",
        }

        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp):
            result = query_greynoise("1.2.3.4")

        assert result["ip"] == "1.2.3.4"
        assert result["noise"] is True
        assert result["classification"] == "malicious"

    def test_not_found_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp):
            result = query_greynoise("10.0.0.1")

        assert result["ip"] == "10.0.0.1"
        assert result["noise"] is False
        assert result["message"] == "Not found"

    def test_rate_limit_429_retries(self):
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"ip": "1.2.3.4", "noise": True}

        with patch("fetch_threat_data_greynoise.requests.get", side_effect=[resp_429, resp_200]), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = query_greynoise("1.2.3.4")

        assert result["noise"] is True

    def test_max_retries_exceeded(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = query_greynoise("1.2.3.4")

        assert result["error"] == "Max retries exceeded"

    def test_request_exception(self):
        with patch("fetch_threat_data_greynoise.requests.get", side_effect=Exception("timeout")), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = query_greynoise("1.2.3.4")

        assert result["error"] == "Max retries exceeded"

    def test_other_error_status(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp):
            result = query_greynoise("1.2.3.4")

        assert "error" in result


class TestEnrichWithGeo:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "country": "Germany",
            "city": "Berlin",
            "lat": 52.52,
            "lon": 13.405,
            "org": "TestOrg",
            "isp": "TestISP",
        }

        item = {"ip": "1.2.3.4"}
        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = enrich_with_geo(item)

        assert result["country"] == "Germany"
        assert result["lat"] == 52.52

    def test_geo_api_failure(self):
        item = {"ip": "1.2.3.4"}
        with patch("fetch_threat_data_greynoise.requests.get", side_effect=Exception("connection error")), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = enrich_with_geo(item)

        assert "geo_error" in result

    def test_geo_api_non_success_status(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "fail", "message": "private range"}

        item = {"ip": "192.168.1.1"}
        with patch("fetch_threat_data_greynoise.requests.get", return_value=mock_resp), \
             patch("fetch_threat_data_greynoise.time.sleep"):
            result = enrich_with_geo(item)

        assert result["geo_error"] == "private range"
