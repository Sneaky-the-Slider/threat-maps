"""Tests for fetch_threat_data_otx_sdk.py - AlienVault OTX SDK integration."""

import sys
import os
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Mock OTXv2 before importing the module
sys.modules["OTXv2"] = MagicMock()
sys.modules["OTXv2"].IndicatorTypes = MagicMock()
sys.modules["OTXv2"].IndicatorTypes.IPv4 = "IPv4"

from fetch_threat_data_otx_sdk import fetch_subscribed_pulses, extract_ipv4_indicators


class TestFetchSubscribedPulses:
    def _make_pulse(self, name, days_ago=1):
        ts = (datetime.utcnow() - timedelta(days=days_ago)).isoformat()
        return {
            "id": f"pulse-{name}",
            "name": name,
            "created": ts,
            "modified": ts,
            "tags": ["test"],
            "indicators": [],
        }

    def test_fetches_recent_pulses(self):
        otx = MagicMock()
        otx.get_subscribed.return_value = {
            "results": [self._make_pulse("recent", days_ago=1)]
        }

        with patch("fetch_threat_data_otx_sdk.time.sleep"):
            result = fetch_subscribed_pulses(otx, max_pulses=10, days_back=7)

        assert len(result) == 1
        assert result[0]["name"] == "recent"

    def test_filters_old_pulses(self):
        otx = MagicMock()
        otx.get_subscribed.return_value = {
            "results": [self._make_pulse("old", days_ago=30)]
        }

        with patch("fetch_threat_data_otx_sdk.time.sleep"):
            result = fetch_subscribed_pulses(otx, max_pulses=10, days_back=7)

        assert len(result) == 0

    def test_stops_on_empty_page(self):
        otx = MagicMock()
        otx.get_subscribed.side_effect = [
            {"results": [self._make_pulse("p1")]},
            {"results": []},
        ]

        with patch("fetch_threat_data_otx_sdk.time.sleep"):
            result = fetch_subscribed_pulses(otx, max_pulses=50, days_back=7)

        assert len(result) == 1

    def test_respects_max_pulses(self):
        otx = MagicMock()
        pulses = [self._make_pulse(f"p{i}") for i in range(25)]
        otx.get_subscribed.return_value = {"results": pulses}

        with patch("fetch_threat_data_otx_sdk.time.sleep"):
            result = fetch_subscribed_pulses(otx, max_pulses=5, days_back=7)

        assert len(result) == 5

    def test_handles_api_error(self):
        otx = MagicMock()
        otx.get_subscribed.side_effect = Exception("API error")

        with patch("fetch_threat_data_otx_sdk.time.sleep"):
            result = fetch_subscribed_pulses(otx, max_pulses=10, days_back=7)

        assert result == []


class TestExtractIpv4Indicators:
    def test_extracts_ipv4(self):
        pulses = [
            {
                "id": "pulse-1",
                "name": "Test Pulse",
                "created": "2024-01-01T00:00:00Z",
                "tags": ["malware"],
                "indicators": [
                    {"type": "IPv4", "indicator": "1.2.3.4", "description": "bad ip"},
                    {"type": "domain", "indicator": "evil.com", "description": "bad domain"},
                    {"type": "IPv4", "indicator": "5.6.7.8", "description": "another bad ip"},
                ],
            }
        ]

        result = extract_ipv4_indicators(pulses)

        assert len(result) == 2
        assert result[0]["ip"] == "1.2.3.4"
        assert result[0]["pulse_name"] == "Test Pulse"
        assert result[1]["ip"] == "5.6.7.8"

    def test_empty_pulses(self):
        assert extract_ipv4_indicators([]) == []

    def test_pulse_with_no_indicators(self):
        pulses = [{"id": "p1", "name": "Empty", "created": "2024-01-01T00:00:00Z", "tags": [], "indicators": []}]
        assert extract_ipv4_indicators(pulses) == []
