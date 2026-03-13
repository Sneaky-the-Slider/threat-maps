"""Tests for query_greynoise_gnql.py - GreyNoise GNQL SDK queries."""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Mock greynoise SDK before importing
mock_greynoise = MagicMock()
sys.modules["greynoise"] = mock_greynoise
sys.modules["greynoise.exceptions"] = MagicMock()

from query_greynoise_gnql import run_gnql_query, enrich_geo_simple


class TestRunGnqlQuery:
    def test_single_page_complete(self):
        session = MagicMock()
        session.query.return_value = {
            "data": [{"ip": "1.2.3.4", "noise": True}],
            "request_metadata": {"count": 1, "complete": True, "scroll": None},
        }

        result = run_gnql_query(session, "classification:malicious")
        assert len(result) == 1
        assert result[0]["ip"] == "1.2.3.4"

    def test_pagination_with_fetch_all(self):
        session = MagicMock()
        session.query.side_effect = [
            {
                "data": [{"ip": f"1.2.3.{i}"} for i in range(3)],
                "request_metadata": {"count": 5, "complete": False, "scroll": "abc123"},
            },
            {
                "data": [{"ip": f"5.6.7.{i}"} for i in range(2)],
                "request_metadata": {"count": 5, "complete": True, "scroll": None},
            },
        ]

        with patch("query_greynoise_gnql.time.sleep"):
            result = run_gnql_query(session, "classification:malicious", fetch_all=True)

        assert len(result) == 5

    def test_stops_after_first_page_without_fetch_all(self):
        session = MagicMock()
        session.query.return_value = {
            "data": [{"ip": "1.2.3.4"}],
            "request_metadata": {"count": 100, "complete": False, "scroll": "abc"},
        }

        result = run_gnql_query(session, "test", fetch_all=False)
        assert len(result) == 1
        assert session.query.call_count == 1

    def test_max_results_cap(self):
        session = MagicMock()
        session.query.return_value = {
            "data": [{"ip": f"1.2.3.{i}"} for i in range(10)],
            "request_metadata": {"count": 10, "complete": True},
        }

        result = run_gnql_query(session, "test", max_results=3)
        assert len(result) == 3

    def test_empty_results(self):
        session = MagicMock()
        session.query.return_value = {
            "data": [],
            "request_metadata": {"count": 0, "complete": True},
        }

        result = run_gnql_query(session, "nothing:here")
        assert result == []

    def test_auth_error_raises(self):
        RequestFailure = type("RequestFailure", (Exception,), {})
        session = MagicMock()
        session.query.side_effect = RequestFailure("401 Unauthorized")

        with patch("query_greynoise_gnql.RequestFailure", RequestFailure):
            with pytest.raises(ValueError, match="Invalid or insufficient"):
                run_gnql_query(session, "test")


class TestEnrichGeoSimple:
    def test_adds_country_code_from_metadata(self):
        records = [
            {"ip": "1.2.3.4", "metadata": {"country": "DE"}},
            {"ip": "5.6.7.8", "metadata": {"country": "US"}},
        ]

        result = enrich_geo_simple(records)
        assert result[0]["country_code"] == "DE"
        assert result[1]["country_code"] == "US"

    def test_skips_when_no_country(self):
        records = [{"ip": "1.2.3.4", "metadata": {}}]
        result = enrich_geo_simple(records)
        assert "country_code" not in result[0]

    def test_handles_missing_metadata(self):
        records = [{"ip": "1.2.3.4"}]
        result = enrich_geo_simple(records)
        assert "country_code" not in result[0]
