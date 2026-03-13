"""Tests for fetch_threat_data_otx_taxii.py - TAXII/STIX with lxml parsing."""

import sys
import os
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Check if lxml is genuinely available (not mocked)
try:
    from lxml import etree
    etree.fromstring(b"<test/>")  # verify it actually works
    HAS_LXML = True
except Exception:
    HAS_LXML = False
    # Mock cabby and lxml so the module can be imported
    sys.modules.setdefault("cabby", MagicMock())
    sys.modules.setdefault("lxml", MagicMock())
    sys.modules.setdefault("lxml.etree", MagicMock())

from fetch_threat_data_otx_taxii import extract_ipv4_from_stix, enrich_geo


SAMPLE_STIX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
                   xmlns:cybox="http://cybox.mitre.org/cybox-2"
                   xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2">
  <stix:Indicators>
    <stix:Indicator>
      <stix:Observable>
        <cybox:Object>
          <cybox:Properties>
            <AddressObj:Address category="ipv4-addr">1.2.3.4</AddressObj:Address>
          </cybox:Properties>
        </cybox:Object>
      </stix:Observable>
    </stix:Indicator>
    <stix:Indicator>
      <stix:Observable>
        <cybox:Object>
          <cybox:Properties>
            <AddressObj:Address category="ipv4-addr">5.6.7.8</AddressObj:Address>
          </cybox:Properties>
        </cybox:Object>
      </stix:Observable>
    </stix:Indicator>
  </stix:Indicators>
</stix:STIX_Package>"""

STIX_XML_NO_IPS = """<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
                   xmlns:cybox="http://cybox.mitre.org/cybox-2"
                   xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2">
  <stix:Indicators/>
</stix:STIX_Package>"""


@pytest.mark.skipif(not HAS_LXML, reason="lxml not available")
class TestExtractIpv4FromStix:
    def test_extracts_ips_from_valid_stix(self):
        result = extract_ipv4_from_stix(SAMPLE_STIX_XML)
        assert sorted(result) == ["1.2.3.4", "5.6.7.8"]

    def test_empty_stix_returns_empty(self):
        result = extract_ipv4_from_stix(STIX_XML_NO_IPS)
        assert result == []

    def test_invalid_xml_returns_empty(self):
        result = extract_ipv4_from_stix("not xml at all")
        assert result == []

    def test_empty_string_returns_empty(self):
        result = extract_ipv4_from_stix("")
        assert result == []


class TestEnrichGeo:
    def test_enriches_ips(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "country": "US",
            "city": "New York",
            "lat": 40.71,
            "lon": -74.0,
            "org": "TestOrg",
        }

        with patch("fetch_threat_data_otx_taxii.requests.get", return_value=mock_resp), \
             patch("fetch_threat_data_otx_taxii.time.sleep"):
            result = enrich_geo(["1.2.3.4"])

        assert len(result) == 1
        assert result[0]["ip"] == "1.2.3.4"
        assert result[0]["country"] == "US"

    def test_handles_api_error(self):
        with patch("fetch_threat_data_otx_taxii.requests.get", side_effect=Exception("timeout")), \
             patch("fetch_threat_data_otx_taxii.time.sleep"):
            result = enrich_geo(["1.2.3.4"])

        assert result == []

    def test_deduplicates_ips(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success", "country": "US", "city": "NYC",
            "lat": 40.71, "lon": -74.0, "org": "Org",
        }

        with patch("fetch_threat_data_otx_taxii.requests.get", return_value=mock_resp), \
             patch("fetch_threat_data_otx_taxii.time.sleep"):
            result = enrich_geo(["1.2.3.4", "1.2.3.4", "1.2.3.4"])

        assert len(result) == 1
