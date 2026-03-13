# OTX TAXII (STIX 1.x)

AlienVault OTX can be polled over TAXII 1.x to retrieve STIX 1.x XML bundles. This is a standardized alternative to the JSON REST API.

## Key Details

- Protocol: TAXII 1.x (Discovery + Poll)
- Discovery URL: https://otx.alienvault.com/taxii/discovery
- Poll URL: https://otx.alienvault.com/taxii/poll
- Auth: username = OTX API key, password = anything
- Collections: `user_<your_username>`, `user_AlienVault`, `group_<group_name>`
- Format: STIX 1.x XML (not STIX 2.x JSON)

## Scripts

### Full STIX 1.x Parser (Recommended)

Use `src/fetch_threat_data_otx_taxii_stix.py` for complete STIX 1.x parsing with the official `python-stix` library.

```sh
pip install cabby stix lxml
python src/fetch_threat_data_otx_taxii_stix.py --api-key YOUR_KEY --collection user_yourusername \
  --output data/otx_taxii_stix.json --enrich-geo
```

**Features:**
- Full STIX 1.1.1/1.2 XML parsing via `STIXPackage.from_xml()`
- Extracts IPv4 indicators with metadata (confidence, title, description, indicator ID)
- Optional geolocation enrichment via ip-api.com
- Deduplication by IP address
- Structured JSON output with timestamps

### Legacy Parser

Use `src/fetch_threat_data_otx_taxii.py` for lightweight XML parsing without full STIX object handling.

```sh
pip install cabby lxml requests
python src/fetch_threat_data_otx_taxii.py --api-key YOUR_KEY --collection user_yourusername \
  --output data/otx_taxii.json --enrich-geo
```

## Output Format

The STIX parser produces JSON like:

```json
{
  "fetched_at": "2026-03-12T10:30:00.000000",
  "source": "AlienVault OTX TAXII/STIX 1.x - collection user_sneaky",
  "blocks_parsed": 5,
  "indicators_count": 42,
  "indicators": [
    {
      "ip": "192.0.2.1",
      "indicator_id": "indicator-12345",
      "title": "Malicious IP Indicator",
      "description": "Detected in phishing campaign",
      "confidence": "High",
      "source": "AlienVault OTX",
      "timestamp_label": "2026-03-12T09:00:00Z",
      "country": "United States",
      "city": "San Francisco",
      "lat": 37.7749,
      "lon": -122.4194,
      "org": "Example ISP"
    }
  ]
}
```

## Extending the Parser

To extract additional IOC types, modify `parse_stix_extract_ipv4()`:

```python
from cybox.objects.domain_name_object import DomainNameObject
from cybox.objects.file_object import FileObject

# Domains
if isinstance(obj.properties, DomainNameObject):
    domain = obj.properties.value.value

# Files (MD5, SHA256, etc.)
if isinstance(obj.properties, FileObject):
    md5 = obj.properties.md5 if obj.properties.md5 else None
    sha256 = obj.properties.sha256 if obj.properties.sha256 else None
```

## Notes

- TAXII 2.1 is not supported on OTX as of this writing.
- STIX 1.x does not include geo data by default; you need IP-to-geo enrichment.
- Keep polling volume low and respect rate limits tied to your API key.
- The `stix` package (python-stix) is for STIX 1.x only; use `stix2` for modern STIX 2.x JSON.
- Incremental polling: save `exclusive_end_time` from a run and pass as `--begin-time` for subsequent polls.
