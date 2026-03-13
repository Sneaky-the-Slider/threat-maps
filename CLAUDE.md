# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Threat Maps is a collection of Python scripts that fetch threat intelligence data from various APIs (IP geolocation, GreyNoise, AlienVault OTX) and a Leaflet.js-based HTML map for visualizing geo-located cyber threats. All scripts output JSON to `data/` for consumption by the map frontend.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env  # Fill in API keys
```

## Running Scripts

All Python scripts are in `src/` and run standalone via CLI with argparse:

```bash
# Basic IP geolocation lookup
python src/fetch_threat_data.py --ip 8.8.8.8 --service ipapi

# GreyNoise Community API (no key needed)
python src/fetch_threat_data_greynoise.py --input ips.txt --output data/greynoise_enriched.json --enrich-geo

# GreyNoise GNQL (Enterprise key required)
python src/query_greynoise_gnql.py --api-key KEY --query "classification:malicious last_seen:>now-7d" --output data/gnql_results.json --fetch-all

# AlienVault OTX via SDK
python src/fetch_threat_data_otx_sdk.py --api-key KEY --days 7 --output data/otx_subscribed.json --enrich-geo

# OTX via TAXII/STIX (Cabby + lxml)
python src/fetch_threat_data_otx_taxii.py --api-key KEY --collection user_sneaky --enrich-geo

# OTX via TAXII/STIX (python-stix parser, richer metadata)
python src/fetch_threat_data_otx_taxii_stix.py --api-key KEY --collection user_sneaky --enrich-geo
```

## Architecture

- **Data pipeline pattern**: Each `src/fetch_*.py` script follows the same flow: fetch from API -> extract IPv4 indicators -> optional `--enrich-geo` via ip-api.com -> write JSON to `data/`
- **Two TAXII parsers**: `_otx_taxii.py` uses raw lxml XPath; `_otx_taxii_stix.py` uses the python-stix library for richer STIX 1.x metadata extraction
- **`fetch_threat_data_gnql.py`** is a thin wrapper that imports from `query_greynoise_gnql.py`
- **`src/generate_map.html`**: Standalone Leaflet.js dark-themed map with sample hardcoded data; intended to be connected to live JSON feeds from the scripts
- **Geo enrichment**: All scripts share the same pattern using free ip-api.com with 1.5s sleep between requests for rate limiting

## Key API Dependencies

| Source | Auth | Library |
|--------|------|---------|
| GreyNoise Community | None | `requests` |
| GreyNoise GNQL | Enterprise key | `greynoise` SDK |
| AlienVault OTX | OTX API key | `OTXv2` SDK |
| OTX TAXII | OTX key as username | `cabby` + `stix`/`lxml` |
| IP geolocation | Varies | `requests` (ipapi.co, ipinfo.io, ip-api.com) |

## Notes

- No test suite exists yet
- Output JSON goes to `data/` (gitignored)
- API keys go in `.env` (see `.env.example`); never commit credentials
- Rate limiting is handled inline with `time.sleep()` calls; GreyNoise Community is especially strict (6s between requests)
