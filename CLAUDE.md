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

## Real-Time Server

FastAPI WebSocket server that tails Cowrie honeypot logs, enriches with geo data, and broadcasts to connected map clients.

```bash
# Start the server (requires cowrie.json log file)
uvicorn src.realtime_server:app --host 0.0.0.0 --port 8000

# Custom H3 resolution and window
uvicorn src.realtime_server:app --host 0.0.0.0 --port 8000 \
  --app-args "--cowrie-log cowrie.json --h3-resolution 7 --window-minutes 30"
```

- **WebSocket at `/ws`** sends two message types: `"attack"` (individual events for arcs) and `"heatmap_update"` (aggregated hex data)
- **Client can send**: `{"type": "refresh"}`, `{"type": "set_viewport", "bounds": {...}}`, `{"type": "set_resolution", "resolution": 8}`
- **`/api/status`** returns buffer size, connection count, aggregation method, and viewport state
- **Frontend**: `src/realtime_map.html` (Leaflet.js + leaflet.heat, dark theme)

## Architecture

- **Data pipeline pattern**: Each `src/fetch_*.py` script follows the same flow: fetch from API -> extract IPv4 indicators -> optional `--enrich-geo` via ip-api.com -> write JSON to `data/`
- **Real-time pipeline**: `realtime_server.py` tails Cowrie log -> `parse_cowrie_line()` -> geo enrich via ip-api.com -> buffer in `recent_points` -> `aggregate_and_broadcast()` aggregates via H3 hexes on a timer
- **Aggregation** (`heatmap_aggregator.py`): Three methods with the same `.aggregate(points)` interface returning `[[lat, lng, intensity], ...]`:
  - `H3Aggregator` (default) — hexagonal binning via Uber H3 (requires `h3>=4.0.0`)
  - `GridAggregator` — simple lat/lon rounding (fallback if h3 not installed)
  - `GeohashAggregator` — geohash-based (requires `geohash2`)
- **Viewport filtering**: Server filters points to client's visible map bounds before aggregation, reducing payload size
- **Two TAXII parsers**: `_otx_taxii.py` uses raw lxml XPath; `_otx_taxii_stix.py` uses the python-stix library for richer STIX 1.x metadata extraction
- **`fetch_threat_data_gnql.py`** is a thin wrapper that imports from `query_greynoise_gnql.py`
- **`src/generate_map.html`**: Standalone Leaflet.js dark-themed map with sample hardcoded data; intended to be connected to live JSON feeds from the scripts
- **Cowrie log parser** (`parse_cowrie_logs.py`): Batch mode — parses cowrie.json, enriches with geo (MaxMind GeoLite2 or ip-api.com), outputs structured JSON
- **Geo enrichment**: All scripts share the same pattern using free ip-api.com with 1.5s sleep between requests for rate limiting

## Key API Dependencies

| Source | Auth | Library |
|--------|------|---------|
| GreyNoise Community | None | `requests` |
| GreyNoise GNQL | Enterprise key | `greynoise` SDK |
| AlienVault OTX | OTX API key | `OTXv2` SDK |
| OTX TAXII | OTX key as username | `cabby` + `stix`/`lxml` |
| IP geolocation | Varies | `requests` (ipapi.co, ipinfo.io, ip-api.com) |
| H3 hexagonal binning | None | `h3` (v4+ API) |
| Real-time server | None | `fastapi` + `uvicorn` + `websockets` |

## Testing

```bash
python -m pytest tests/ -v
```

Tests mock all external API calls. STIX XML parsing tests (`TestExtractIpv4FromStix`) require `lxml` and are skipped if unavailable.

## CI

GitHub Actions workflow at `.github/workflows/ci.yml` runs `pytest` on Python 3.10/3.11/3.12 for pushes and PRs to `main`.

## Notes
- Output JSON goes to `data/` (gitignored)
- API keys go in `.env` (see `.env.example`); never commit credentials
- Rate limiting is handled inline with `time.sleep()` calls; GreyNoise Community is especially strict (6s between requests)
- Personal dotfiles (`.gitconfig`, `.ssh-config`) are gitignored; do not add them back
