# Usage

Use the scripts in `src/` to fetch indicators, enrich them with geo data, and render a simple map demo.

## Quick Examples

### Single IP Lookup
```sh
python src/fetch_threat_data.py --ip 8.8.8.8 --output data/ip_lookup.json
```

### GreyNoise Community Enrichment
```sh
python src/fetch_threat_data_greynoise.py --input ips.txt --output data/greynoise_enriched.json --enrich-geo
```

### GNQL Query (Enterprise Key Required)
```sh
python src/query_greynoise_gnql.py --api-key YOUR_KEY --query "classification:malicious last_seen:>now-7d" \
  --output data/gnql_results.json
```

### OTX TAXII STIX 1.x Pull
```sh
python src/fetch_threat_data_otx_taxii_stix.py --api-key YOUR_KEY --collection user_yourusername \
  --output data/otx_taxii_stix.json --enrich-geo
```

## Map Demo

1. Start a local server.
```sh
python -m http.server 8000
```
2. Open the demo map in a browser.
```text
http://localhost:8000/src/generate_map.html
```

![Threat map demo preview](assets/map-demo.svg)

## Next Steps

1. Replace the sample `attacks` array in `src/generate_map.html` with JSON produced by the fetch scripts.
2. Wire a real-time feed to update markers on an interval (polling or WebSocket).
3. Swap the basemap tiles to match your visual style.
