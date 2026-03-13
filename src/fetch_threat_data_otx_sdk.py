#!/usr/bin/env python3
"""
fetch_threat_data_otx_sdk.py - AlienVault OTX integration using official Python SDK (OTXv2)
for threat-maps repo. Fetches subscribed pulses → extracts IPs → optional geo enrichment.

Usage:
    python src/fetch_threat_data_otx_sdk.py --api-key YOUR_OTX_KEY [--days 7] [--output data/otx_subscribed.json] [--enrich-geo]

Features:
- Uses OTXv2 SDK for clean pagination & auth
- Focuses on IPv4 indicators (best for geo-mapping)
- Filters recent activity (approximate via pulse created/modified)
- Rate-limit friendly

Requirements:
    pip install OTXv2
"""

import argparse
import json
from datetime import datetime, timedelta
import time
import os

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

# Optional geo enrichment (free, rate-limited)
GEOIP_API = "http://ip-api.com/json/{}?fields=status,message,country,city,lat,lon,query,org"


def fetch_subscribed_pulses(otx, max_pulses=50, days_back=7):
    """
    Fetch your subscribed pulses (paginated via SDK).
    Filters to recent ones (created or modified in last days_back).
    """
    cutoff = datetime.utcnow() - timedelta(days=days_back)
    pulses = []
    page = 1

    print(f"Fetching subscribed pulses (last {days_back} days)...")

    while True:
        try:
            response = otx.get_subscribed(page=page, limit=20)
            new_pulses = response.get('results', [])

            if not new_pulses:
                break

            recent = []
            for p in new_pulses:
                created = datetime.fromisoformat(p['created'].replace('Z', '+00:00'))
                modified = datetime.fromisoformat(p['modified'].replace('Z', '+00:00')) if p.get('modified') else created
                if created >= cutoff or modified >= cutoff:
                    recent.append(p)

            pulses.extend(recent)
            print(f"Page {page}: {len(recent)} recent pulses (total: {len(pulses)})")

            if len(new_pulses) < 20 or len(pulses) >= max_pulses:
                break

            page += 1
            time.sleep(1.2)

        except Exception as e:
            print(f"Error fetching page {page}: {e}")
            break

    return pulses[:max_pulses]


def extract_ipv4_indicators(pulses):
    """Extract IPv4 indicators + metadata from pulses."""
    indicators = []
    for pulse in pulses:
        pulse_id = pulse['id']
        name = pulse['name']
        created = pulse['created']
        tags = pulse.get('tags', [])
        for ind in pulse.get('indicators', []):
            if ind['type'] == IndicatorTypes.IPv4:
                indicators.append({
                    "ip": ind['indicator'],
                    "pulse_id": pulse_id,
                    "pulse_name": name,
                    "created": created,
                    "tags": tags,
                    "description": ind.get('description', ''),
                })
    return indicators


def enrich_geo(indicators):
    """Add lat/lon/country using free ip-api.com"""
    import requests
    for item in indicators:
        ip = item["ip"]
        try:
            resp = requests.get(GEOIP_API.format(ip), timeout=8)
            if resp.status_code == 200:
                geo = resp.json()
                if geo.get("status") == "success":
                    item.update({
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                        "org": geo.get("org"),
                    })
                    print(f"Enriched {ip} → {item.get('country')} ({item.get('lat')},{item.get('lon')})")
                else:
                    item["geo_error"] = geo.get("message")
        except Exception as e:
            item["geo_error"] = str(e)
        time.sleep(1.5)
    return indicators


def main():
    parser = argparse.ArgumentParser(description="Fetch AlienVault OTX subscribed pulses via SDK")
    parser.add_argument("--api-key", required=True, help="OTX API key")
    parser.add_argument("--days", type=int, default=7, help="Filter recent pulses (days back)")
    parser.add_argument("--max-pulses", type=int, default=50, help="Max pulses to process")
    parser.add_argument("--output", default="data/otx_subscribed.json", help="Output JSON")
    parser.add_argument("--enrich-geo", action="store_true", help="Add geolocation")
    args = parser.parse_args()

    otx = OTXv2(args.api_key)

    pulses = fetch_subscribed_pulses(otx, max_pulses=args.max_pulses, days_back=args.days)

    if not pulses:
        print("No recent subscribed pulses found.")
        return

    print(f"Extracting IPv4 indicators from {len(pulses)} pulses...")
    indicators = extract_ipv4_indicators(pulses)

    if args.enrich_geo:
        print("Enriching with geolocation...")
        indicators = enrich_geo(indicators)

    output_data = {
        "fetched_at": datetime.utcnow().isoformat(),
        "source": "AlienVault OTX (subscribed pulses via OTXv2 SDK)",
        "pulses_count": len(pulses),
        "indicators_count": len(indicators),
        "indicators": indicators
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(indicators)} indicators to {args.output}")
    print("Ready for mapping: Use lat/lon or country for Leaflet/Mapbox plots")


if __name__ == "__main__":
    main()
