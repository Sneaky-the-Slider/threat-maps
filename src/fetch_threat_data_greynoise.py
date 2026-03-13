#!/usr/bin/env python3
"""
fetch_threat_data_greynoise.py - Query GreyNoise Community API for IP context.

Focus: Enrich a list of suspicious IPs -> determine if real threat vs background noise.

Usage:
    python src/fetch_threat_data_greynoise.py --input ips.txt --output data/greynoise_enriched.json

Requirements:
    pip install requests
"""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path

import requests

# ---------------- Configuration ----------------
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{}"
GEOIP_API = "http://ip-api.com/json/{}?fields=status,message,country,city,lat,lon,query,org,isp"

# Rate limit safety (community tier is strict; be conservative)
SLEEP_BETWEEN = 6
MAX_RETRIES = 3

# ------------------------------------------------


def query_greynoise(ip):
    """Query single IP via GreyNoise Community API (no auth key needed)."""
    url = GREYNOISE_URL.format(ip)
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                print(f"Rate limit hit (429) for {ip} - sleeping longer...")
                time.sleep(60 * (attempt + 1))
                continue
            if resp.status_code == 404:
                return {"ip": ip, "noise": False, "riot": False, "message": "Not found"}
            print(f"Error {resp.status_code} for {ip}: {resp.text}")
            return {"ip": ip, "error": resp.text}
        except Exception as e:
            print(f"Request failed for {ip}: {e}")
            time.sleep(5)
    return {"ip": ip, "error": "Max retries exceeded"}


def enrich_with_geo(item):
    """Add lat/lon using free ip-api.com."""
    ip = item["ip"]
    try:
        resp = requests.get(GEOIP_API.format(ip), timeout=8)
        if resp.status_code == 200:
            geo = resp.json()
            if geo.get("status") == "success":
                item.update(
                    {
                        "country": geo.get("country"),
                        "city": geo.get("city"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                        "org": geo.get("org") or geo.get("isp"),
                    }
                )
                print(
                    f"Enriched {ip} -> {item.get('country')} ({item.get('lat')},{item.get('lon')})"
                )
            else:
                item["geo_error"] = geo.get("message", "Unknown")
    except Exception as e:
        item["geo_error"] = str(e)
    time.sleep(1.5)
    return item


def main():
    parser = argparse.ArgumentParser(description="Enrich IPs with GreyNoise Community API")
    parser.add_argument("--input", required=True, help="File with one IP per line (or comma-separated)")
    parser.add_argument("--output", default="data/greynoise_enriched.json", help="Output JSON file")
    parser.add_argument("--enrich-geo", action="store_true", help="Add geolocation")
    args = parser.parse_args()

    raw = Path(args.input).read_text(encoding="utf-8").strip()
    ips = [ip.strip() for ip in raw.replace(",", "\n").splitlines() if ip.strip()]

    print(f"Processing {len(ips)} IPs via GreyNoise Community API...")

    results = []
    for i, ip in enumerate(ips, 1):
        print(f"[{i}/{len(ips)}] Querying {ip}...")
        gn_data = query_greynoise(ip)
        enriched = {"ip": ip, **gn_data}

        if args.enrich_geo and "lat" not in enriched:
            enrich_with_geo(enriched)

        results.append(enriched)
        time.sleep(SLEEP_BETWEEN)

    output_data = {
        "fetched_at": datetime.utcnow().isoformat(),
        "source": "GreyNoise Community API",
        "count": len(results),
        "indicators": results,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(results)} enriched records to {args.output}")
    print("Tip: Filter where 'noise': true and 'classification' != 'riot' for real threats")


if __name__ == "__main__":
    main()
