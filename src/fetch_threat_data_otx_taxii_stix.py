#!/usr/bin/env python3
"""
fetch_threat_data_otx_taxii_stix.py - OTX TAXII integration with full STIX 1.x parsing using python-stix
for threat-maps repo.

Polls OTX collection → parses STIX XML blocks → extracts IPv4 indicators + metadata.

Usage:
    python src/fetch_threat_data_otx_taxii_stix.py --api-key YOUR_OTX_KEY --collection user_sneaky [--output data/otx_taxii_stix.json] [--enrich-geo]

Requirements:
    pip install cabby stix lxml  # stix = python-stix for STIX 1.x
"""

import argparse
import json
from datetime import datetime
import time
import os

from cabby import create_client
from stix.core import STIXPackage  # Core parser for STIX 1.x
from cybox.objects.address_object import Address  # For IPv4 extraction

# Optional geo enrichment
GEOIP_API = "http://ip-api.com/json/{}?fields=status,message,country,city,lat,lon,query,org"


def poll_otx_collection(client, collection_name, begin_time=None):
    """Poll TAXII collection and return list of (stix_content_str, timestamp)"""
    content_blocks = []
    more = True
    exclusive_begin_ts = begin_time

    while more:
        try:
            result = client.poll(
                collection_name=collection_name,
                begin_time=exclusive_begin_ts,
                end_time=None,
                count=30  # Smaller batches for STIX parsing safety
            )

            for block in result.content_blocks:
                # block.content is bytes → decode to str
                content_str = block.content.decode('utf-8') if isinstance(block.content, bytes) else block.content
                content_blocks.append((content_str, block.timestamp_label))

            exclusive_begin_ts = result.more and result.exclusive_end_time or None
            more = result.more

            print(f"Fetched {len(result.content_blocks)} STIX blocks (more={more})")
            time.sleep(2.5)  # Conservative rate limiting

        except Exception as e:
            print(f"Poll error: {e}")
            break

    return content_blocks


def parse_stix_extract_ipv4(stix_xml_str):
    """
    Parse full STIX 1.x package and extract IPv4 indicators with context.
    Returns list of dicts with ip + metadata.
    """
    indicators = []
    try:
        # Parse the STIX XML string into a STIXPackage object
        package = STIXPackage.from_xml(stix_xml_str)

        # Extract from Indicators (common in OTX pulses)
        if package.indicators:
            for indicator in package.indicators:
                if not indicator.observables:
                    continue

                for observable in indicator.observables:
                    obj = observable.object_  # CybOX Object
                    if obj and obj.properties and isinstance(obj.properties, Address):
                        if obj.properties.category == "ipv4-addr":
                            ip = obj.properties.address_value.value
                            indicators.append({
                                "ip": str(ip).strip(),
                                "indicator_id": indicator.idref or indicator.id_,
                                "title": indicator.title or "Unnamed Indicator",
                                "description": indicator.description or "",
                                "confidence": str(indicator.confidence.value) if indicator.confidence else None,
                                "source": "AlienVault OTX",
                                # Add more: e.g., related TTPs, timestamps, etc.
                            })

        # Optional: Check other places (e.g., related observables, incidents)
        # ... extend if needed for domains, files, etc.

    except Exception as e:
        print(f"STIX parsing error: {e}")
        # Fallback: could log raw XML or partial parse

    return indicators


def enrich_geo(indicators):
    """Enrich extracted IPs with free geo data"""
    import requests
    enriched = []
    for item in indicators:
        ip = item.get("ip")
        if not ip:
            continue
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
                    print(f"Enriched {ip} → {geo.get('country')} ({geo.get('lat')},{geo.get('lon')})")
        except Exception as e:
            item["geo_error"] = str(e)
        time.sleep(1.5)
        enriched.append(item)
    return enriched


def main():
    parser = argparse.ArgumentParser(description="Fetch & parse OTX TAXII/STIX 1.x with python-stix")
    parser.add_argument("--api-key", required=True, help="OTX API key (username)")
    parser.add_argument("--collection", required=True, help="e.g. user_sneaky or user_AlienVault")
    parser.add_argument("--output", default="data/otx_taxii_parsed.json", help="Output JSON")
    parser.add_argument("--enrich-geo", action="store_true", help="Add geolocation")
    args = parser.parse_args()

    # TAXII Client setup
    client = create_client('otx.alienvault.com', use_https=True, discovery_path='/taxii-discovery-service')
    client.set_auth(username=args.api_key, password="x")  # Password ignored

    print(f"Polling OTX collection: {args.collection}")
    blocks = poll_otx_collection(client, args.collection)

    all_indicators = []
    for stix_content, ts in blocks:
        print(f"Parsing STIX block from {ts}...")
        ips_from_block = parse_stix_extract_ipv4(stix_content)
        for ind in ips_from_block:
            ind["timestamp_label"] = str(ts)
        all_indicators.extend(ips_from_block)

    # Dedup by IP (simple; could use more sophisticated logic)
    seen_ips = set()
    unique_indicators = [ind for ind in all_indicators if ind["ip"] not in seen_ips and not seen_ips.add(ind["ip"])]

    if args.enrich_geo:
        print("Enriching extracted IPs with geolocation...")
        unique_indicators = enrich_geo(unique_indicators)

    output_data = {
        "fetched_at": datetime.utcnow().isoformat(),
        "source": f"AlienVault OTX TAXII/STIX 1.x - collection {args.collection}",
        "blocks_parsed": len(blocks),
        "indicators_count": len(unique_indicators),
        "indicators": unique_indicators
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Saved {len(unique_indicators)} unique IPv4 indicators to {args.output}")
    if unique_indicators:
        print("Sample (first 3):")
        for ind in unique_indicators[:3]:
            print(f"  - {ind['ip']} ({ind.get('country', 'unknown')}) - {ind.get('title', 'no title')}")


if __name__ == "__main__":
    main()
