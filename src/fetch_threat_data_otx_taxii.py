#!/usr/bin/env python3
"""
fetch_threat_data_otx_taxii.py - AlienVault OTX TAXII/STIX integration using Cabby.
Polls a collection -> parses STIX -> extracts IPv4 indicators.

Usage:
    python src/fetch_threat_data_otx_taxii.py --api-key YOUR_OTX_KEY \
      --collection user_yourusername [--output data/otx_taxii.json] [--enrich-geo]

Requirements:
    pip install cabby lxml requests
"""

import argparse
import json
import os
import time
from datetime import datetime

from cabby import create_client
from lxml import etree
import requests

# Optional geo
GEOIP_API = "http://ip-api.com/json/{}?fields=status,message,country,city,lat,lon,query,org"


def poll_otx_collection(client, collection_name, begin_time=None, count=50):
    """
    Poll the specified collection for content blocks.
    Returns list of (content_block, timestamp) tuples.
    """
    content_blocks = []
    more = True
    exclusive_begin_ts = begin_time

    while more:
        try:
            result = client.poll(
                collection_name=collection_name,
                begin_time=exclusive_begin_ts,
                end_time=None,
                count=count,
            )

            for block in result.content_blocks:
                content_blocks.append((block.content, block.timestamp_label))

            exclusive_begin_ts = result.more and result.exclusive_end_time or None
            more = result.more

            print(f"Fetched {len(result.content_blocks)} blocks (more={more})")
            time.sleep(2)

        except Exception as e:
            print(f"Poll error: {e}")
            break

    return content_blocks


def extract_ipv4_from_stix(stix_xml_str):
    """Basic STIX 1.x XML parsing to pull IPv4 indicators."""
    indicators = []
    try:
        root = etree.fromstring(stix_xml_str.encode("utf-8"))
        ns = {
            "cybox": "http://cybox.mitre.org/cybox-2",
            "AddressObj": "http://cybox.mitre.org/objects#AddressObject-2",
        }
        for addr in root.xpath(
            '//cybox:Object/cybox:Properties/AddressObj:Address[@category="ipv4-addr"]',
            namespaces=ns,
        ):
            ip = (addr.text or "").strip()
            if ip:
                indicators.append(ip)
    except Exception as e:
        print(f"STIX parse error: {e}")
    return indicators


def enrich_geo(indicators):
    enriched = []
    for ip in set(indicators):
        try:
            resp = requests.get(GEOIP_API.format(ip), timeout=8)
            if resp.status_code == 200:
                geo = resp.json()
                if geo.get("status") == "success":
                    enriched.append(
                        {
                            "ip": ip,
                            "country": geo.get("country"),
                            "city": geo.get("city"),
                            "lat": geo.get("lat"),
                            "lon": geo.get("lon"),
                            "org": geo.get("org"),
                        }
                    )
                    print(f"Enriched {ip} -> {geo.get('country')}")
        except Exception as e:
            print(f"Geo error for {ip}: {e}")
        time.sleep(1.5)
    return enriched


def main():
    parser = argparse.ArgumentParser(description="Fetch OTX via TAXII/STIX using Cabby")
    parser.add_argument("--api-key", required=True, help="OTX API key (used as username)")
    parser.add_argument(
        "--collection",
        required=True,
        help="Collection name, e.g. user_yourusername or user_AlienVault",
    )
    parser.add_argument("--output", default="data/otx_taxii.json", help="Output JSON")
    parser.add_argument("--enrich-geo", action="store_true", help="Add geolocation")
    parser.add_argument(
        "--discovery-path",
        default="/taxii/discovery",
        help="OTX TAXII discovery path (default: /taxii/discovery)",
    )
    args = parser.parse_args()

    client = create_client("otx.alienvault.com", use_https=True, discovery_path=args.discovery_path)
    client.set_auth(username=args.api_key, password="x", jwt_auth_url=None)

    print(f"Polling collection: {args.collection}")
    blocks = poll_otx_collection(client, args.collection)

    all_ips = []
    for content, _ts in blocks:
        all_ips.extend(extract_ipv4_from_stix(content))

    indicators = [{"ip": ip} for ip in sorted(set(all_ips))]

    if args.enrich_geo:
        print("Enriching IPs...")
        indicators = enrich_geo([i["ip"] for i in indicators])

    output_data = {
        "fetched_at": datetime.utcnow().isoformat(),
        "source": f"AlienVault OTX TAXII - collection {args.collection}",
        "indicators_count": len(indicators),
        "indicators": indicators,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Saved {len(indicators)} unique IPs to {args.output}")


if __name__ == "__main__":
    main()
