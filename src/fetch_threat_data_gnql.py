#!/usr/bin/env python3
"""
fetch_threat_data_gnql.py - Run a GNQL query with GreyNoise (enterprise key required).

Usage:
    python src/fetch_threat_data_gnql.py --api-key YOUR_KEY --query "classification:malicious last_seen:>now-7d" \
      --output data/gnql_results.json

Requirements:
    pip install requests
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

import requests

GNQL_URL = "https://api.greynoise.io/v3/gnql"
GNQL_DATA_URL = "https://api.greynoise.io/v3/gnql/data"


def gnql_count(api_key, query):
    headers = {"key": api_key}
    resp = requests.get(GNQL_URL, headers=headers, params={"query": query}, timeout=20)
    resp.raise_for_status()
    return resp.json()


def gnql_data(api_key, query, size=1000, offset=0):
    headers = {"key": api_key}
    params = {"query": query, "size": size, "offset": offset}
    resp = requests.get(GNQL_DATA_URL, headers=headers, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Run a GNQL query via GreyNoise API")
    parser.add_argument("--api-key", required=True, help="GreyNoise enterprise API key")
    parser.add_argument("--query", required=True, help="GNQL query string")
    parser.add_argument("--output", default="data/gnql_results.json", help="Output JSON file")
    parser.add_argument("--size", type=int, default=1000, help="Number of results to fetch")
    args = parser.parse_args()

    count_info = gnql_count(args.api_key, args.query)

    data = gnql_data(args.api_key, args.query, size=args.size)

    output = {
        "fetched_at": datetime.utcnow().isoformat(),
        "source": "GreyNoise GNQL",
        "query": args.query,
        "count_info": count_info,
        "data": data,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Saved GNQL results to {args.output}")


if __name__ == "__main__":
    main()
