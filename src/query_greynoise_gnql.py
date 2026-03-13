#!/usr/bin/env python3
"""
query_greynoise_gnql.py - Enhanced script using GreyNoise Python SDK to run GNQL queries
with full pagination support.

Usage:
    python src/query_greynoise_gnql.py --api-key YOUR_KEY --query "classification:malicious last_seen:>now-7d" \
        --output data/gnql_malicious.json --fetch-all [--page-size 1000] [--max-results 50000]

Requirements:
    pip install greynoise
    (Enterprise/Pro API key required for GNQL)
"""

import argparse
import json
import time
from datetime import datetime

from greynoise import GreyNoise
from greynoise.exceptions import RequestFailure


def run_gnql_query(session, query_str, page_size=1000, fetch_all=False, max_results=None, exclude_raw=True):
    """
    Execute a GNQL query with full pagination via scroll.
    Fetches all results if fetch_all=True, else limits to first page.
    Returns list of matching records (up to max_results).
    """
    results = []
    scroll_id = None
    total_fetched = 0
    total_expected = None

    while True:
        try:
            params = {
                "query": query_str,
                "size": min(page_size, 10000),
                "exclude_raw": exclude_raw,
            }
            if scroll_id:
                params["scroll"] = scroll_id

            response = session.query(**params)

            data = response.get("data", [])
            metadata = response.get("request_metadata", {})

            if total_expected is None:
                total_expected = metadata.get("count", 0)
                mode = "all" if fetch_all else "first page"
                print(f"Total matching indicators: {total_expected:,} (fetching {mode})")

            results.extend(data)
            total_fetched += len(data)
            print(f"Fetched page (size {len(data):,}): cumulative {total_fetched:,} / {total_expected:,}")

            scroll_id = metadata.get("scroll")
            complete = metadata.get("complete", True)

            if complete or not scroll_id:
                print("Query complete - no more pages.")
                break

            if not fetch_all:
                print("Stopping after first page (use --fetch-all for everything).")
                break

            if max_results and total_fetched >= max_results:
                print(f"Hit max_results cap ({max_results:,}) - stopping.")
                break

            time.sleep(1.5)

        except RequestFailure as e:
            print(f"API error: {e}")
            if "429" in str(e):
                print("Rate limit hit - sleeping 30s and retrying...")
                time.sleep(30)
                continue
            if "401" in str(e) or "403" in str(e):
                raise ValueError("Invalid or insufficient API key/permissions for GNQL")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break

    if max_results and len(results) > max_results:
        results = results[:max_results]

    return results


def enrich_geo_simple(records):
    """Optional: Add country_code from GreyNoise metadata."""
    for rec in records:
        meta = rec.get("metadata", {})
        if meta.get("country"):
            rec["country_code"] = meta.get("country")
    return records


def main():
    parser = argparse.ArgumentParser(description="Query GreyNoise with GNQL + full pagination")
    parser.add_argument("--api-key", required=True, help="GreyNoise API key (Enterprise/Pro required)")
    parser.add_argument(
        "--query",
        default="classification:malicious last_seen:>now-7d tags:*",
        help="GNQL query string",
    )
    parser.add_argument("--page-size", type=int, default=1000, help="Results per page (max 10000)")
    parser.add_argument("--fetch-all", action="store_true", help="Fetch ALL matching results")
    parser.add_argument("--max-results", type=int, default=None, help="Cap total results")
    parser.add_argument("--output", default="data/gnql_results.json", help="Output JSON file")
    parser.add_argument("--no-enrich", action="store_true", help="Skip simple country enrichment")
    args = parser.parse_args()

    print(
        f"Running GNQL query: {args.query} (fetch_all={args.fetch_all}, page_size={args.page_size:,})"
    )

    try:
        session = GreyNoise(api_key=args.api_key, integration_name="threat-maps-gnql-sample-v2")

        indicators = run_gnql_query(
            session,
            args.query,
            page_size=args.page_size,
            fetch_all=args.fetch_all,
            max_results=args.max_results,
        )

        if not indicators:
            print("No results found for this query.")
            return

        if not args.no_enrich:
            print("Adding basic country enrichment...")
            indicators = enrich_geo_simple(indicators)

        output_data = {
            "fetched_at": datetime.utcnow().isoformat(),
            "query": args.query,
            "count": len(indicators),
            "source": "GreyNoise GNQL (via Python SDK)",
            "indicators": indicators,
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        print(f"Saved {len(indicators):,} indicators to {args.output}")
        print("Next: For very large JSON, consider processing in chunks for mapping")

        tags_seen = set()
        countries_seen = set()
        for ind in indicators[:20]:
            tags_seen.update(ind.get("tags", []))
            countries_seen.add(ind.get("metadata", {}).get("country", "Unknown"))

        print("\nQuick summary (first 20 results sample):")
        print(f"  Unique tags: {', '.join(sorted(tags_seen)) or 'None'}")
        print(f"  Countries: {', '.join(sorted(countries_seen)) or 'None'}")

    except ValueError as ve:
        print(f"Setup error: {ve}")
    except Exception as e:
        print(f"Failed: {e}")


if __name__ == "__main__":
    main()
