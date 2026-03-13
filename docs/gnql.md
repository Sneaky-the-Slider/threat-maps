# GNQL (GreyNoise Query Language)

GNQL is GreyNoise's query language for searching internet-wide scanning activity and related intelligence. It is similar to Lucene syntax and is used in the GreyNoise Visualizer and enterprise API endpoints.

## Important Notes

- Community (free) API supports single-IP lookups only. GNQL requires a paid or enterprise key.
- Query scope typically focuses on recent observations; consult GreyNoise docs for exact data windows.

## Common Fields

- `classification` (benign, suspicious, malicious)
- `last_seen` (date / range)
- `tags`
- `metadata.organization`
- `metadata.asn`
- `metadata.country`
- `cve`
- `actor`
- `raw_data.scan.port`
- `raw_data.http.user_agent`

## Syntax Basics

- `field:value` (exact match)
- `field:"phrase with spaces"`
- `field:value1 OR field:value2`
- `field:value AND field:value` (space implies AND)
- `NOT field:value` or `-field:value`
- `field:*wildcard*`
- `field:>value`, `field:<value`, `field:[start TO end]`
- Grouping with parentheses

## Example Queries

- `classification:malicious last_seen:>now-1d`
- `tags:Mirai* last_seen:>now-7d`
- `cve:"CVE-2021-44228" last_seen:>now-7d`
- `metadata.country:CN tags:*Brute* last_seen:>now-3d`
- `tags:*Scanner* classification:malicious`

## SDK Script

Use the SDK-based GNQL runner:

```sh
pip install greynoise
python src/query_greynoise_gnql.py --api-key YOUR_KEY --query "classification:malicious last_seen:>now-7d" \
  --output data/gnql_results.json
```
