#!/usr/bin/env python3
"""
Parse Cowrie honeypot JSON logs and enrich with geo-location data.

Cowrie logs attacker sessions in JSON lines format. This script:
1. Parses cowrie.json log entries
2. Extracts source IPs from login events
3. Enriches with geo-location (using MaxMind GeoLite2 or IP API)
4. Outputs structured JSON for threat map visualization

Usage:
    python parse_cowrie_logs.py --input cowrie.json --output enriched.json
    python parse_cowrie_logs.py --input cowrie.json --geoip --output enriched.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


def parse_cowrie_log(filepath: str) -> list:
    """Parse Cowrie JSON log file and extract attack events."""
    events = []
    
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                event = json.loads(line.strip())
                # Filter for login events (failed/successful)
                event_id = event.get('eventid', '')
                if event_id in ['cowrie.login.failed', 'cowrie.login.success', 
                                'cowrie.session.file_upload', 'cowrie.command.failed']:
                    events.append(event)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON on line {line_num}: {e}", file=sys.stderr)
    
    return events


def get_geo_from_ip(ip: str, use_geoip: bool = False, geoip_reader=None) -> dict:
    """Fetch geo-location data for an IP address."""
    geo_data = {
        'ip': ip,
        'latitude': None,
        'longitude': None,
        'country': None,
        'city': None,
        'region': None
    }
    
    # Try local GeoIP database first (faster, offline)
    if use_geoip and geoip_reader:
        try:
            response = geoip_reader.city(ip)
            geo_data['latitude'] = response.location.latitude
            geo_data['longitude'] = response.location.longitude
            geo_data['country'] = response.country.name
            geo_data['city'] = response.city.name
            geo_data['region'] = response.subdivisions.most_specific.name
            return geo_data
        except Exception:
            pass  # Fall through to API
    
    # Fallback to IP API (requires internet, rate limited)
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = Request(url, headers={"User-Agent": "threat-maps/1.0"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                geo_data['latitude'] = data.get('lat')
                geo_data['longitude'] = data.get('lon')
                geo_data['country'] = data.get('country')
                geo_data['city'] = data.get('city')
                geo_data['region'] = data.get('regionName')
    except URLError as e:
        geo_data['geo_error'] = str(e)
    
    return geo_data


def enrich_events(events: list, use_geoip: bool = False, geoip_path: str = None) -> list:
    """Enrich Cowrie events with geo-location data."""
    geoip_reader = None
    
    if use_geoip:
        if not GEOIP_AVAILABLE:
            print("Warning: geoip2 package not installed. Install with: pip install geoip2", 
                  file=sys.stderr)
            use_geoip = False
        elif geoip_path and os.path.exists(geoip_path):
            try:
                geoip_reader = geoip2.database.Reader(geoip_path)
                print(f"Using GeoIP database: {geoip_path}")
            except Exception as e:
                print(f"Warning: Could not load GeoIP database: {e}", file=sys.stderr)
                use_geoip = False
        else:
            print("Warning: GeoIP database file not found. Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", 
                  file=sys.stderr)
            use_geoip = False
    
    enriched = []
    seen_ips = {}  # Cache geo lookups
    
    for event in events:
        src_ip = event.get('src_ip')
        if not src_ip:
            continue
        
        # Cache geo lookups to avoid redundant API calls
        if src_ip in seen_ips:
            geo_data = seen_ips[src_ip].copy()
        else:
            geo_data = get_geo_from_ip(src_ip, use_geoip, geoip_reader)
            seen_ips[src_ip] = geo_data
        
        # Build enriched event
        enriched_event = {
            'timestamp': event.get('timestamp'),
            'event_id': event.get('eventid'),
            'event_type': event.get('eventid', '').split('.')[-1],
            'source_ip': src_ip,
            'geo': geo_data,
            'details': {}
        }
        
        # Extract event-specific details
        if event.get('eventid') in ['cowrie.login.failed', 'cowrie.login.success']:
            enriched_event['details'] = {
                'username': event.get('username', ''),
                'password': event.get('password', ''),
                'success': event.get('eventid') == 'cowrie.login.success'
            }
        elif event.get('eventid') == 'cowrie.session.file_upload':
            enriched_event['details'] = {
                'filename': event.get('filename', ''),
                'shasum': event.get('shasum', '')
            }
        elif event.get('eventid') == 'cowrie.command.failed':
            enriched_event['details'] = {
                'command': event.get('input', '')
            }
        
        enriched.append(enriched_event)
    
    return enriched


def main():
    parser = argparse.ArgumentParser(
        description='Parse and enrich Cowrie honeypot logs for threat mapping'
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to Cowrie JSON log file (cowrie.json)'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Path to output enriched JSON file'
    )
    parser.add_argument(
        '--geoip',
        action='store_true',
        help='Use local GeoIP database (requires geoip2 package and GeoLite2-City.mmdb)'
    )
    parser.add_argument(
        '--geoip-db',
        default='GeoLite2-City.mmdb',
        help='Path to GeoLite2-City.mmdb database (default: GeoLite2-City.mmdb)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    # Check input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    # Parse Cowrie logs
    if args.verbose:
        print(f"Parsing Cowrie log: {args.input}")
    events = parse_cowrie_log(args.input)
    
    if not events:
        print("No relevant events found in log file.", file=sys.stderr)
        sys.exit(0)
    
    if args.verbose:
        print(f"Found {len(events)} attack events")
        print("Enriching with geo-location data...")
    
    # Enrich with geo data
    enriched = enrich_events(events, args.geoip, args.geoip_db)
    
    # Build output
    output = {
        'metadata': {
            'source': 'Cowrie honeypot logs',
            'input_file': args.input,
            'processed_at': datetime.utcnow().isoformat() + 'Z',
            'total_events': len(enriched),
            'unique_ips': len(set(e['source_ip'] for e in enriched))
        },
        'events': enriched
    }
    
    # Write output
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Enriched {len(enriched)} events written to: {args.output}")
    
    # Print summary
    event_counts = {}
    for e in enriched:
        event_type = e['event_type']
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    
    print("\nEvent breakdown:")
    for event_type, count in sorted(event_counts.items()):
        print(f"  {event_type}: {count}")


if __name__ == '__main__':
    main()
