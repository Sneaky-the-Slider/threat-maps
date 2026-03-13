#!/usr/bin/env python3
"""
Fetch threat data from various APIs and output as JSON.

Usage:
    python fetch_threat_data.py --ip 8.8.8.8
    python fetch_threat_data.py --file ips.txt
"""

import argparse
import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError

# API endpoints (add your keys in secrets repo)
API_ENDPOINTS = {
    "ipapi": "https://ipapi.co/{ip}/json/",
    "ipinfo": "https://ipinfo.io/{ip}/json?token={token}",
    "abuseipdb": "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
}


def get_ip_info(ip: str, service: str = "ipapi") -> dict:
    """Fetch IP geolocation and threat info."""
    try:
        if service == "ipapi":
            url = API_ENDPOINTS["ipapi"].format(ip=ip)
            req = Request(url, headers={"User-Agent": "threat-maps/1.0"})
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        
        elif service == "ipinfo":
            token = os.environ.get("IPINFO_TOKEN", "")
            url = API_ENDPOINTS["ipinfo"].format(ip=ip, token=token)
            req = Request(url, headers={"User-Agent": "threat-maps/1.0"})
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
    
    except URLError as e:
        return {"error": str(e), "ip": ip}
    
    return {}


def process_file(filepath: str) -> list:
    """Process a file of IPs (one per line)."""
    results = []
    with open(filepath, 'r') as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith('#'):
                info = get_ip_info(ip)
                results.append(info)
    return results


def main():
    parser = argparse.ArgumentParser(description="Fetch threat data for IPs")
    parser.add_argument("--ip", help="Single IP to lookup")
    parser.add_argument("--file", help="File with IPs (one per line)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--service", default="ipapi", choices=["ipapi", "ipinfo"])
    
    args = parser.parse_args()
    
    results = []
    
    if args.ip:
        results = [get_ip_info(args.ip, args.service)]
    elif args.file:
        results = process_file(args.file)
    else:
        parser.print_help()
        sys.exit(1)
    
    output = json.dumps(results, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
