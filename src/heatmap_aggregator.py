#!/usr/bin/env python3
"""
Real-time heatmap aggregation for threat maps.

Aggregates attack points into grid cells for efficient real-time visualization.
Reduces bandwidth and browser rendering load by grouping nearby points.

Supports:
- Simple grid aggregation (fast, lightweight)
- H3 hexagonal binning (better visual uniformity)
- Geohash binning (string-based keys)

Usage:
    python heatmap_aggregator.py --input data/cowrie_enriched.json --output aggregated.json
    python heatmap_aggregator.py --method h3 --resolution 5 --input data.json --output aggregated.json
"""

import argparse
import json
import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

try:
    import h3
    H3_AVAILABLE = True
except ImportError:
    H3_AVAILABLE = False


class GridAggregator:
    """Simple grid-based aggregation (lat/lon rounding)."""
    
    def __init__(self, resolution: float = 0.05):
        """
        Initialize grid aggregator.
        
        Args:
            resolution: Grid cell size in degrees (0.05 ≈ 5 km at equator)
        """
        self.resolution = resolution
    
    def aggregate(self, points: list[dict]) -> list[list[float]]:
        """
        Aggregate points into grid cells.
        
        Args:
            points: List of dicts with 'lat', 'lon', and optional 'intensity'
            
        Returns:
            List of [lat, lng, intensity] for heatmap rendering
        """
        grid = defaultdict(float)
        
        for point in points:
            lat = point.get('lat') or point.get('latitude')
            lon = point.get('lon') or point.get('longitude')
            
            if lat is None or lon is None:
                continue
            
            # Get intensity (default 1.0, can be weighted by event severity)
            intensity = point.get('intensity', 1.0)
            
            # Round to grid cell center
            rounded_lat = round(lat / self.resolution) * self.resolution
            rounded_lon = round(lon / self.resolution) * self.resolution
            
            grid[(rounded_lat, rounded_lon)] += intensity
        
        # Convert to heatmap format: [[lat, lng, intensity], ...]
        return [[lat, lon, count] for (lat, lon), count in grid.items()]


class H3Aggregator:
    """H3 hexagonal binning for aggregation."""
    
    def __init__(self, resolution: int = 5):
        """
        Initialize H3 aggregator.
        
        Args:
            resolution: H3 resolution (0-15, higher = finer cells)
                       Resolution 5 ≈ 10-20 km cells
        """
        if not H3_AVAILABLE:
            raise ImportError("h3 library not installed. Install with: pip install h3")
        self.resolution = resolution
    
    def aggregate(self, points: list[dict]) -> list[list[float]]:
        """
        Aggregate points into H3 hexagonal cells.
        
        Args:
            points: List of dicts with 'lat', 'lon', and optional 'intensity'
            
        Returns:
            List of [lat, lng, intensity] for heatmap rendering
        """
        hex_grid = defaultdict(float)
        
        for point in points:
            lat = point.get('lat') or point.get('latitude')
            lon = point.get('lon') or point.get('longitude')
            
            if lat is None or lon is None:
                continue
            
            intensity = point.get('intensity', 1.0)
            
            # Get H3 hex ID for this location
            hex_id = h3.latlng_to_cell(lat, lon, self.resolution)
            hex_grid[hex_id] += intensity
        
        # Convert H3 cells to lat/lng centers
        result = []
        for hex_id, intensity in hex_grid.items():
            lat, lon = h3.cell_to_latlng(hex_id)
            result.append([lat, lon, intensity])
        
        return result


class GeohashAggregator:
    """Geohash-based aggregation."""
    
    def __init__(self, precision: int = 5):
        """
        Initialize geohash aggregator.
        
        Args:
            precision: Geohash precision (1-12, higher = finer cells)
                      Precision 5 ≈ 5 km cells
        """
        try:
            import geohash2
            self.geohash = geohash2
        except ImportError:
            raise ImportError("geohash2 library not installed. Install with: pip install geohash2")
        
        self.precision = precision
    
    def aggregate(self, points: list[dict]) -> list[list[float]]:
        """
        Aggregate points into geohash cells.
        
        Args:
            points: List of dicts with 'lat', 'lon', and optional 'intensity'
            
        Returns:
            List of [lat, lng, intensity] for heatmap rendering
        """
        geo_grid = defaultdict(float)
        
        for point in points:
            lat = point.get('lat') or point.get('latitude')
            lon = point.get('lon') or point.get('longitude')
            
            if lat is None or lon is None:
                continue
            
            intensity = point.get('intensity', 1.0)
            
            # Get geohash for this location
            gh = self.geohash.encode(lat, lon, precision=self.precision)
            geo_grid[gh] += intensity
        
        # Convert geohash to lat/lng centers
        result = []
        for gh, intensity in geo_grid.items():
            lat, lon = self.geohash.decode(gh)[:2]
            result.append([lat, lon, intensity])
        
        return result


def load_events(filepath: str) -> list[dict]:
    """Load events from JSON file (supports both array and object with 'events' key)."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Handle both formats: array or object with 'events' key
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and 'events' in data:
        return data['events']
    else:
        raise ValueError("JSON must be an array or object with 'events' key")


def extract_coordinates(events: list[dict]) -> list[dict]:
    """
    Extract lat/lon from various event formats.
    
    Handles:
    - Direct lat/lon fields
    - Nested geo object
    - Cowrie enriched format
    """
    points = []
    
    for event in events:
        point = {}
        
        # Check for direct lat/lon
        if 'lat' in event and 'lon' in event:
            point['lat'] = event['lat']
            point['lon'] = event['lon']
        # Check for nested geo object
        elif 'geo' in event:
            geo = event['geo']
            point['lat'] = geo.get('latitude') or geo.get('lat')
            point['lon'] = geo.get('longitude') or geo.get('lon')
        # Check for location object
        elif 'location' in event:
            loc = event['location']
            point['lat'] = loc.get('lat') or loc.get('latitude')
            point['lon'] = loc.get('lng') or loc.get('lon') or loc.get('longitude')
        
        if point.get('lat') and point.get('lon'):
            # Add intensity based on event type/severity
            event_type = event.get('event_type', event.get('eventid', ''))
            if 'success' in event_type or 'upload' in event_type:
                point['intensity'] = 3.0  # Higher weight for successful attacks
            elif 'failed' in event_type:
                point['intensity'] = 1.0
            else:
                point['intensity'] = event.get('intensity', 1.0)
            
            points.append(point)
    
    return points


def main():
    parser = argparse.ArgumentParser(
        description='Aggregate attack points for efficient heatmap visualization'
    )
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input JSON file with attack events'
    )
    parser.add_argument(
        '--output', '-o',
        required=True,
        help='Output JSON file with aggregated heatmap data'
    )
    parser.add_argument(
        '--method', '-m',
        choices=['grid', 'h3', 'geohash'],
        default='grid',
        help='Aggregation method (default: grid)'
    )
    parser.add_argument(
        '--resolution', '-r',
        type=float,
        default=0.05,
        help='Grid resolution in degrees (for grid method, default: 0.05)'
    )
    parser.add_argument(
        '--h3-resolution',
        type=int,
        default=5,
        help='H3 resolution 0-15 (for h3 method, default: 5)'
    )
    parser.add_argument(
        '--geohash-precision',
        type=int,
        default=5,
        help='Geohash precision 1-12 (for geohash method, default: 5)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print verbose output'
    )
    
    args = parser.parse_args()
    
    # Load events
    if args.verbose:
        print(f"Loading events from: {args.input}")
    events = load_events(args.input)
    
    if args.verbose:
        print(f"Loaded {len(events)} events")
    
    # Extract coordinates
    points = extract_coordinates(events)
    
    if not points:
        print("No valid coordinates found in events.", file=sys.stderr)
        sys.exit(1)
    
    if args.verbose:
        print(f"Extracted {len(points)} points with coordinates")
        print(f"Aggregating using {args.method} method...")
    
    # Aggregate based on method
    if args.method == 'grid':
        aggregator = GridAggregator(resolution=args.resolution)
        aggregated = aggregator.aggregate(points)
    elif args.method == 'h3':
        if not H3_AVAILABLE:
            print("Error: h3 library not installed. Install with: pip install h3", file=sys.stderr)
            sys.exit(1)
        aggregator = H3Aggregator(resolution=args.h3_resolution)
        aggregated = aggregator.aggregate(points)
    elif args.method == 'geohash':
        try:
            aggregator = GeohashAggregator(precision=args.geohash_precision)
            aggregated = aggregator.aggregate(points)
        except ImportError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Build output
    output = {
        'metadata': {
            'method': args.method,
            'resolution': args.resolution if args.method == 'grid' else (
                args.h3_resolution if args.method == 'h3' else args.geohash_precision
            ),
            'input_file': args.input,
            'processed_at': datetime.utcnow().isoformat() + 'Z',
            'raw_points': len(points),
            'aggregated_cells': len(aggregated),
            'reduction_ratio': f"{len(aggregated) / len(points) * 100:.1f}%" if points else "N/A"
        },
        'heatmap_data': aggregated
    }
    
    # Write output
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Aggregated {len(points)} points → {len(aggregated)} cells")
    print(f"Output written to: {args.output}")
    
    if args.verbose:
        print(f"\nReduction: {len(points)} → {len(aggregated)} ({output['metadata']['reduction_ratio']})")


if __name__ == '__main__':
    import sys
    main()
