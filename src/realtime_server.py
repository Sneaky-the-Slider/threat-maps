#!/usr/bin/env python3
"""
FastAPI backend for real-time threat map with heatmap aggregation.

Streams Cowrie honeypot logs via WebSocket with server-side aggregation
to reduce bandwidth and improve browser performance.

Features:
- Tails Cowrie JSON log file in real-time
- Aggregates points into H3 hexagonal cells (falls back to grid if h3 not installed)
- Broadcasts via WebSocket: individual attacks (for arcs) + aggregated heatmap
- Sliding window keeps only recent points (configurable duration)
- Safety cap on buffer size to prevent memory growth

Usage:
    uvicorn realtime_server:app --host 0.0.0.0 --port 8000

    # With custom H3 resolution
    uvicorn realtime_server:app --host 0.0.0.0 --port 8000 \
      --app-args "--cowrie-log cowrie.json --h3-resolution 7 --window-minutes 30"
"""

import argparse
import asyncio
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Aggregation imports
from heatmap_aggregator import GridAggregator, H3Aggregator, extract_coordinates

# Configuration
WINDOW_MINUTES = 30
AGGREGATE_INTERVAL_SEC = 8
H3_RESOLUTION = 7                 # 5–10 km edge; 6=~20km, 8=~1km, 9=~500m
MAX_POINTS_BEFORE_PRUNE = 20000   # Safety cap
COWRIE_LOG_PATH = "cowrie.json"
HONEYPOT_LAT = 34.0522  # Default: Los Angeles
HONEYPOT_LON = -118.2437

# Global state
recent_points: list[dict] = []
current_bounds: Optional[Dict] = None  # Viewport bounds from client
current_h3_resolution: int = H3_RESOLUTION
use_viewport_filtering = True
aggregator = None
AGGREGATION_METHOD = None

try:
    import h3
    H3_AVAILABLE = True
    aggregator = H3Aggregator(resolution=H3_RESOLUTION)
    AGGREGATION_METHOD = "h3"
except ImportError:
    H3_AVAILABLE = False
    aggregator = GridAggregator(resolution=0.05)
    AGGREGATION_METHOD = "grid"
    print("Warning: h3 not installed, falling back to grid aggregation")


def point_in_bounds(lat: float, lon: float, bounds: Dict) -> bool:
    """Check if a point is inside the given map bounds (axis-aligned bounding box)."""
    if not bounds:
        return True  # No bounds = include all points
    s = bounds.get('south', -90)
    w = bounds.get('west', -180)
    n = bounds.get('north', 90)
    e = bounds.get('east', 180)
    
    # Handle antimeridian crossing (e.g., Pacific view)
    if w > e:
        return (s <= lat <= n) and ((w <= lon <= 180) or (-180 <= lon <= e))
    else:
        return (s <= lat <= n) and (w <= lon <= e)


class ConnectionManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"Client connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"Client disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        if not self.active_connections:
            return
        
        message_text = json.dumps(message)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(message_text)
            except Exception as e:
                print(f"Error sending to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()

# FastAPI app
app = FastAPI(title="Threat Maps Real-Time API")

# CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def parse_cowrie_line(line: str) -> Optional[dict]:
    """Parse a single Cowrie log line and extract relevant fields."""
    try:
        event = json.loads(line.strip())
    except json.JSONDecodeError:
        return None
    
    event_id = event.get('eventid', '')
    
    # Filter for relevant events
    if event_id not in [
        'cowrie.login.failed',
        'cowrie.login.success',
        'cowrie.session.file_upload',
        'cowrie.command.failed',
        'cowrie.session.file_download'
    ]:
        return None
    
    src_ip = event.get('src_ip')
    if not src_ip:
        return None
    
    # Build enriched event
    enriched = {
        'timestamp': event.get('timestamp'),
        'event_id': event_id,
        'event_type': event_id.split('.')[-1],
        'source_ip': src_ip,
        'details': {}
    }
    
    # Extract event-specific details
    if event_id in ['cowrie.login.failed', 'cowrie.login.success']:
        enriched['details'] = {
            'username': event.get('username', ''),
            'password': event.get('password', ''),
            'success': event_id == 'cowrie.login.success'
        }
    elif event_id == 'cowrie.session.file_upload':
        enriched['details'] = {
            'filename': event.get('filename', ''),
            'shasum': event.get('shasum', '')
        }
    elif event_id == 'cowrie.command.failed':
        enriched['details'] = {
            'command': event.get('input', '')
        }
    
    return enriched


async def enrich_with_geo(event: dict) -> dict:
    """Add geo-location to event (simple IP-API, can be enhanced)."""
    ip = event.get('source_ip')
    if not ip:
        return event
    
    # Try local cache first (in production, use Redis/database)
    # For now, use simple IP-API (rate limited to 150/min)
    try:
        import requests
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                event['lat'] = data.get('lat')
                event['lon'] = data.get('lon')
                event['geo'] = {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'region': data.get('regionName')
                }
    except Exception as e:
        print(f"Geo lookup failed for {ip}: {e}")
    
    return event


async def tail_cowrie_log(filepath: str):
    """Tail Cowrie log file and process new lines."""
    if not os.path.exists(filepath):
        print(f"Warning: Cowrie log not found: {filepath}")
        return
    
    print(f"Tailing Cowrie log: {filepath}")
    
    with open(filepath, 'r') as f:
        # Seek to end of file
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if line:
                event = parse_cowrie_line(line)
                if event:
                    # Enrich with geo data (async-safe)
                    loop = asyncio.get_event_loop()
                    enriched = await loop.run_in_executor(
                        None,
                        lambda: asyncio.run(enrich_with_geo(event))
                    )
                    
                    # Add to buffer
                    recent_points.append(enriched)
                    
                    # Broadcast individual attack (for arcs)
                    await manager.broadcast({
                        "type": "attack",
                        "data": enriched
                    })
            else:
                await asyncio.sleep(0.5)


async def aggregate_and_broadcast():
    """Periodically aggregate recent points into H3 hexes and broadcast heatmap.
    
    If viewport bounds are set, only aggregate points within the visible area.
    """
    global current_bounds, current_h3_resolution
    
    while True:
        await asyncio.sleep(AGGREGATE_INTERVAL_SEC)
        now = datetime.utcnow()

        # Prune old points outside sliding window
        cutoff = now - timedelta(minutes=WINDOW_MINUTES)
        recent_points[:] = [
            p for p in recent_points
            if "timestamp" in p
            and datetime.fromisoformat(
                p["timestamp"].replace("Z", "+00:00").replace("+00:00", "")
            ) > cutoff
        ]

        # Safety cap: keep most recent if buffer grows too large
        if len(recent_points) > MAX_POINTS_BEFORE_PRUNE:
            recent_points[:] = recent_points[-MAX_POINTS_BEFORE_PRUNE:]

        if not recent_points:
            continue

        # Filter points to current viewport (if enabled and bounds received)
        filtered_points = recent_points
        viewport_active = bool(current_bounds) and use_viewport_filtering
        
        if viewport_active:
            filtered_points = [
                p for p in recent_points
                if "lat" in p and "lon" in p and point_in_bounds(p["lat"], p["lon"], current_bounds)
            ]
        
        # Skip if no points in viewport
        if not filtered_points:
            await manager.broadcast({
                "type": "heatmap_update",
                "data": [],
                "raw_count": len(recent_points),
                "filtered_count": 0,
                "hex_count": 0,
                "resolution": current_h3_resolution if AGGREGATION_METHOD == "h3" else None,
                "window_minutes": WINDOW_MINUTES,
                "timestamp": now.isoformat(),
                "viewport_active": viewport_active
            })
            continue

        # Aggregate filtered points
        aggregated = aggregator.aggregate(filtered_points)

        # Broadcast aggregated heatmap data
        await manager.broadcast({
            "type": "heatmap_update",
            "data": aggregated,
            "raw_count": len(recent_points),
            "filtered_count": len(filtered_points),
            "hex_count": len(aggregated),
            "resolution": current_h3_resolution if AGGREGATION_METHOD == "h3" else None,
            "window_minutes": WINDOW_MINUTES,
            "timestamp": now.isoformat(),
            "viewport_active": viewport_active
        })


@app.on_event("startup")
async def startup_event():
    """Start background tasks on server startup."""
    # Start log tailing
    asyncio.create_task(tail_cowrie_log(COWRIE_LOG_PATH))
    
    # Start aggregation
    asyncio.create_task(aggregate_and_broadcast())
    
    print(f"Server started. Aggregating every {AGGREGATE_INTERVAL_SEC}s, window: {WINDOW_MINUTES}m")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on server shutdown."""
    print("Server shutting down...")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat data."""
    global current_bounds, current_h3_resolution, aggregator
    
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get('type')

                if msg_type == 'refresh':
                    # Send current aggregated state immediately
                    aggregated_data = aggregator.aggregate(recent_points)
                    await websocket.send_json({
                        "type": "heatmap_update",
                        "data": aggregated_data,
                        "raw_count": len(recent_points),
                        "hex_count": len(aggregated_data),
                        "resolution": current_h3_resolution if AGGREGATION_METHOD == "h3" else None,
                        "timestamp": datetime.utcnow().isoformat()
                    })

                elif msg_type == 'set_viewport':
                    # Update viewport bounds from client
                    bounds = msg.get('bounds')
                    if bounds and "southWest" in bounds and "northEast" in bounds:
                        current_bounds = {
                            'south': bounds["southWest"]["lat"],
                            'west': bounds["southWest"]["lng"],
                            'north': bounds["northEast"]["lat"],
                            'east': bounds["northEast"]["lng"]
                        }
                        print(f"Viewport updated: {current_bounds}")

                elif msg_type == 'set_resolution':
                    # Update H3 resolution based on zoom level
                    new_res = msg.get('resolution')
                    if new_res and isinstance(new_res, int) and 0 <= new_res <= 15:
                        current_h3_resolution = new_res
                        # Re-create aggregator with new resolution
                        if AGGREGATION_METHOD == "h3" and H3_AVAILABLE:
                            aggregator = H3Aggregator(resolution=new_res)
                        print(f"H3 resolution updated: {new_res}")

            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/")
async def root():
    """Serve the threat map HTML frontend."""
    return FileResponse("realtime_map.html")


@app.get("/api/status")
async def status():
    """Get current server status."""
    return {
        "connected_clients": len(manager.active_connections),
        "points_in_buffer": len(recent_points),
        "window_minutes": WINDOW_MINUTES,
        "aggregation_interval": AGGREGATE_INTERVAL_SEC,
        "aggregation_method": AGGREGATION_METHOD,
        "h3_resolution": current_h3_resolution if AGGREGATION_METHOD == "h3" else None,
        "viewport_active": bool(current_bounds),
        "current_bounds": current_bounds
    }


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Threat Maps Real-Time Server")
    parser.add_argument(
        "--cowrie-log",
        default=COWRIE_LOG_PATH,
        help="Path to Cowrie JSON log file"
    )
    parser.add_argument(
        "--h3-resolution",
        type=int,
        default=H3_RESOLUTION,
        help="H3 hex resolution 0-15 (default: 7, ~5-10 km edge)"
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=WINDOW_MINUTES,
        help="Sliding window duration in minutes (default: 30)"
    )
    parser.add_argument(
        "--aggregate-interval",
        type=int,
        default=AGGREGATE_INTERVAL_SEC,
        help="Aggregation interval in seconds (default: 10)"
    )
    parser.add_argument(
        "--honeypot-lat",
        type=float,
        default=HONEYPOT_LAT,
        help="Honeypot latitude for arc visualization"
    )
    parser.add_argument(
        "--honeypot-lon",
        type=float,
        default=HONEYPOT_LON,
        help="Honeypot longitude for arc visualization"
    )
    return parser.parse_args()


# Apply command-line args
if __name__ == "__main__":
    args = parse_args()
    COWRIE_LOG_PATH = args.cowrie_log
    H3_RESOLUTION = args.h3_resolution
    WINDOW_MINUTES = args.window_minutes
    AGGREGATE_INTERVAL_SEC = args.aggregate_interval
    HONEYPOT_LAT = args.honeypot_lat
    HONEYPOT_LON = args.honeypot_lon
    try:
        aggregator = H3Aggregator(resolution=H3_RESOLUTION)
        AGGREGATION_METHOD = "h3"
    except ImportError:
        aggregator = GridAggregator(resolution=0.05)
        AGGREGATION_METHOD = "grid"
        print("Warning: h3 not installed, falling back to grid aggregation")
