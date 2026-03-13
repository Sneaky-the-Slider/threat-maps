# Real-Time Heatmap Aggregation

Server-side point aggregation for real-time Leaflet heatmaps is a best practice when attack volume from honeypots like Cowrie grows high (hundreds to thousands of events per minute). Sending every single point to the browser via WebSocket causes:

- **High bandwidth usage**
- **Browser memory/CPU strain** (especially on mobile)
- **Cluttered or slow heatmap rendering**

Aggregation reduces data sent by grouping points into cells/bins and computing counts/intensity per bin. The client receives far fewer aggregated points (e.g., 100–500 instead of 10,000+), which `leaflet.heat` handles efficiently.

## Recommended Approaches

### 1. Simple Grid Aggregation (Fast & Lightweight – Recommended Start)

Bucket points into fixed lat/lon grids (e.g., 0.05° × 0.05° cells ≈ 5 km resolution at equator). Use Python dict with rounded (lat, lon) keys.

**Pros:** Fast, no dependencies, easy to tune
**Cons:** Cell size varies with latitude

### 2. H3 Hexagonal Binning

Use `h3` library (`pip install h3`) for hexagonal grids – popular for geospatial aggregation.

**Pros:** Uniform cell sizes, better visual appearance, zoom-aware
**Cons:** Requires h3 dependency

### 3. Geohash Binning

String-based keys, easy bounding box queries later.

**Pros:** Simple, hierarchical (precision-based)
**Cons:** Rectangular cells, edge effects

## Quick Start

### Offline Aggregation (Batch Processing)

Aggregate historical data for visualization:

```bash
# Grid aggregation (default)
python src/heatmap_aggregator.py \
  --input data/cowrie_enriched.json \
  --output data/heatmap_aggregated.json

# H3 hexagonal binning
python src/heatmap_aggregator.py \
  --method h3 --h3-resolution 5 \
  --input data/cowrie_enriched.json \
  --output data/heatmap_h3.json

# Geohash binning
python src/heatmap_aggregator.py \
  --method geohash --geohash-precision 5 \
  --input data/cowrie_enriched.json \
  --output data/heatmap_geohash.json
```

### Real-Time Aggregation (WebSocket Streaming)

Run the FastAPI server for live threat map updates:

```bash
# Start the real-time server
uvicorn src.realtime_server:app --host 0.0.0.0 --port 8000

# With custom configuration
uvicorn src.realtime_server:app --host 0.0.0.0 --port 8000 \
  --app-args "--cowrie-log /var/log/cowrie/cowrie.json --window-minutes 60"
```

Then open `http://localhost:8000` in your browser to view the real-time threat map.

## Configuration Options

### Grid Aggregation

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--resolution` | 0.05 | Grid cell size in degrees (~5 km at equator) |

Smaller values = finer resolution but more cells sent to client.

### H3 Aggregation

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--h3-resolution` | 5 | H3 resolution (0-15, higher = finer cells) |

Resolution guide:
- 3-4: ~100 km cells (global view)
- 5-6: ~10-20 km cells (regional view)
- 7-8: ~1-5 km cells (city view)

### Geohash Aggregation

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--geohash-precision` | 5 | Geohash precision (1-12) |

Precision guide:
- 3-4: ~20-80 km cells
- 5-6: ~1-5 km cells
- 7-8: ~100-500 m cells

### Real-Time Server

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--cowrie-log` | cowrie.json | Path to Cowrie JSON log file |
| `--grid-resolution` | 0.05 | Aggregation grid size |
| `--window-minutes` | 30 | Sliding window duration |
| `--aggregate-interval` | 10 | How often to aggregate (seconds) |
| `--honeypot-lat` | 34.0522 | Honeypot latitude (for arcs) |
| `--honeypot-lon` | -118.2437 | Honeypot longitude (for arcs) |

## Architecture

### Server-Side (FastAPI)

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Cowrie Log     │────▶│  Log Tailer      │────▶│  Point Buffer   │
│  (JSON lines)   │     │  (parse & enrich)│     │  (sliding window)│
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
┌─────────────────┐     ┌──────────────────┐     ┌────────▼────────┐
│  WebSocket      │◀────│  Aggregator      │◀────│  Background    │
│  Broadcast      │     │  (grid/h3/geo)   │     │  Task (10s)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Client-Side (Leaflet)

```javascript
ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'attack') {
        // Draw individual arc for recent attack
        drawArc(data.lat, data.lon, honeypotLat, honeypotLon);
    }
    else if (msg.type === 'heatmap_update') {
        // Update heatmap with aggregated data
        heatLayer.setLatLngs(msg.data);  // [[lat, lng, intensity], ...]
    }
};
```

## Performance Tuning

### Data Reduction Examples

| Scenario | Raw Points | Aggregated Cells | Reduction |
|----------|------------|------------------|-----------|
| Light traffic (100 events) | 100 | 45 | 55% |
| Medium traffic (1,000 events) | 1,000 | 180 | 82% |
| Heavy traffic (10,000 events) | 10,000 | 350 | 96.5% |

### Tuning Guidelines

1. **Start with grid resolution 0.05** (~5 km) for regional maps
2. **Use sliding window of 30 minutes** for recent activity focus
3. **Aggregate every 10 seconds** for smooth updates without overload
4. **For zoom-aware aggregation**: Request finer resolution when client zooms in (via WebSocket message)

### Hybrid Approach

Send both:
- **Individual attacks** → For arc animations (recent only, last 50)
- **Aggregated heatmap** → For density visualization (sliding window)

This gives visual impact of individual attacks while maintaining performance.

## Advanced: Dynamic Resolution Based on Zoom

```javascript
// Client-side: Send zoom level to server
ws.send(JSON.stringify({
    type: 'set_zoom',
    zoom: map.getZoom(),
    bounds: map.getBounds()
}));
```

```python
# Server-side: Adjust resolution based on zoom
ZOOM_RESOLUTIONS = {
    (0, 3): 0.5,    # Global view
    (4, 6): 0.1,    # Continental view
    (7, 10): 0.05,  # Regional view
    (11, 15): 0.01, # City view
}

def get_resolution_for_zoom(zoom: int) -> float:
    for (min_z, max_z), res in ZOOM_RESOLUTIONS.items():
        if min_z <= zoom <= max_z:
            return res
    return 0.05
```

## Integration with T-Pot / ELK

If using T-Pot or Elasticsearch:

1. **Use Elasticsearch aggregations** instead of Python:
   ```json
   {
     "aggs": {
       "heatmap": {
         "geohash_grid": {
           "field": "geo.location",
           "precision": 5
         }
       }
     }
   }
   ```

2. **Query via Kibana API** and broadcast results via WebSocket

3. **Or use Filebeat → Logstash → Python** for custom aggregation

## References

- [H3 Library Documentation](https://h3geo.org/docs/)
- [Leaflet.heat Plugin](https://github.com/Leaflet/Leaflet.heat)
- [FastAPI WebSocket Guide](https://fastapi.tiangolo.com/advanced/websockets/)
- [Cowrie Honeypot](https://docs.cowrie.org/)
