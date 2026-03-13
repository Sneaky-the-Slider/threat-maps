# Tools & Libraries Reference

## Map Visualization Libraries

### JavaScript / Web-Based

| Library | Best For | Difficulty | Notes |
|---------|----------|------------|-------|
| [D3.js](https://d3js.org/) | Custom SVG maps | Medium-High | Most flexible, steep learning curve |
| [Leaflet.js](https://leafletjs.com/) | Interactive tile maps | Easy | Lightweight, great plugins |
| [Mapbox GL JS](https://docs.mapbox.com/mapbox-gl-js/) | Styled vector maps | Medium | Beautiful dark themes |
| [OpenLayers](https://openlayers.org/) | Complex GIS | Medium-High | Full-featured |
| [Three.js](https://threejs.org/) | 3D globe effects | High | WebGL-based |
| [Cesium](https://cesium.com/) | 3D globe + time | High | Professional grade |

### Python

| Library | Best For | Notes |
|---------|----------|-------|
| [Folium](https://python-visualization.github.io/folium/) | Leaflet wrapper | Easy, interactive |
| [Plotly](https://plotly.com/python/) | Choropleth + scatter | Great for dashboards |
| [Geopandas](https://geopandas.org/) | Geo data manipulation | Pandas for maps |
| [Dash](https://dash.plotly.com/) | Interactive web apps | Full web framework |

## Data Processing

### IP Geolocation Tools

```bash
# MaxMind GeoIP2 (offline)
mmdblookup --file GeoLite2-City.mmdb --ip 8.8.8.8

# Python libraries
pip install geoip2 maxminddb-geolite2

# Node.js
npm install maxmind
```

### Log Parsing

```bash
# Cowrie honeypot logs
jq '.eventid' cowrie.json | sort | uniq -c

# Extract IPs and geolocate
cat auth.log | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read ip; do
    curl -s ipapi.co/$ip/json | jq '.country_name'
done
```

## Sample Projects / Inspiration

- [Kaspersky Cyberthreat Map](https://cybermap.kaspersky.com/) - 3D globe
- [Fortinet Threat Map](https://threatmap.fortiguard.com/) - Real-time attacks
- [FireEye Cyber Threat Map](https://www.fireeye.com/cyber-map/threat-map.html) - Attack origins
- [Digital Attack Map](https://www.digitalattackmap.com/) - DDoS visualization

## Useful Commands

```bash
# Quick IP lookup
curl ipapi.co/8.8.8.8/json

# Get country from IP
curl -s ipapi.co/1.1.1.1/country_name

# Bulk lookup (example)
cat ips.txt | xargs -I {} curl -s ipapi.co/{}/json | jq '.ip, .country_name'
```

## APIs Quick Reference

### GreyNoise
```bash
curl -H "key: YOUR_API_KEY" \
  "https://api.greynoise.io/v3/community/8.8.8.8"
```

### AbuseIPDB
```bash
curl -G --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: YOUR_API_KEY" \
  "https://api.abuseipdb.com/api/v2/check"
```

### IPinfo
```bash
curl "https://ipinfo.io/8.8.8.8/json?token=YOUR_TOKEN"
```

---

*Last updated: 2026-03-12*
