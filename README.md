# Threat Maps

A collection of resources, scripts, data samples, and references for building/visualizing **cyber threat maps** (live attack visualizations, honeypot logs, IOC geo-mapping, etc.).

## Purpose
This repo serves as a personal/team reference for:
- Threat intelligence feeds with geo-location data
- Map visualization libraries and examples
- Sample code to fetch, process, and display attacks on a world map
- Useful datasets and tools

## Quick Start
1. Clone the repo: `git clone https://github.com/Sneaky-the-Slider/threat-maps.git`
2. See [data-sources.md](./docs/data-sources.md) for where to get live attack data
3. Check [src/](./src/) for example scripts (coming soon)

## Features / Planned
- [ ] Live threat feed ingestion (e.g., from AlienVault OTX, GreyNoise, etc.)
- [ ] World map visualizations (D3.js, Leaflet, Mapbox GL)
- [ ] Sample honeypot attack logs → geo-mapped
- [ ] Offline-capable map examples

## Data Sources & Feeds
See [docs/data-sources.md](./docs/data-sources.md) for the full list.

## Tools & Libraries Commonly Used
- D3.js + Datamaps / topojson for SVG-based attack maps
- Leaflet.js or OpenLayers for interactive web maps
- Mapbox GL JS (great for dark-themed cyber maps)
- Three.js/WebGL for 3D globe effects (if you want fancy globe visuals)

## License
MIT License

## Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md) if you'd like to add feeds, scripts, or fixes.
