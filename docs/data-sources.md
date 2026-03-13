# Threat Map Data Sources & Feeds

## Live / Real-time Attack / Threat Feeds (with geo data)

| Source | API | Geo Data | Free Tier | Notes |
|--------|-----|----------|-----------|-------|
| [GreyNoise](https://www.greynoise.io/) | ✅ | ✅ | ✅ Community | IP intelligence, noise vs attacks |
| [AlienVault OTX](https://otx.alienvault.com/) | ✅ | ✅ | ✅ | Pulses with indicators, some geo-tags |
| [AbuseIPDB](https://www.abuseipdb.com/) | ✅ | ✅ | ✅ | Reported malicious IPs |
| [Shodan](https://www.shodan.io/) | ✅ | ✅ | ⚠️ Limited | Exposed devices/services |
| [Censys](https://search.censys.io/) | ✅ | ✅ | ⚠️ Limited | Internet-wide scan data |
| [VirusTotal](https://www.virustotal.com/) | ✅ | ⚠️ Partial | ✅ | Malware/URL/IP analysis |
| [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) | ✅ | ✅ | ✅ | Threat intel sharing |

## Honeypot Data Sources

| Honeypot | Description | Output Format |
|----------|-------------|---------------|
| [Cowrie](https://github.com/cowrie/cowrie) | SSH/Telnet honeypot | JSON logs |
| [Dionaea](https://github.com/DinoTools/dionaea) | Multi-protocol honeypot | JSON/SQLite |
| [Conpot](https://github.com/mushorg/conpot) | ICS/SCADA honeypot | JSON |
| [T-Pot](https://github.com/telekom-security/tpotce) | Multi-honeypot platform | Elasticsearch |

## Public Datasets / Samples

- [DShield / Internet Storm Center](https://www.dshield.org/) - Attack summaries
- [PacketTotal](https://www.packettotal.com/) - PCAP analysis
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) - Sample PCaps
- [MISP Project](https://www.misp-project.org/) - Threat intel sharing

## Map Base Files

| Source | Format | Description |
|--------|--------|-------------|
| [Natural Earth](https://github.com/nvkelso/natural-earth-vector) | GeoJSON/Shapefile | Countries, regions, cities |
| [d3-geo](https://github.com/d3/d3-geo) | TopoJSON | World maps for D3 |
| [Simple Maps](https://simplemaps.com/data/world-map) | SVG/GeoJSON | Free world maps |
| [GeoNames](https://www.geognome.com/) | JSON/CSV | Cities, countries, coordinates |

## IP Geolocation APIs

| Service | Free Requests | Accuracy |
|---------|---------------|----------|
| [ipapi.co](https://ipapi.co/) | 1k/day | High |
| [IPinfo](https://ipinfo.io/) | 50k/month | High |
| [MaxMind GeoIP2](https://www.maxmind.com/) | Varies | Very High |
| [IP2Location](https://www.ip2location.com/) | Varies | High |
| [Abstract API](https://www.abstractapi.com/ip-geolocation-api) | 20k/month | Medium |

## Adding New Sources

When adding a new source, include:
1. Name and URL
2. API availability
3. Geo-location data support
4. Free tier limits
5. Brief description

---

*Last updated: 2026-03-12*
