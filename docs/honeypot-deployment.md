# Honeypot Deployment for Threat Maps

Deploying **Cowrie** (a popular medium-interaction SSH/Telnet honeypot) and integrating it with **threat map visualizations** is a practical way to generate real attacker data (IPs, geolocations, timestamps, commands, etc.) and feed it into live maps.

Cowrie logs attacker sessions in JSON format (by default in `var/log/cowrie/cowrie.json`), making it easy to parse IPs → geolocate → visualize.

## Recommended Approaches

There are two main paths, depending on complexity:

1. **Quick & Isolated**: Deploy standalone Cowrie (Docker recommended) → parse logs → build a simple threat map.
2. **All-in-One Production-Grade**: Use **T-Pot** (includes Cowrie + 20+ other honeypots + built-in Kibana dashboards + attack map).

T-Pot is often the fastest path for "threat maps" since it already has visualization (including animated attack maps via Kibana or plugins). If you want full custom control (e.g., your own Python scripts + Leaflet/Mapbox), go standalone Cowrie.

---

## Option 1: Quick Standalone Cowrie Deployment (Recommended for Custom Threat Maps)

### Prerequisites

- A Linux server/VM (Ubuntu 22.04/24.04 LTS preferred) or VPS with public IP.
- Docker & Docker Compose installed.
- Firewall: Allow inbound TCP 2222 (or remap to 22 if careful — not recommended on production).
- **Security note**: Isolate the honeypot (no outbound except logging; use cloud provider security groups; never expose real services).

### Step-by-Step: Docker Deployment

1. **Install Docker** (if not present):
   ```bash
   sudo apt update && sudo apt install docker.io docker-compose -y
   sudo systemctl enable --now docker
   ```

2. **Pull and run official Cowrie Docker image** (maps SSH to port 2222):
   ```bash
   sudo docker run -d \
     --name cowrie \
     -p 2222:2222 \
     -v cowrie-data:/cowrie/var/lib/cowrie \
     -v cowrie-logs:/cowrie/var/log/cowrie \
     cowrie/cowrie:latest
   ```
   - This starts Cowrie listening on 2222.
   - Volumes persist honeypot filesystem and JSON logs.

   For more control (custom config, Telnet enabled, etc.), use Docker Compose:

   Create `docker-compose.yml`:
   ```yaml
   version: '3'
   services:
     cowrie:
       image: cowrie/cowrie:latest
       container_name: cowrie
       ports:
         - "2222:2222"   # SSH
         - "2223:2223"   # Optional Telnet
       volumes:
         - ./cowrie/etc:/cowrie/etc
         - ./cowrie/var/log:/cowrie/var/log
         - ./cowrie/var/lib:/cowrie/var/lib
       restart: unless-stopped
   ```

   Then:
   ```bash
   mkdir -p cowrie/etc cowrie/var/log cowrie/var/lib
   docker-compose up -d
   ```

3. **Customize** (optional but useful):
   - Copy default config: `docker cp cowrie:/cowrie/etc/cowrie.cfg.dist ./cowrie/etc/cowrie.cfg`
   - Edit `./cowrie/etc/cowrie.cfg` (e.g., set hostname, enable Telnet, fake filesystem).
   - Restart: `docker restart cowrie`

4. **Test it**:
   ```bash
   ssh -p 2222 root@your-server-ip
   ```
   Use weak creds like `root:123456` — Cowrie will log the attempt and fake a shell.

Logs appear in `./cowrie/var/log/cowrie/cowrie.json` (JSON lines format).

---

## Option 2: Deploy with T-Pot (Built-in Threat Maps + Cowrie)

T-Pot bundles Cowrie + many honeypots + Elasticsearch + Kibana (with maps) + animated attack map plugins.

1. On a fresh Ubuntu 22.04/24.04 (min 8GB RAM recommended):
   ```bash
   git clone https://github.com/telekom-security/tpotce
   cd tpotce
   ./install.sh
   ```
   Follow prompts (choose "standard" install, set passwords).

2. After install (~30-60 min), access:
   - Web UI: https://your-ip:64294 (Kibana dashboards, attack map).
   - Cowrie logs feed into Elasticsearch → Kibana has geo-maps (attacker locations, heatmaps).
   - Optional: Add T-Pot-Attack-Map plugin for classic "pew-pew" animated globe.

This gives instant threat maps without custom coding.

---

## Integrating Cowrie Logs with Custom Threat Maps

To feed Cowrie into your **threat-maps** project:

### 1. Parse Cowrie JSON Logs

Use the provided script: [`src/parse_cowrie_logs.py`](../src/parse_cowrie_logs.md)

```bash
python src/parse_cowrie_logs.py --input cowrie/var/log/cowrie/cowrie.json --output data/cowrie_enriched.json
```

### 2. Enrich & Visualize

- Use your existing libs (Leaflet/Mapbox GL for 2D globe, Three.js for 3D).
- Poll/process new log lines → geolocate IPs → plot origin points + animated lines to your honeypot location.
- Add volume (attacks/hour), types (brute-force vs. commands), filters.

### 3. Real-Time Setup

- Use Filebeat/Logstash to ship JSON to Elasticsearch (like T-Pot).
- Or tail logs with Python + WebSocket → push to frontend for live updates.
- For animated "pew-pew": Libraries like `leaflet.migrationLayer` or custom D3 arcs work great.

---

## Security Best Practices

- Run on non-critical server; use cloud firewall to allow only necessary inbound.
- Restrict outbound (honeypot shouldn't attack back).
- Rotate/encrypt logs if sensitive.
- Monitor for compromise (high-interaction risk low in Cowrie but never zero).

Within hours of exposure, you'll see brute-force from bots worldwide — perfect data for your threat maps.

## References

- [Cowrie Official Documentation](https://docs.cowrie.org/)
- [Cowrie GitHub](https://github.com/cowrie/cowrie)
- [T-Pot GitHub](https://github.com/telekom-security/tpotce)
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
