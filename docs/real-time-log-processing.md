# Real-Time Log Processing (Cowrie)

Real-time log processing involves continuously monitoring, parsing, transforming, enriching, and acting on log data as it is generated with minimal latency. For honeypot logs like Cowrie's `cowrie.json`, this enables live threat map visualizations of attacker IPs, geolocations, attack types, timestamps, and commands.

## Core Techniques
1. File tailing (polling or inotify) for `tail -f` style processing.
2. Event-driven async I/O to integrate with WebSockets or queues.
3. Message queues or streaming pipelines for reliability at scale.
4. Stream processing frameworks for stateful analytics and aggregation.
5. Purpose-built stacks like ELK or T-Pot for out-of-the-box pipelines.

## Async Tail Example (Cowrie JSONL)
Prerequisite:
```sh
pip install aiofiles
```

```python
import asyncio
import json
import aiofiles
import os
from datetime import datetime
from typing import Callable, Any

try:
    from geoip2.database import Reader as GeoReader
    GEO_AVAILABLE = True
except ImportError:
    GEO_AVAILABLE = False
    print("GeoIP not available; install geoip2 for location enrichment")

LOG_FILE = "cowrie/var/log/cowrie/cowrie.json"
GEO_DB_PATH = "GeoLite2-City.mmdb"

async def tail_file(filename: str, callback: Callable[[str], Any]):
    if not os.path.exists(filename):
        print(f"Waiting for log file to appear: {filename}")
        await asyncio.sleep(2)
        return await tail_file(filename, callback)

    async with aiofiles.open(filename, mode="r", encoding="utf-8") as f:
        await f.seek(0, os.SEEK_END)
        last_inode = os.stat(filename).st_ino

        while True:
            line = await f.readline()
            if line:
                await callback(line.strip())
                continue

            await asyncio.sleep(0.2)

            try:
                current_inode = os.stat(filename).st_ino
                if current_inode != last_inode:
                    print("Log file rotated (new inode). Re-opening...")
                    break
            except FileNotFoundError:
                print("Log file disappeared. Waiting for recreation...")
                await asyncio.sleep(2)
                break


async def process_cowrie_line(line: str):
    if not line:
        return

    try:
        event = json.loads(line)
        event_id = event.get("eventid")

        if event_id not in [
            "cowrie.session.connect",
            "cowrie.login.failed",
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.direct-tcpip.request",
        ]:
            return

        src_ip = event.get("src_ip", "unknown")
        timestamp = event.get("timestamp", datetime.utcnow().isoformat())

        enriched = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "event": event_id,
            "session": event.get("session"),
        }

        if GEO_AVAILABLE:
            try:
                with GeoReader(GEO_DB_PATH) as reader:
                    geo = reader.city(src_ip)
                    enriched.update(
                        {
                            "country": geo.country.name or "Unknown",
                            "city": geo.city.name or "Unknown",
                            "lat": geo.location.latitude,
                            "lon": geo.location.longitude,
                        }
                    )
            except Exception as e:
                enriched["geo_error"] = str(e)

        print(f"[{timestamp}] {src_ip} -> {event_id}")
        print(json.dumps(enriched, indent=2))

    except json.JSONDecodeError:
        print(f"Malformed JSON line: {line}")
    except Exception as e:
        print(f"Processing error: {e}")


async def main():
    print(f"Starting async tail on {LOG_FILE}...")

    async def line_callback(line: str):
        await process_cowrie_line(line)

    while True:
        try:
            await tail_file(LOG_FILE, line_callback)
        except Exception as e:
            print(f"Tail error: {e}. Restarting in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
```

## Best Practices for Cowrie to Threat Maps
1. Filter relevant events like login, session, command, or file transfer.
2. Enrich with GeoIP and keep the database up to date.
3. Deduplicate or rate-limit noisy sources for clean visuals.
4. Detect log rotation by inode or file size changes.
5. Push updates over WebSockets for real-time map animation.

## Integration Ideas
1. Use FastAPI WebSockets for live event streaming to the browser.
2. Add batching to smooth animation and reduce frontend churn.
3. Fan out to Redis Pub/Sub or Kafka when scaling beyond a single host.
