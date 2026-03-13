"""
Feodo Tracker Collector
-----------------------
Source: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
Free, no auth required. Provides botnet C2 IPs.
"""
import httpx
import csv
import io
from datetime import datetime

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

async def fetch_feodo_data(limit: int = 100) -> list:
    """Fetch Feodo Tracker C2 botnet IP blocklist (CSV, no auth)."""
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(FEODO_URL)
        if response.status_code != 200:
            print(f"[feodo] HTTP {response.status_code}")
            return []

        records = []
        reader = csv.reader(io.StringIO(response.text))
        for row in reader:
            # Skip comment lines and the header row
            if not row or row[0].startswith('#') or row[0].strip() == 'first_seen_utc':
                continue
            # CSV format: first_seen, dst_ip, dst_port, c2_status, last_online, malware
            if len(row) >= 6:
                records.append({
                    "id": f"feodo-{row[1]}-{row[2]}",
                    "ioc": row[1],              # IP address
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware_alias": row[5].strip() if len(row) > 5 else "Unknown",
                    "tags": f"C2, {row[5].strip()}, port {row[2]}",
                    "confidence_level": 90,
                    "timestamp": row[0],
                    "source": "FeodoTracker"
                })
            if len(records) >= limit:
                break

        return records


if __name__ == "__main__":
    import asyncio
    data = asyncio.run(fetch_feodo_data(5))
    for r in data:
        print(r)
