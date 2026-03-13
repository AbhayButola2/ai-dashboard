"""
Blocklist.de Collector
-----------------------
Source: https://lists.blocklist.de/lists/all.txt
Free, no auth. Provides IPs that have attacked other servers (SSH, SMTP, brute force etc.)
"""
import httpx

BLOCKLIST_URL = "https://lists.blocklist.de/lists/all.txt"

async def fetch_blocklist_data(limit: int = 200) -> list:
    """Fetch attacker IPs from Blocklist.de."""
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(BLOCKLIST_URL)
        if response.status_code != 200:
            print(f"[blocklist.de] HTTP {response.status_code}")
            return []

        lines = [l.strip() for l in response.text.splitlines() if l.strip() and not l.startswith('#')]
        records = []
        for i, ip in enumerate(lines[:limit]):
            records.append({
                "id": f"blde-{i}",
                "ioc": ip,
                "ioc_type": "ip",
                "threat_type": "brute_force",
                "malware_alias": "Unknown",
                "tags": "brute_force, SSH, attack",
                "confidence_level": 70,
                "timestamp": None,
                "source": "Blocklist.de"
            })
        return records

if __name__ == "__main__":
    import asyncio
    data = asyncio.run(fetch_blocklist_data(5))
    for r in data:
        print(r)
