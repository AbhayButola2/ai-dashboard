"""
Emerging Threats Collector
---------------------------
Source: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
Free, no auth. Provides known compromised IPs.
"""
import httpx

ET_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

async def fetch_emerging_threats_data(limit: int = 100) -> list:
    """Fetch compromised IPs from Emerging Threats."""
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(ET_URL)
        if response.status_code != 200:
            print(f"[emerging threats] HTTP {response.status_code}")
            return []

        lines = [l.strip() for l in response.text.splitlines() if l.strip() and not l.startswith('#')]
        records = []
        for i, ip in enumerate(lines[:limit]):
            records.append({
                "id": f"et-{i}",
                "ioc": ip,
                "ioc_type": "ip",
                "threat_type": "compromised_host",
                "malware_alias": "Unknown",
                "tags": "compromised, malicious_host",
                "confidence_level": 80,
                "timestamp": None,
                "source": "EmergingThreats"
            })
        return records

if __name__ == "__main__":
    import asyncio
    data = asyncio.run(fetch_emerging_threats_data(5))
    for r in data:
        print(r)
