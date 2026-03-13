import httpx

async def fetch_threatfox_data():
    """Fetch recent IOCs from ThreatFox."""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload)
        if response.status_code == 200:
            return response.json().get('data', [])
        return []

if __name__ == "__main__":
    import asyncio
    print(asyncio.run(fetch_threatfox_data())[:2])
