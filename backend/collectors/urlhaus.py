import httpx

async def fetch_urlhaus_data():
    """Fetch recent malicious URLs from URLhaus."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        if response.status_code == 200:
            return response.json().get('urls', [])
        return []

if __name__ == "__main__":
    import asyncio
    print(asyncio.run(fetch_urlhaus_data())[:2])
