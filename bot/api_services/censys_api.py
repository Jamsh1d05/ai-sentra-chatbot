import aiohttp
import asyncio
import logging
from bot.config import CENSYS_API_ID, CENSYS_API_SECRET


class CensysAPI:
    BASE_URL = "https://search.censys.io/api/v2/hosts/search"
    
    def __init__(self, api_id: str = CENSYS_API_ID, api_secret: str = CENSYS_API_SECRET):
        self.api_id = api_id
        self.api_secret = api_secret
        self.headers = {
            "Content-Type": "application/json"
        }

    async def query(self, query: str) -> str:
        payload = {
            "q": query,
            "per_page": 1
        }
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
                async with session.post(self.BASE_URL, headers=self.headers, auth=auth, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._format_result(data)
                    elif response.status == 401:
                        return "🔐 Censys API key is missing or invalid."
                    elif response.status == 403:
                        return "🚫 Access denied — check your Censys plan or permissions."
                    else:
                        return f"❌ Censys query failed. Status: {response.status}"
        except asyncio.TimeoutError:
            return "⏱️ Censys query timed out."
        except Exception as e:
            logging.exception("Censys query error:")
            return f"❌ Censys error: {e}"

    def _format_result(self, data: dict) -> str:
        try:
            hit = data["result"]["hits"][0]
            ip = hit.get("ip", "N/A")
            country = hit.get("location", {}).get("country", "Unknown")
            services = hit.get("services", [])

            ports = ", ".join(str(s["port"]) for s in services if "port" in s)
            protocols = ", ".join(s.get("service_name", "Unknown") for s in services)

            return (
                f"🌐 Censys Report for: {ip}\n"
                f"🔹 Country: {country}\n"
                f"🔹 Open Ports: {ports or 'None'}\n"
                f"🔍 Services: {protocols or 'No data'}"
            )
        except (IndexError, KeyError):
            return "❌ No results found for this query."
