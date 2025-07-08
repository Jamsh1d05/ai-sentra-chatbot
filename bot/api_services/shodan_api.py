import aiohttp
import asyncio
import logging
from bot.config import SHODAN_API_KEY

#Requires API key, need to be added to .env file 
KEY = SHODAN_API_KEY
SHODAN_BASE_URL = "https://api.shodan.io"

class ShodanService:
    def __init__(self, api_key: str): 
        self.api_key = api_key
        self.base_url = SHODAN_BASE_URL

    async def query_shodan(self, ip: str) -> str:
        """Query Shodan for the given IP address and return formatted results."""
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self.format_shodan_result(data)
                    else:
                        logging.warning(f"Shodan query failed with status {response.status}")
                        return "❌ Shodan query failed."
        except asyncio.TimeoutError:
            logging.error("Shodan query timed out.")
            return "⏱️ Shodan query timed out."
        except Exception as e:
            logging.exception(f"Error querying Shodan: {e}")
            return f"❌ Error querying Shodan: {e}"

    def format_shodan_result(self, data: dict) -> str:
        """Format the raw Shodan response data into a readable string."""
        if not data:
            return "❌ No Shodan data found."

        ip = data.get("ip_str", "Unknown")
        org = data.get("org", "N/A")
        isp = data.get("isp", "N/A")
        country = data.get("country_name", "N/A")
        open_ports = data.get("ports", [])
        tags = data.get("tags", [])

        services = "\n".join(
            f"• {service.get('port')}/{service.get('transport')} - {service.get('product', 'Unknown')}"
            for service in data.get("data", [])[:5]
        )

        return (
            f"📡 Shodan Report for IP: {ip}\n"
            f"🔹 Country: {country}\n"
            f"🔹 Org: {org}\n"
            f"🔹 ISP: {isp}\n"
            f"🔹 Tags: {', '.join(tags) if tags else 'None'}\n"
            f"🔹 Open Ports: {', '.join(map(str, open_ports)) or 'None'}\n"
            f"🔍 Detected Services:\n{services if services else 'No detailed services listed.'}"
        )


