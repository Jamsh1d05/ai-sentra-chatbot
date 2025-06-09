import asyncio
import logging
import whois
from datetime import datetime


async def query_whois(target: str) -> str:
    try:
        whois_data = await asyncio.to_thread(whois.whois, target)
        return format_whois_result(whois_data, target)
    except Exception as e:
        logging.exception(f"WHOIS lookup failed for {target}: {e}")
        return f"❌ WHOIS lookup failed for `{target}`."

def format_whois_result(data: dict, target: str) -> str:
    if not data:
        return f"❌ No WHOIS data found for `{target}`."

    def format_date(d):
        if isinstance(d, list):
            d = d[0]
        return d.strftime("%Y-%m-%d") if isinstance(d, datetime) else str(d)

    registrar = data.get("registrar", "N/A")
    creation_date = format_date(data.get("creation_date", "N/A"))
    expiration_date = format_date(data.get("expiration_date", "N/A"))
    name_servers = data.get("name_servers", [])
    country = data.get("country", "N/A")

    return (
        f"📄 <b>WHOIS</b>\n <b>Report for:</b> <b>{target}</b>\n"
        f" <b>• Registrar:</b> {registrar}\n"
        f" <b>• Country:</b> {country}\n"
        f" <b>• Created:</b> {creation_date}\n"
        f" <b>• Expires:</b> {expiration_date}\n"
        f" <b>• Servers name:</b>\n" +
        "\n".join(f"   • {ns}" for ns in name_servers) if name_servers else "N/A"
    )
