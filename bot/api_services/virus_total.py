import re
import aiohttp
import asyncio
import base64
import hashlib
from bot.config import VIRUS_TOTAL_TOKEN

'''
---------------------------------------------------------------------------
VirusTotal API call Class 
----------------------------------------------------------------------------
'''

class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    async def query(self, input_type: str, query: str) -> dict:
        headers = {"x-apikey": VIRUS_TOTAL_TOKEN}
        endpoint = {
            "ip": f"/ip_addresses/{query}",
            "domain": f"/domains/{query}",
            "hash": f"/files/{query}",
            "url": f"/urls/{self.encode_url(query)}"
        }.get(input_type)

        if not endpoint:
            return {"error": "Invalid input type"}

        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.BASE_URL}{endpoint}", headers=headers) as res:
                return await res.json()

    def encode_url(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def scan_url(self, url: str) -> dict:
        headers = {"x-apikey": VIRUS_TOTAL_TOKEN}
        data = {"url": url}
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.BASE_URL}/urls", headers=headers, data=data) as resp:
                if resp.status == 200:
                    res_data = await resp.json()
                    url_id = res_data["data"]["id"]
                    return await self.get_analysis_result(url_id)
                return {"error": f"URL scan failed: {resp.status}"}

def detect_input_type(text: str) -> str:
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', text):
        octets = map(int, text.split('.'))
        if all(0 <= o <= 255 for o in octets): 
            return 'ip'
    if re.match(r'^[a-fA-F0-9]{32,64}$', text):
        return 'hash'
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', text  ):
        return 'domain'
    if re.match(r'^(http|https)://', text):  
        return 'url'

    return 'unknown'

#Escaping
def escape_html(text) -> str:
    """Escapes HTML special characters in the given text."""
    text_str = str(text) if not isinstance(text, str) else text
    return (
        text_str
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

def format_vt_result(data: dict, input_type: str, query: str) -> str:
    from datetime import datetime

    def fmt_date(timestamp):
        if not timestamp:
            return "N/A"
        return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M UTC")

    def get_reputation(attr):
        rep = attr.get("reputation")
        return f"{rep}" if rep is not None else "N/A"

    if "data" not in data:
        return f"🔴 <b>Error</b>\n<code>{escape_html(query)}</code>\nNo data available."

    attributes = data["data"].get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    rep = get_reputation(attributes)

    threat = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "None")

    if input_type == "hash":
        hashes = {
            "SHA256": attributes.get("sha256", "N/A"),
            "SHA1": attributes.get("sha1", "N/A"),
            "MD5": attributes.get("md5", "N/A"),
        }
        detection_details = []
        if malicious > 0 and "last_analysis_results" in attributes:
            for engine, result in attributes["last_analysis_results"].items():
                if result.get("category") == "malicious" and result.get("result"):
                    detection_details.append(f"• <b>{escape_html(engine)}</b>: {escape_html(result['result'])}")

        detection_summary = "\n".join(detection_details[:5])
        if len(detection_details) > 5: 
            detection_summary += f"\n• <i>and {len(detection_details) - 5} more...</i>"

        hash_items = "\n".join(f"• <b>{escape_html(k)}</b>: <code>{escape_html(v)}</code>" for k, v in hashes.items())

        return (
            f"📦 <b>Hash Report</b>\n"
            f"<code>{escape_html(query)}</code>\n\n"
            f"<b>Type:</b> {escape_html(attributes.get('type_description', 'Unknown'))}\n"
            f"<b>Size:</b> {escape_html(attributes.get('size', 'Unknown'))} bytes\n"
            f"<b>Reputation:</b> {escape_html(rep)}\n"
            f"<b>Threat Label:</b> {escape_html(threat)}\n"
            f"<b>Submitted:</b> {escape_html(fmt_date(attributes.get('first_submission_date')))}\n"
            f"<b>Last Analysis:</b> {escape_html(fmt_date(attributes.get('last_analysis_date')))}\n"
            f"<b>Detection:</b> {escape_html(malicious)}/{escape_html(total)}\n"
            f"\n<b>Hashes:</b>\n{hash_items}"
            f"\n\n<b>Detection Details:</b>\n{detection_summary if detection_details else 'No detections'}"
        )

    elif input_type == "ip":
        return (
            f"🔍 <b>IP Report</b>\n"
            f"<code>{escape_html(query)}</code>\n"
            f"<b>Country:</b> {escape_html(attributes.get('country', 'Unknown'))}\n"
            f"<b>ASN:</b> {escape_html(attributes.get('asn', 'Unknown'))}\n"
            f"<b>Network:</b> {escape_html(attributes.get('network', 'Unknown'))}\n"
            f"<b>Reputation:</b> {escape_html(rep)}\n"
            f"<b>Last Analysis:</b> {escape_html(fmt_date(attributes.get('last_analysis_date')))}\n"
            f"<b>Malicious:</b>  {escape_html(malicious)}/{escape_html(total)}\n"
            f"<b>Threat Label:</b> {escape_html(threat)}"
        )

    elif input_type == "domain":
        return (
            f"🌐 <b>Domain Report</b>\n"
            f"<code>{escape_html(query)}</code>\n"
            f"<b>Registrar:</b> {escape_html(attributes.get('registrar', 'Unknown'))}\n"
            f"<b>Created:</b> {escape_html(attributes.get('creation_date', 'Unknown'))}\n"
            f"<b>Reputation:</b> {escape_html(rep)}\n"
            f"<b>Last Analysis:</b> {escape_html(fmt_date(attributes.get('last_analysis_date')))}\n"
            f"<b>Malicious:</b> {escape_html(malicious)}/{escape_html(total)}\n"
            f"<b>Threat Label:</b> {escape_html(threat)}"
        )

    elif input_type == "url":
        return (
            f"🌐 <b>URL Report</b>\n"
            f"<code>{escape_html(query)}</code>\n\n"
            f"<b>Final URL:</b> {escape_html(attributes.get('url', query))}\n"
            f"<b>Reputation:</b> {escape_html(rep)}\n"
            f"<b>Last Analysis:</b> {escape_html(fmt_date(attributes.get('last_analysis_date')))}\n"
            f"<b>Threat Label:</b> {escape_html(threat)}\n"
            f"<b>Detection:</b> {escape_html(malicious)}/{escape_html(total)}"
        )

    return f"🔎 <b>Unknown Type</b>\n<code>{escape_html(query)}</code>\nRaw data: {escape_html(str(data)[:300])}..."
