import aiohttp

ABUSEIPDB_API_KEY = "KEY" 
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

HEADERS = {
    "Accept": "application/json",
    "Key": ABUSEIPDB_API_KEY
}

async def scan_abuseipdb(ip: str) -> str:
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(ABUSEIPDB_URL, headers=HEADERS, params=params) as response:
                if response.status != 200:
                    return f"❌ AbuseIPDB error: {response.status}"
                
                data = await response.json()
                result = data.get("data", {})

                abuse_score = result.get("abuseConfidenceScore", "N/A")
                total_reports = result.get("totalReports", "N/A")
                country = result.get("countryCode", "N/A")
                isp = result.get("isp", "N/A")
                usage_type = result.get("usageType", "N/A")
                last_report = result.get("lastReportedAt", "N/A")

                return (
                    f"🛡️ <b>AbuseIPDB Report</b>:\n"
                    f"• IP: <code>{ip}</code>\n"
                    f"• Country: {country}\n"
                    f"• ISP: {isp}\n"
                    f"• Usage Type: {usage_type}\n"
                    f"• Total Reports: <b>{total_reports}</b>\n"
                    f"• Abuse Score: <b>{abuse_score}/100</b>\n"
                    f"• Last Reported: {last_report or 'Never'}"
                )

    except Exception as e:
        return f"⚠️ Error querying AbuseIPDB: {str(e)}"


