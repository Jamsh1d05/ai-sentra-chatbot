# bot/api_services/full_scan.py
import asyncio
import time
from datetime import datetime
from bot.config import VIRUS_TOTAL_TOKEN
from bot.api_services.virus_total import VirusTotalAPI 
from bot.api_services.whois_api import query_whois
from bot.api_services.abuseipdb_api import scan_abuseipdb
from bot.api_services.virus_total import detect_input_type

vt = VirusTotalAPI(VIRUS_TOTAL_TOKEN)

async def scan_all(ioc: str) -> dict:
    """
    Perform comprehensive IOC analysis across multiple threat intelligence sources
    Returns structured data for better formatting control
    """
    start_time = time.time()
    ioc_type = detect_input_type(ioc)

    scan_tasks = []
    
    scan_tasks.append({
        'name': 'VirusTotal',
        'task': asyncio.create_task(vt.query(ioc_type, ioc)),
        'priority': 1,
        'icon': '🔍'
    })
    
    if ioc_type in ("ip", "domain"):
        scan_tasks.append({
            'name': 'WHOIS',
            'task': asyncio.create_task(query_whois(ioc)),
            'priority': 2,
            'icon': '📋'
        })
    
    if ioc_type == "ip":
        scan_tasks.append({
            'name': 'AbuseIPDB',
            'task': asyncio.create_task(scan_abuseipdb(ioc)),
            'priority': 1,
            'icon': '🚫'
        })
    
    tasks = [item['task'] for item in scan_tasks]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    scan_results = {
        'ioc': ioc,
        'ioc_type': ioc_type,
        'scan_time': round(time.time() - start_time, 2),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'services': []
    }
    
    for i, (scan_info, result) in enumerate(zip(scan_tasks, results)):
        service_result = {
            'name': scan_info['name'],
            'priority': scan_info['priority'],
            'icon': scan_info['icon'],
            'success': not isinstance(result, Exception),
            'data': result if not isinstance(result, Exception) else None,
            'error': str(result) if isinstance(result, Exception) else None
        }
        scan_results['services'].append(service_result)
    
    return scan_results

def format_scan_results(scan_data: dict) -> str:
    ioc = scan_data['ioc']
    ioc_type = scan_data['ioc_type'].upper()
    scan_time = scan_data['scan_time']
    timestamp = scan_data['timestamp']
    
    message = f"🛡️ <b>Full IOC Analysis Report</b>\n"
    message += f"{'─' * 35}\n"
    message += f"🎯 <b>Target:</b> <code>{ioc}</code>\n"
    message += f"🏷️ <b>Type:</b> {ioc_type}\n"
    message += f"⏱️ <b>Scan Duration:</b> {scan_time}s\n"
    message += f"📅 <b>Timestamp:</b> {timestamp}\n\n"
    
    threat_level = assess_overall_threat(scan_data['services'])
    message += f"🚨 <b>Overall Threat Level:</b> {threat_level}\n"
    message += f"{'═' * 35}\n\n"
    
    services = sorted(scan_data['services'], key=lambda x: x['priority'])
    
    for service in services:
        if service['success']:
            message += f"{service['icon']} <b>{service['name']}</b>\n"
            formatted_data = format_service_data(service['name'], service['data'])
            message += f"{formatted_data}\n"
            message += f"{'─' * 25}\n\n"
        else:
            message += f"❌ <b>{service['name']}</b>\n"
            message += f"🚫 <i>Error: {service['error']}</i>\n"
            message += f"{'─' * 25}\n\n"
    
    return message

def assess_overall_threat(services: list) -> str:
    threat_indicators = []
    
    for service in services:
        if service['success'] and service['name'] == 'VirusTotal':
            data = service['data']
            if isinstance(data, dict) and 'data' in data:
                vt_data = data['data']
                if 'attributes' in vt_data:
                    stats = vt_data['attributes'].get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    if malicious > 0:
                        return "🔴 <b>HIGH RISK</b> - Malicious indicators detected"
                    elif suspicious > 0:
                        return "🟡 <b>MEDIUM RISK</b> - Suspicious activity detected"
                    else:
                        threat_indicators.append("VT_CLEAN")
    
    if "VT_CLEAN" in threat_indicators:
        return "🟢 <b>LOW RISK</b> - No malicious indicators found"
    
    return "⚪ <b>UNKNOWN</b> - Insufficient data for assessment"

def format_service_data(service_name: str, data: any) -> str:
    if service_name == "VirusTotal":
        return format_virustotal_data(data)
    elif service_name == "WHOIS":
        return format_whois_data(data)
    elif service_name == "AbuseIPDB":
        return format_abuseipdb_data(data)
    else:
        return "📄 Raw data available on request"

def format_virustotal_data(data) -> str:
    try:
        if isinstance(data, dict) and 'data' in data:
            vt_data = data['data']
            attributes = vt_data.get('attributes', {})
            
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0) 
            total_engines = malicious + suspicious + harmless + undetected
            
            reputation = attributes.get('reputation', 0)
            tags = attributes.get('tags', [])
            
            last_analysis = attributes.get('last_analysis_date')
            if last_analysis:
                analysis_date = datetime.fromtimestamp(last_analysis).strftime('%Y-%m-%d')
            else:
                analysis_date = "Unknown"
            
            result = f"📊 <b>Detection Results:</b>\n"
            result += f"   🔴 Malicious: {malicious}/{total_engines}\n"
            result += f"   🟡 Suspicious: {suspicious}/{total_engines}\n"
            result += f"   🟢 Harmless: {harmless}/{total_engines}\n"
            result += f"   ⚪ Undetected: {undetected}/{total_engines}\n\n"
            
            result += f"⭐ <b>Reputation Score:</b> {reputation}\n"
            
            if tags:
                result += f"🏷️ <b>Tags:</b> {', '.join(tags[:3])}\n"  # Show first 3 tags
            
            result += f"📅 <b>Last Analyzed:</b> {analysis_date}\n"
            
            if 'private' in tags:
                result += f"\n💡 <i>Note: This is a private IP address (RFC 1918)</i>"
            
            return result
            
    except Exception as e:
        return f"❌ Error parsing VirusTotal data: {str(e)}"
    
    return "📄 No detailed analysis available"

def format_whois_data(data) -> str:
    try:
        if isinstance(data, str):
            lines = data.split('\n')
            
            org_name = "Unknown"
            country = "Unknown"
            net_range = "Unknown"
            
            for line in lines:
                line = line.strip()
                if line.startswith('OrgName:'):
                    org_name = line.split(':', 1)[1].strip()
                elif line.startswith('Country:'):
                    country = line.split(':', 1)[1].strip()
                elif line.startswith('NetRange:'):
                    net_range = line.split(':', 1)[1].strip()
            
            result = f"🏢 <b>Organization:</b> {org_name}\n"
            result += f"🌍 <b>Country:</b> {country}\n"
            result += f"📡 <b>Network Range:</b> {net_range}\n"
            
            return result
            
    except Exception as e:
        return f"❌ Error parsing WHOIS data: {str(e)}"
    
    return "📄 WHOIS lookup completed"

def format_abuseipdb_data(data) -> str:
    try:
        if isinstance(data, dict):
            abuse_confidence = data.get('abuseConfidencePercentage', 0)
            is_public = data.get('isPublic', True)
            usage_type = data.get('usageType', 'Unknown')
            isp = data.get('isp', 'Unknown')
            country_code = data.get('countryCode', 'Unknown')
            
            result = f"🚫 <b>Abuse Confidence:</b> {abuse_confidence}%\n"
            result += f"🌐 <b>ISP:</b> {isp}\n"
            result += f"🏴 <b>Country:</b> {country_code}\n"
            result += f"💼 <b>Usage Type:</b> {usage_type}\n"
            
            if abuse_confidence > 75:
                result += f"\n⚠️ <b>High abuse confidence - Potentially malicious!</b>"
            elif abuse_confidence > 25:
                result += f"\n🟡 <b>Moderate abuse reports found</b>"
            else:
                result += f"\n✅ <b>Low abuse reports</b>"
                
            return result
            
    except Exception as e:
        return f"❌ Error parsing AbuseIPDB data: {str(e)}"
    
    return "📄 AbuseIPDB scan completed"


# Usage example for your handler:
"""
@router.message(Command("fullscan"))
async def full_scan_handler(message: types.Message):
    args = message.text.split()[1:]
    if not args:
        await message.reply("Usage: /fullscan <IP/domain/hash>")
        return
    
    ioc = args[0]
    
    # Send loading message
    loading_msg = await message.reply(
        "🔄 <b>Initiating Full IOC Analysis...</b>\n"
        "⏳ Scanning across multiple threat intelligence sources...", 
        parse_mode="HTML"
    )
    
    try:
        # Perform scan
        scan_results = await scan_all(ioc)
        
        # Format and send results
        formatted_message = format_scan_results(scan_results)
        
        # Check message length (Telegram limit ~4096 chars)
        if len(formatted_message) > 4000:
            # Split into multiple messages if too long
            parts = split_long_message(formatted_message)
            await loading_msg.edit_text(parts[0], parse_mode="HTML")
            for part in parts[1:]:
                await message.reply(part, parse_mode="HTML")
        else:
            await loading_msg.edit_text(formatted_message, parse_mode="HTML")
        
    except Exception as e:
        await loading_msg.edit_text(f"❌ <b>Full scan failed:</b> {str(e)}", parse_mode="HTML")

def split_long_message(message: str, max_length: int = 4000) -> list:
    if len(message) <= max_length:
        return [message]
    
    parts = []
    current_part = ""
    
    for line in message.split('\n'):
        if len(current_part + line + '\n') > max_length:
            if current_part:
                parts.append(current_part.strip())
                current_part = line + '\n'
            else:
                # Single line too long, force split
                parts.append(line[:max_length])
                current_part = line[max_length:] + '\n'
        else:
            current_part += line + '\n'
    
    if current_part.strip():
        parts.append(current_part.strip())
    
    return parts
"""