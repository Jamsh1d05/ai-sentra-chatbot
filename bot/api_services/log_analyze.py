import pandas as pd
import json
import io
import re

def extract_ip(text):
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(text))
    return match.group(0) if match else None

def detect_patterns(text):
    patterns = {
        "SQLi": r"(UNION|SELECT|INSERT|UPDATE|DROP|WHERE|--|\*|\')",
        "XSS": r"<script>|javascript:",
        "CMD": r"(cmd\.exe|powershell|bash|sh )",
        "Auth Fail": r"(fail|denied|unauthorized)",
        "Suspicious Time": r"(0[0-4]:\d{2})"
    }
    found = []
    for label, pattern in patterns.items():
        if re.search(pattern, str(text), re.IGNORECASE):
            found.append(label)
    return found

async def process_log_file(file_content, file_extension):
    try:
        if file_extension == "csv":
            df = pd.read_csv(io.BytesIO(file_content.read()))
        elif file_extension == "json":
            df = pd.read_json(io.BytesIO(file_content.read()))
        elif file_extension == "log":
            decoded = file_content.read().decode("utf-8")
            logs = decoded.splitlines()
            df = pd.DataFrame({"message": logs})
        else:
            return {"status": "error", "message": "Unsupported file format"}

        if df.empty or len(df.columns) < 1:
            return {"status": "error", "message": "Invalid or empty log file"}

        # --- Begin analysis ---
        report = {
            "ips": {},
            "matches": {
                "SQLi": 0,
                "XSS": 0,
                "CMD": 0,
                "Auth Fail": 0,
                "Suspicious Time": 0
            },
            "total_lines": len(df)
        }

        for index, row in df.iterrows():
            row_text = " ".join([str(v) for v in row.values])
            ip = extract_ip(row_text)
            if ip:
                report["ips"][ip] = report["ips"].get(ip, 0) + 1
            matches = detect_patterns(row_text)
            for match in matches:
                report["matches"][match] += 1

        # Risk Level
        total_hits = sum(report["matches"].values())
        if total_hits > 10:
            risk = "🔴 HIGH"
        elif total_hits > 5:
            risk = "🟠 MEDIUM"
        else:
            risk = "🟢 LOW"

        # Create report
        summary = f"📄 Total Lines: {report['total_lines']}\n"
        summary += f"🌐 Unique IPs: {len(report['ips'])}\n"
        summary += f"🚩 Matches:\n"
        for k, v in report["matches"].items():
            summary += f"  - {k}: {v}\n"
        summary += f"\n🔐 Risk Level: {risk}"

        return {"status": "success", "report": summary}

    except Exception as e:
        return {"status": "error", "message": str(e)}
