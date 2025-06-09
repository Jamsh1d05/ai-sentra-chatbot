import aiohttp
import asyncio
import json
from datetime import datetime, timedelta, timezone
from bot.database.db import Database
from bot.config import redis_client

db = Database()
NVD_SOURCE = "1"

'''----------------------------------------------------------------------------
NVDService Class API calls 
------------------------------------------------------------------------------'''

class NVDService:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.session = None
        self.last_fetched_time = datetime.now(timezone.utc) - timedelta(days=1) 

    async def start_session(self):
        self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()

    def parse_cve_date(self, date_str):
        """Parses NVD API date formats."""
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)

    async def fetch_cves_paginated(self):
        """Fetches paginated CVE data from NVD API."""
        try:
            await self.start_session()
            current_date = datetime.now(timezone.utc)
            all_cves = []
            start_index = 0
            results_per_page = 20
            max_retries = 3

            while True:
                params = {
                    "pubStartDate": self.last_fetched_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "pubEndDate": current_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                }
                
                for _ in range(max_retries):  
                    async with self.session.get(self.BASE_URL, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            vulnerabilities = data.get("vulnerabilities", [])

                            if not vulnerabilities:
                                return all_cves  

                            all_cves.extend(vulnerabilities)
                            start_index += results_per_page  

                            latest_published = max(
                                (self.parse_cve_date(cve["cve"]["published"]) for cve in vulnerabilities),
                                default=self.last_fetched_time
                            )
                            self.last_fetched_time = latest_published
                            break  
                        else:
                            print(f"Failed to fetch CVEs. Status: {response.status}")
                            await asyncio.sleep(2)
                else:
                    return all_cves

        except Exception as e:
            print(f"Error fetching paginated CVEs: {e}")
            return []
        finally:
            await self.close_session()

    async def get_cve_bulletin(self):
        """Fetches new CVEs, filters them, and stores them in Redis."""
        latest_cves = await self.fetch_cves_paginated()
        if not latest_cves: 
            print("No new CVEs found.")
            return []

        new_bulletins = []
        stored_cve_ids = redis_client.get("stored_cve_ids")
        stored_cve_ids = set(json.loads(stored_cve_ids)) if stored_cve_ids else set()

        for item in latest_cves:
            if not item or 'cve' not in item:
                continue

            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "N/A")

            if cve_id in stored_cve_ids:
                continue

            descriptions = cve_data.get("descriptions", [])
            description = descriptions[0].get("value", "No description available.") if descriptions else "No description available."

            base_score, base_severity = "N/A", "N/A"
            metrics = cve_data.get('metrics', {})
            
            if metrics:
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]:
                    if version in metrics and isinstance(metrics[version], list) and metrics[version]:
                        cvss_data = metrics[version][0].get('cvssData', {})
                        base_score = cvss_data.get('baseScore', "N/A")
                        base_severity = cvss_data.get('baseSeverity', "N/A")
                        break

            published_date = cve_data.get("published", "N/A")
            formatted_date = "N/A"

            if published_date and published_date != "N/A":
                try:
                    parsed_date = datetime.fromisoformat(published_date)
                    formatted_date = parsed_date.strftime('%d %B %Y')
                except ValueError:
                    print(f"Warning: Invalid date format for CVE {cve_id}: {published_date}")
            try:
                await db.add_cve(cve_id, NVD_SOURCE, description, base_severity, base_score, published_date)
            except Exception as db_error:
                print(f"Error inserting CVE-ID {cve_id} into the database: {db_error}")

            bulletin_data = {
                "cve_id": cve_id,
                "severity": f"{base_score}, {base_severity}",
                "description": description,
                "published": formatted_date
            }
            new_bulletins.append(bulletin_data)
            stored_cve_ids.add(cve_id)

        if new_bulletins:
            redis_client.set("cve_bulletin", json.dumps(new_bulletins), ex=60)
            redis_client.setex("stored_cve_ids", timedelta(days=7), json.dumps(list(stored_cve_ids)))
            print(f"{len(new_bulletins)} new bulletins stored to redis!")

        return new_bulletins  


'''
async def nvd_results():
    nvd = NVDService()
    await nvd.get_cve_bulletin()

if __name__ == "__main__":
    asyncio.run(nvd_results())
'''