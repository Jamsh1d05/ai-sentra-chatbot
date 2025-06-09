import json
import logging
import asyncio
from aiogram import Bot, types
from bot.config import redis_client
from bot.database.db import Database

logging.basicConfig(level=logging.INFO)

# Configurable settings
MAX_BULLETINS_PER_MESSAGE = 5  
NOTIFICATION_INTERVAL = 30

class NotificationService:
    def __init__(self, bot_token):
        self.bot = Bot(token=bot_token)
        self.db = Database()

    async def send_cve_notifications(self):
        """Send CVE notifications to subscribed users, avoiding duplicates."""
        users = await self.db.get_all_subscribed_users()
        if not users:
            logging.info("No subscribed users found.")
            return
        
        cached_bulletins = redis_client.get("cve_bulletin")
        if not cached_bulletins:
            logging.info("No new bulletins to notify.")
            return
        
        bulletins = json.loads(cached_bulletins)

        '''
        for idx, bulletin in enumerate(bulletins):
            if not isinstance(bulletin, dict):
                print(f"❌ Malformed bulletin at index {idx}: {bulletin} (type: {type(bulletin)})")
            else:
                print(f"✅ Bulletin {idx} OK: {bulletin.get('cve_id')}")
        '''

        last_sent_index = int(redis_client.get("last_cve_index") or 0)

        unnotified_bulletins = []
        for bulletin in bulletins[last_sent_index:last_sent_index + MAX_BULLETINS_PER_MESSAGE]:
            cve_id = bulletin["cve_id"]
            if not await self.db.check_bulletin_status(cve_id): 
                unnotified_bulletins.append(bulletin)

        if not unnotified_bulletins:
            logging.info("All bulletins are already notified.")
            return

        sent_cve_ids = set()

        async def send_message(user):
            user_id = user

            user_sources = await self.db.get_user_sources(user_id)
            user_sources = [s.lower() for s in user_sources]

            matching_bulletins = []

            for bulletin in unnotified_bulletins:
                description = bulletin.get("description", "").lower()

                if any(keyword in description for keyword in user_sources):
                    matching_bulletins.append(bulletin)

            if not matching_bulletins:
                return 

            # Send separate message for each bulletin
            for bulletin in matching_bulletins:
                severity = bulletin["severity"]
                cve_id = bulletin["cve_id"]
                more_info_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(severity, "⚪")

                message_text = (
                    f"🔔 *New Bulletin received:*\n\n"
                    f"📌 *CVE ID:* `{cve_id}`\n"
                    f"{severity_icon} *Severity:* `{severity}`\n"
                    f"📅 *Published:* `{bulletin['published']}`\n"
                    f"[🔗 More Info]({more_info_url})\n"
                )

                inline_buttons = [
                    types.InlineKeyboardButton(
                        text="📖 Description",
                        callback_data=f"details_{cve_id}"
                    )
                ] 
                markup = types.InlineKeyboardMarkup(inline_keyboard=[inline_buttons])

                try:
                    await self.bot.send_message(
                        user_id, 
                        message_text, 
                        parse_mode="Markdown",
                        reply_markup=markup,
                        disable_web_page_preview=True
                    )
                    sent_cve_ids.add(cve_id)
                    logging.info(f"Sent CVE {cve_id} to {user_id}")
                except Exception as e:
                    logging.error(f"Error sending CVE {cve_id} to {user_id}: {e}")

            logging.info(f"Sent {len(matching_bulletins)} filtered CVEs to {user_id}.")

        await asyncio.gather(*[send_message(user) for user in users])

        for cve_id in sent_cve_ids:
            await self.db.update_bulletin_notified(cve_id)  

        redis_client.set("last_cve_index", last_sent_index + MAX_BULLETINS_PER_MESSAGE)