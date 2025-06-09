import re
import hashlib

from aiogram.types import InlineQuery, InlineQueryResultArticle, InputTextMessageContent
from bot.database.db import Database

db = Database()

def escape(text):
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)

async def inline_search(query: InlineQuery):
    search_text = query.query.strip()
    
    if not search_text:
        await query.answer([])
        return

    results = await db.search_cves(search_text) 

    if not results:
        return

    articles = []
    for cve in results:
        cve_id = cve["bulletin_id"]
        description = cve["description"]
        base_severity = cve.get("base_severity", "Unknown")
        base_score = cve.get("base_score", "Unknown")
        date = cve["published_date"]

        text = (
            f"🔎 *Search result*\n"
            f"📌 *ID:* {escape(cve_id)}\n"
            f"🔴 *Severity:* {escape(base_severity)}, {escape(base_score)}\n\n"
            f"*Description:* {escape(description)}\n\n"
           f"[🔗 More Info](https://nvd.nist.gov/vuln/detail/{escape(cve_id)})"
        )

        article = InlineQueryResultArticle(
            id=hashlib.md5(cve_id.encode()).hexdigest(),
            title=f"{cve_id} ({description})",
            description=f"Severity: {base_severity}",
            input_message_content = InputTextMessageContent(
                message_text=text,
                parse_mode="MarkdownV2" 
                )        
            )
        articles.append(article)

    await query.answer(articles, cache_time=20)