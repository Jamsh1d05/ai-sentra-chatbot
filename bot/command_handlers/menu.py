#import redis
#import json
import html
from aiogram import Router
from aiogram.types import Message
from aiogram.filters import Command 
from aiogram.fsm.context import FSMContext
from bot.database.db import Database
from bot.api_services.nvd_service import NVDService
from bot.config import  GIT_HUB_TOKEN
from bot.config import LANGUAGES
from bot.utils.message_utils import escape_md, convert_markdown_to_html
from bot.handlers.message_handler import redis_client
from bot.keyboards.inline_btns import settings_menu
from bot.handlers.message_handler import send_cve_list
from bot.ai_services.openai_gpt import GitHubGPT


router = Router()
db = Database()
nvd = NVDService()
gpt = GitHubGPT(GIT_HUB_TOKEN)


@router.message(Command("settings"))
async def settings(message: Message, state: FSMContext):
    set_menu = await settings_menu(message)
    await message.answer("Settings", reply_markup=set_menu)
    
@router.message(Command("latest_bulletins"))
async def bulletins(message: Message, state: FSMContext):
    await send_cve_list(message)
    
@router.message(Command("ai"))
async def handle_ai_query(message: Message):
    query = message.text.replace("/ai", "").strip()
    if not query:
        await message.answer("🧠 Please provide a question after the /ai command.")
        return  
    
    await message.answer("🤖 Thinking...")
    result = await gpt.ask(query)
    reply = escape_md(result)

    formatted_summary = convert_markdown_to_html(result)
    safe_summary = html.escape(formatted_summary, quote=False)
    safe_summary = safe_summary.replace('&lt;b&gt;', '<b>').replace('&lt;/b&gt;', '</b>')
    safe_summary = safe_summary.replace('&lt;i&gt;', '<i>').replace('&lt;/i&gt;', '</i>')
    safe_summary = safe_summary.replace('&lt;code&gt;', '<code>').replace('&lt;/code&gt;', '</code>')
    safe_summary = safe_summary.replace('&lt;a href=&quot;', '<a href="').replace('&quot;&gt;', '">').replace('&lt;/a&gt;', '</a>')


    '''
    if len(reply) > 4096:
        await message.answer("⚠️ The response is too long. Sending in chunks...")
        chunks = [reply[i:i + 4096] for i in range(0, len(reply), 4096)]
        for chunk in chunks:
            await message.answer(chunk, parse_mode="MarkdownV2")
    else:
        await message.answer(reply, parse_mode="MarkdownV2")
    '''

    await message.answer(safe_summary, parse_mode="HTML")

@router.message(Command("help"))
async def handle_ai_query(message: Message):
    help_text = (
        "📘 *SENTRA Help Center*\n\n"
        "Welcome to *SENTRA* \\— your AI\\-powered cybersecurity assistant\\.\n\n"
        "Use the *main menu buttons* below to explore features:\n\n"
        "🔍 *Bulletins*\n"
        "See latest TOP bulletins\n\n"
        "🧠 *AI Assistant*\n"
        "Ask security\\-related questions or get summaries of CVEs using a built\\-in AI assistant\\.\n\n"
        "🧰 *Tools*\n"
        "Access tools for *IOC* scanning: domain\\/IP reputation, phishing scanners, WHOIS & breach lookups, and more\\.\n\n"
        "⚙️ *Settings*\n"
        "Manage your preferences:\n"
        "• Notification filters\n"
        "• Alert frequency\n"
        "• Source subscriptions\n\n"
        "📜 *Commands:*\n"
        "• /start \\- Start the bot and set your language\n"
        "• /settings \\- Access settings menu\n"
        "• /latest\\_bulletins \\- Get the latest CVE bulletins\n"
        "• /ai \\- Ask any cyber security related question from AI assistant\\!\n\n"
        "_Need more help\\? Contact us: @oxDevSec\\._\n"
        "Stay safe — stay informed\\. 🛡"
    )



    await message.answer(help_text, parse_mode="MarkdownV2")
