import redis
import json

from aiogram import Router
from aiogram.types import Message
from aiogram.filters import Command 
from aiogram.fsm.context import FSMContext
from aiogram.filters.state import StateFilter
from aiogram.fsm.state import State, StatesGroup

from bot.states.user_states import NameState
from bot.keyboards.buttons import main_menu
from bot.keyboards.inline_btns import lang_preferences
from bot.database.db import Database
from bot.api_services.nvd_service import NVDService
from bot.config import LANGUAGES

from bot.handlers.message_handler import redis_client

router = Router()
db = Database()
nvd = NVDService()

@router.message(Command("start"))
async def start(message: Message, state: FSMContext):
    chat_id = message.chat.id
    user_lang = await db.get_user_language(chat_id)

    if await db.is_registered(chat_id):
        menu = await main_menu(chat_id, user_lang) 
        await message.answer(
            "👋 *Welcome to SENTRA*\n"
            "_Your AI-powered cybersecurity bulletin assistant_\n\n"
            "🛡 Stay ahead of emerging threats with real-time CVE alerts, curated from trusted sources like the *NVD*.\n\n"
            "🔍 Monitor vulnerabilities by *keywords*, *technologies*, or *vendors* relevant to *you*.\n\n"
            "❓ Use /help command to explore all available commands and features\n\n"
            "ℹ️ Use the menu below to explore features and customize your security feed.",
            parse_mode="Markdown",
            reply_markup=menu
        )

    else:                    
        await message.answer("Choose language:/Выберите язык:/Тілді таңдаңыз:", reply_markup=await lang_preferences(message))
    
    '''
    bulletin = await nvd.get_cve_bulletin()
    if bulletin:
        redis_client.set("cve_bulletin", json.dumps(bulletin))
        print('Bulletins stored to cache')
    else:
        print("Failed to retrieve the bulletin")
    '''