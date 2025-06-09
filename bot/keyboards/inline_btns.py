from aiogram import Router, types, F
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import Message
from bot.config import LANGUAGES
from bot.database.db import Database

router = Router()
db = Database()

#Lang preferences buttons
async def lang_preferences(message: Message):
    lang_btns = [
            [
                types.InlineKeyboardButton(text='English', callback_data= "lang_en")
            ],
            [
                types.InlineKeyboardButton(text='Русский', callback_data= "lang_ru")
            ],
            [
                types.InlineKeyboardButton(text='Қазақша', callback_data= "lang_kk")
            ],
            [
                types.InlineKeyboardButton(text='⬅', callback_data="settings_menu")
            ]
        ]
    lang_preferences_btn = types.InlineKeyboardMarkup(inline_keyboard=lang_btns)
    return lang_preferences_btn


#Settings menu buttons
async def settings_menu(message: Message):
    chat_id = message.chat.id
    user_lang = await db.get_user_language(chat_id)

    settings_texts = LANGUAGES.get(user_lang, LANGUAGES["en"])["settings"]
    settings = [
            [
                types.InlineKeyboardButton(text=settings_texts["notifications"], callback_data= "notifications"),
                types.InlineKeyboardButton(text=settings_texts["language"], callback_data= "language")
            ],
            [types.InlineKeyboardButton(text=settings_texts["back"], callback_data="delete_msg")]
        ]
    settings_btn = types.InlineKeyboardMarkup(inline_keyboard=settings)
    return settings_btn


async def notif_menu(message: Message):
    buttons = [
                [types.InlineKeyboardButton(text='🔔Enabled', callback_data="if_notif_enabled"),
                types.InlineKeyboardButton(text="➕Subscriptions", callback_data="subscribe")
                ],
                [types.InlineKeyboardButton(text="⬅Back", callback_data="settings_menu")]
            ]
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=buttons)
    return keyboard

