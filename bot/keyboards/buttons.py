from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup,InlineKeyboardButton
from aiogram.utils.keyboard import ReplyKeyboardBuilder
from bot.config import LANGUAGES

#Main menu buttons
async def main_menu(message: Message, user_lang: str):
    builder = ReplyKeyboardBuilder()
    menu = LANGUAGES.get(user_lang, LANGUAGES["en"])["main_menu"]

    builder.row(
        KeyboardButton(text=menu["bulletins"]),
        KeyboardButton(text=menu["recommendation"])            
    )
    builder.row(
        KeyboardButton(text=menu["tools"]),
        KeyboardButton(text=menu["settings"])
    )
    keyboard = builder.as_markup(resize_keyboard=True)
    return keyboard


#Risk assessment tools menu buttons
async def risk_assessment_menu(message: Message, user_lang: str):
    builder = ReplyKeyboardBuilder()
    risk_menu = LANGUAGES.get(user_lang, LANGUAGES["en"])["risk_assessment"]
    
    builder.row(KeyboardButton(text=risk_menu["full_scan"]))
    
    
    builder.row(
        KeyboardButton(text=risk_menu["virus_total"]),
        KeyboardButton(text=risk_menu["whois"]),
    )
    builder.row(
        KeyboardButton(text=risk_menu["analyze_file"])
    )

    builder.row(KeyboardButton(text=risk_menu["back"]))
    
    keyboard = builder.as_markup(resize_keyboard=True)
    return keyboard


async def cancel_tool(message : Message, user_lang: str):
    builder = ReplyKeyboardBuilder()
    risk_menu = LANGUAGES.get(user_lang, LANGUAGES["en"])["risk_assessment"]

    builder.add(KeyboardButton(text=risk_menu["cancel"]))
    keyboard = builder.as_markup(resize_keyboard=True)
    return keyboard



async def cyber_mentor_btns(message: Message):
    builder = ReplyKeyboardBuilder()

    builder.row(
        KeyboardButton(text='🎣 Phishing'),
    )
    builder.row(
        KeyboardButton(text='💥 Ransomware')
    )

    builder.row(
        KeyboardButton(text='🪝 Social Engineering')
    )

    builder.row(
        KeyboardButton(text='📦 Supply Chain')
    )

    builder.row(
        KeyboardButton(text='🛠 Secure Coding')
    )

    builder.row(KeyboardButton(text='🔙 Back'))
    
    keyboard = builder.as_markup(resize_keyboard=True)
    return keyboard