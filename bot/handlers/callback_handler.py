import json
import os
import html
import tempfile

from datetime import datetime
from aiogram.types import InputFile, FSInputFile
from aiogram import Router, types, F
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.fsm.context import FSMContext
from aiogram.filters.state import StateFilter
from aiogram.fsm.state import State, StatesGroup
from bot.api_services.nvd_service import NVDService
from bot.api_services.virus_total import VirusTotalAPI 
from bot.utils.reports import SecurityReportGenerator
from bot.utils.message_utils import convert_markdown_to_html
from bot.config import redis_client, LANGUAGES, VIRUS_TOTAL_TOKEN
from bot.database.db import Database
from bot.handlers.message_handler import send_cve_list
from bot.keyboards.buttons import main_menu
from bot.keyboards.inline_btns import settings_menu, notif_menu
from bot.ai_services.ai_desc import CVESummarizer

router = Router()
nvd = NVDService()
db = Database()
vt_api = VirusTotalAPI(VIRUS_TOTAL_TOKEN)
gen_rep = SecurityReportGenerator()

#Language preferences callback


@router.callback_query(lambda c: c.data.startswith("lang_"))
async def lang_pref(callback: types.CallbackQuery):
    lang = callback.data.split("_")[-1]
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    first_name = callback.from_user.first_name
    username = callback.from_user.username
    
    await db.add_user(chat_id, first_name, username, lang)
    await callback.bot.delete_message(
        chat_id = chat_id,
        message_id = message_id,
    )
    menu = await main_menu(callback, lang)
    welcome_message = ("👋 *Welcome to SENTRA*\n"
            "_Your AI-powered cybersecurity bulletin assistant_\n\n"
            "🛡 Stay ahead of emerging threats with real-time CVE alerts, curated from trusted sources like the *NVD*.\n\n"
            "🔍 Monitor vulnerabilities by *keywords*, *technologies*, or *vendors* relevant to *you*.\n\n"
            "❓ Use /help command to explore all available commands and features\n\n"
            "ℹ️ Use the menu below to explore features and customize your security feed.")
    
    await callback.message.answer(welcome_message, reply_markup=menu, parse_mode="Markdown")


#Pagination page flipping
@router.callback_query(lambda c: c.data.startswith("page_"))
async def change_page(callback: types.CallbackQuery):
    page = int(callback.data.split("_")[1])
    await send_cve_list(callback, page, is_callback=True)

#NVD service bulletin callback for "detailes"
@router.callback_query(lambda c: c.data.startswith("details_"))
async def show_details(callback: types.CallbackQuery):
    data_parts = callback.data.split("_")
    bulletin_id = data_parts[1]

    page_or_source = data_parts[2] if len(data_parts) > 2 else "pagination"    
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    cached_bulletin = redis_client.get("cve_bulletin")
    if not cached_bulletin:
        await callback.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text="No security bulletins are currently available. Please try again later."
        )
        return
    try:
        bulletins = json.loads(cached_bulletin)
    except json.JSONDecodeError:
        await callback.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text="Error retrieving security bulletins. Please contact support."
        )
        return
    for bulletin in bulletins:
        cve_id = bulletin.get("cve_id", "Unknown CVE ID")
        if cve_id == bulletin_id:   
            cve_desc = bulletin.get("description", "No description available.")
            cve_desc_safe = html.escape(cve_desc)
            cve_publ_date = bulletin.get("published", "N/A")
            cve_base_score = bulletin.get("severity", "N/A")        

            if page_or_source.isdigit():
                back_callback = f"back_to_list_{page_or_source}"
            else:
                back_callback = f"back_to_notification_{bulletin_id}"

            buttons = [
                [
                    types.InlineKeyboardButton(text="AI Explain", callback_data=f"summarize_{bulletin_id}"),
                    types.InlineKeyboardButton(text="Back", callback_data=back_callback)                    
                ]
            ]

            back_btn = types.InlineKeyboardMarkup(inline_keyboard=buttons)

            await callback.bot.edit_message_text(   
                chat_id=chat_id,
                message_id=message_id,
                text=f"<b>Published date:</b> {cve_publ_date}\n<b>Base Score:</b> {cve_base_score}\n\n<b>Description:</b>\n{cve_desc_safe}\n<a href='https://nvd.nist.gov/vuln/detail/{bulletin['cve_id']}'>🔗 More Info</a>",
                reply_markup=back_btn,
                parse_mode="HTML"
            )
            return
    await callback.bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text=f"No details found for Bulletin ID: {bulletin_id}."
    )


#AI summarize callback
@router.callback_query(lambda c: c.data.startswith("summarize_"))
async def summarize_cve(callback: types.CallbackQuery):
    bulletin_id = callback.data.split("_")[1]
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id

    await callback.answer("🧠 Generating summary...")
    cached_bulletin = redis_client.get("cve_bulletin")
    if not cached_bulletin:
        await callback.bot.answer_callback_query(callback.id, text="❌ No data found.")
        return

    try:
        bulletins = json.loads(cached_bulletin)
    except json.JSONDecodeError:
        await callback.bot.answer_callback_query(callback.id, text="❌ Error decoding CVE data.")
        return

    for bulletin in bulletins:
        if bulletin.get("cve_id") == bulletin_id:
            description = bulletin.get("description", "No description available.")

            await callback.bot.send_message(
                chat_id=chat_id,
                text="🧠 Summarizing CVE bulletin... Please wait."
            )

            summarizer = CVESummarizer()
            summary = await summarizer.summarize(description)


            formatted_summary = convert_markdown_to_html(summary)
            safe_summary = html.escape(formatted_summary, quote=False)
            safe_summary = safe_summary.replace('&lt;b&gt;', '<b>').replace('&lt;/b&gt;', '</b>')
            safe_summary = safe_summary.replace('&lt;i&gt;', '<i>').replace('&lt;/i&gt;', '</i>')
            safe_summary = safe_summary.replace('&lt;code&gt;', '<code>').replace('&lt;/code&gt;', '</code>')
            safe_summary = safe_summary.replace('&lt;a href=&quot;', '<a href="').replace('&quot;&gt;', '">').replace('&lt;/a&gt;', '</a>')

            await callback.bot.send_message(
                chat_id=chat_id,
                text=f"🔍 <b>AI Summary for {html.escape(bulletin_id)}</b>\n\n{safe_summary}",
                parse_mode="HTML"
            )
            return

    await callback.bot.answer_callback_query(callback.id, text="❌ Bulletin not found.")

#Pagination 
@router.callback_query(lambda c: c.data.startswith("back_to_list_"))
async def back_to_list(callback: types.CallbackQuery):
    page = int(callback.data.split("_")[-1]) 
    await send_cve_list(callback, page=page, is_callback=True)

#back to notification
@router.callback_query(lambda c: c.data.startswith("back_to_notification_"))
async def back_to_notification(callback: types.CallbackQuery):
    cve_id = callback.data.split("_")[-1]
    cached_bulletin = redis_client.get("cve_bulletin")

    if not cached_bulletin:
        await callback.bot.edit_message_text(
            chat_id=callback.message.chat.id,
            message_id=callback.message.message_id,
            text="No security bulletins are currently available. Please try again later."
        )
        return

    try:
        bulletins = json.loads(cached_bulletin)
    except json.JSONDecodeError:
        await callback.bot.edit_message_text(
            chat_id=callback.message.chat.id,
            message_id=callback.message.message_id,
            text="Error retrieving security bulletins. Please contact support."
        )
        return

    for bulletin in bulletins:
        if bulletin.get("cve_id") == cve_id:
            message_text = (
                f"🔴 *CVE Alert!*\n"
                f"📌 *ID:* {bulletin['cve_id']}\n"
                f"🛠 *Severity:* {bulletin['severity']}\n"
                f"📅 *Date:* {bulletin['published']}\n"
            )
            buttons = [[types.InlineKeyboardButton(text="Details", callback_data=f"details_{cve_id}_notification")]]
            keyboard = types.InlineKeyboardMarkup(inline_keyboard=buttons)

            await callback.bot.edit_message_text(
                chat_id=callback.message.chat.id,
                message_id=callback.message.message_id,
                text=message_text,
                reply_markup=keyboard,
                parse_mode="Markdown",
                disable_web_page_preview=True
            )
            return

    await callback.bot.edit_message_text(
        chat_id=callback.message.chat.id,
        message_id=callback.message.message_id,
        text="CVE Alert details not found."
    )

#Notification settings callback
@router.callback_query(lambda c: c.data == "notifications")
async def notification_set(callback: types.CallbackQuery):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    buttons = await notif_menu(callback.message)
    await callback.bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text="Notification settings",
        reply_markup=buttons
    )

@router.callback_query(lambda c: c.data == "language")
async def change_lang(callback: types.CallbackQuery):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    lang_btns = [
            [
                types.InlineKeyboardButton(text='English', callback_data= "set_lang_en")
            ],
            [
                types.InlineKeyboardButton(text='Русский', callback_data= "set_lang_ru")
            ],
            [
                types.InlineKeyboardButton(text='Қазақша', callback_data= "set_lang_kk")
            ],
            [
                types.InlineKeyboardButton(text='⬅', callback_data="settings_menu")
            ],
        ]
    
    lang_preferences_btn = types.InlineKeyboardMarkup(inline_keyboard=lang_btns)

    await callback.bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text="Выберите язык / Choose language / Тілді таңдаңыз",
        reply_markup=lang_preferences_btn
    )

@router.callback_query(lambda c: c.data.startswith("set_lang_"))
async def set_language(callback: types.CallbackQuery):
    new_lang = callback.data.split("_")[-1] 
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    await callback.bot.delete_message(
        chat_id = chat_id,
        message_id = message_id
    )

    await db.set_user_language(chat_id, new_lang)
    
    #keyboard = await settings_menu(callback.message)
    back_menu = await main_menu(callback.message, new_lang)
    confirmation_text = LANGUAGES.get(new_lang, LANGUAGES["en"])["language_changed"]
    await callback.message.answer(confirmation_text, reply_markup=back_menu)

#Settings back btn callback
@router.callback_query(lambda c: c.data == "settings_menu")
async def back_to_setting(callback: types.CallbackQuery):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    set_menu = await settings_menu(callback.message)
    await callback.bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text="Settings",
        reply_markup=set_menu
    )


@router.callback_query(lambda c: c.data == "subscribe")
async def subscription(callback: types.CallbackQuery, state: FSMContext):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    
    await state.update_data(current_page=0)
    
    all_sources = await db.get_all_sources()
    user_sources = await db.get_user_subscribed_sources(chat_id)

    if not user_sources:
        user_sources = all_sources.copy()

    buttons = []
    row = []
    
    for i, source in enumerate(all_sources, 1):
        prefix = "✓ " if source in user_sources else ""
        row.append(types.InlineKeyboardButton(
            text=f"{prefix}{source}", 
            callback_data=f"subscribe_{source}"
        ))
        
        if i % 3 == 0:
            buttons.append(row)
            row = []
    
    if row:
        buttons.append(row)
    
    # Add navigation buttons
    navigation_buttons = [
        types.InlineKeyboardButton(text="⬅ Back", callback_data="settings_menu"),
    ]
    buttons.append(navigation_buttons)
    
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=buttons)
    
    await callback.bot.edit_message_text(
        chat_id=chat_id,
        message_id=message_id,
        text="🔔 *Subscription Settings*\n\nSelect vendors to subscribe:\n✓ = already subscribed",
        parse_mode="Markdown",
        reply_markup=keyboard
    )


@router.callback_query(lambda c: c.data.startswith("subscribe_") and "::" not in c.data)
async def toggle_user_subscription(callback: types.CallbackQuery, state: FSMContext):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    source_name = callback.data.replace("subscribe_", "")

    source_id = await db.get_source_id_by_name(source_name)
    if not source_id:
        await callback.answer("❌ Source not found.")
        return

    is_subscribed = await db.is_user_subscribed_to_source(chat_id, source_id)

    if is_subscribed:
        await db.unsubscribe_user_from_source(chat_id, source_id)
        await callback.answer(f"🔕 Unsubscribed from {source_name}")
    else:
        await db.subscribe_user_to_source(chat_id, source_id)
        await callback.answer(f"🔔 Subscribed to {source_name}")

    await subscription(callback, state)  # Reuse existing UI rendering



#Back btn callback
@router.callback_query(lambda c: c.data == "delete_msg")
async def settings_back(callback: types.CallbackQuery):
    chat_id = callback.message.chat.id
    message_id = callback.message.message_id
    await callback.bot.delete_message(
        chat_id = chat_id,
        message_id = message_id
    )
        
         
@router.callback_query(lambda c: c.data == "back_to_main_menu")
async def back_to_main_menu( callback: types.CallbackQuery):
    user_lang = await db.get_user_language(callback.message.chat.id)
    menu = await main_menu(callback.message, user_lang)
    await callback.message.answer(
        text="Main Menu",
        reply_markup=menu
    )
    
'''=============== Virus Total file generation callback =================='''

@router.callback_query(F.data == "vt_generate_report")
async def generate_vt_txt_report(callback_query: types.CallbackQuery, state: FSMContext):
    user_data = await state.get_data()
    query = user_data.get("vt_query")
    input_type = user_data.get("vt_input_type")

    if not query or not input_type:
        await callback_query.message.answer("❌ No data found for report generation.")
        return

    await callback_query.answer("📄 Generating report...")
    result = await vt_api.query(input_type, query)
    if not result:
        await callback_query.message.answer("❌ No result found.")
        return

    attributes = result.get("data", {}).get("attributes", {})

    report = gen_rep.generate_vt_pdf(input_type, query, attributes)
    await callback_query.message.answer_document(FSInputFile(report, filename="VirusTotal_Report.pdf"))

    import os
    try:
        os.unlink(report)
    except:
        pass


