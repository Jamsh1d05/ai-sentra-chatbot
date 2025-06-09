import json

from aiogram.types import Message
from bot.config import redis_client
from aiogram import Router, types, F
from aiogram.fsm.context import FSMContext
from aiogram.filters.state import StateFilter
from aiogram.fsm.state import State, StatesGroup
from bot.database.db import Database
from bot.utils.message_utils import send_long_message
from bot.config import LANGUAGES, VIRUS_TOTAL_TOKEN, SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET
from bot.states.user_states import VirusTotal, UploadFile, Shodan, Censys, Whois, FullScan
from bot.keyboards.inline_btns import settings_menu
from bot.keyboards.buttons import risk_assessment_menu, main_menu, cancel_tool, cyber_mentor_btns
from bot.api_services.nvd_service import NVDService
from bot.api_services.log_analyze import process_log_file
from bot.api_services.full_scan_apis import scan_all, format_scan_results
from bot.api_services.virus_total import VirusTotalAPI, detect_input_type, format_vt_result
from bot.api_services.shodan_api import ShodanService
from bot.api_services.censys_api import CensysAPI
from bot.api_services.whois_api import query_whois
from bot.api_services.abuseipdb_api import scan_abuseipdb


router = Router()
nvd = NVDService()
db = Database()
vt_api = VirusTotalAPI(VIRUS_TOTAL_TOKEN)
shodan_api = ShodanService(SHODAN_API_KEY)
censys_api = CensysAPI(CENSYS_API_ID, CENSYS_API_SECRET)

PAGE_SIZE = 5

'''================= Command handler functions ===================='''

async def send_bulletins(message: Message):
    await send_cve_list(message)

async def subs(message: Message):
    await message.answer("Choose a topic:")

async def settings(message: Message):
    set_menu = await settings_menu(message)
    await message.answer("Settings", reply_markup=set_menu)

async def risk_assessment(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    tools = await risk_assessment_menu(message,user_lang)
    await message.answer("Available tools", reply_markup=tools)

async def help_and_about(message: Message):
    await message.answer("Here is some help info.")

async def action_back(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    menu = await main_menu(message, user_lang)
    await message.answer("Getting back", reply_markup=menu)

async def full_scan(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Enter what you want to scan: ", reply_markup=cancel)
    await state.set_state(FullScan.waitingforfullscaninput)

async def virusTotal(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Please send me an IP, domain, hash or URL to check on VirusTotal.", reply_markup=cancel)
    await state.set_state(VirusTotal.waitingforinput)

async def shodan(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Not available for now!", reply_markup=cancel)
    #await state.set_state(Shodan.waitingforshodaninput)

async def censys(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Censys", reply_markup=cancel)

async def abuse_ipdb(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    #result = await scan_abuseipdb("ip_addr")
    await message.answer("Abuse IPDB", reply_markup=cancel)

async def whois(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Enter a domain name to scan: ", reply_markup=cancel)
    await state.set_state(Whois.waitingforwhoisinput)

async def hibp(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Have I Been Pwned", reply_markup=cancel)

async def hybrid_analysis(message: Message):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Hybrid Analysis", reply_markup=cancel)

async def analyze_file(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel = await cancel_tool(message, user_lang)
    await message.answer("Please upload your log file (.csv, .json, .log ).", reply_markup=cancel)
    await state.set_state(UploadFile.waitingforfile) 

async def cancel_process(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    tools = await risk_assessment_menu(message, user_lang)
    await message.answer("🔙 Process cancelled", reply_markup=tools)
    await state.clear()


'''================= CVE pagination logic ===================='''

async def send_cve_list(message_or_callback, page=0, is_callback=False):
    cached_bulletin = redis_client.get("cve_bulletin")
    if cached_bulletin:
        bulletins = json.loads(cached_bulletin)
    else:
        bulletins = await nvd.get_cve_bulletin()
        redis_client.set("cve_bulletin", json.dumps(bulletins))

    total_pages = (len(bulletins) - 1) // PAGE_SIZE + 1
    start = page * PAGE_SIZE
    end = start + PAGE_SIZE

    message_text = f"🛡️ Latest Bulletins (Page {page + 1}/{total_pages})"
    buttons = []

    for bulletin in bulletins[start:end]:
        cve_id = bulletin.get("cve_id", "N/A")
        severity_parts = bulletin["severity"].split(", ")
        severity = severity_parts[1] if len(severity_parts) > 1 else "N/A"
        if cve_id:
            buttons.append([types.InlineKeyboardButton(
                text=f"{cve_id} ({severity})", callback_data=f"details_{cve_id}_{page}")])

    navigation_buttons = []
    
    prev_page = total_pages - 1 if page == 0 else page - 1
    next_page = 0 if page == total_pages - 1 else page + 1

    navigation_buttons.append(
        types.InlineKeyboardButton(text="⬅", callback_data=f"page_{prev_page}")
        )
    navigation_buttons.append(
        types.InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="ignore")
        )
    navigation_buttons.append(
        types.InlineKeyboardButton(text="➡", callback_data=f"page_{next_page}")
        )
    buttons.append(navigation_buttons)
    buttons.append(
        [types.InlineKeyboardButton(text="Exit", callback_data="delete_msg")]
        )
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=buttons)

    if is_callback:
        await message_or_callback.message.edit_text(
            text=message_text,
            reply_markup=keyboard,
            parse_mode="HTML"
        )
    else: 
        if bulletins:
            await message_or_callback.answer(message_text, reply_markup=keyboard, parse_mode="HTML")
        else:
            await message_or_callback.answer("No bulletins found!", show_alert=True)
    
    
'''================= File analize handlers ===================='''

#Full IOC scan 
@router.message(FullScan.waitingforfullscaninput, F.text)
async def full_scan_func(message: Message, state: FSMContext):
    ioc = message.text.strip()
    ioc_type = detect_input_type(ioc)

    if ioc_type not in {"ip", "domain", "url", "hash"}:
        await message.answer("⚠️ Invalid IOC type. Please send a valid IP address, domain, URL, or file hash.")
        return

    await message.answer("⏳ Scanning... This may take a few seconds.")

    try:
        result_data = await scan_all(ioc)
        formatted_report = format_scan_results(result_data)
        await message.answer(formatted_report, parse_mode="HTML", disable_web_page_preview=True)
    except Exception as e:
        await message.answer(f"❌ Error occurred during scan:\n<code>{str(e)}</code>", parse_mode="HTML")

    await state.clear()


#Virus Total input handler
@router.message(VirusTotal.waitingforinput, F.text)
async def handle_vt_text(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel_btn_lang = LANGUAGES.get(user_lang,  LANGUAGES["en"])["risk_assessment"]
    query = message.text.strip()
    
    if query == cancel_btn_lang["cancel"]:
        await cancel_process(message, state)
        return
    
    input_type = detect_input_type(query)
    if input_type == "unknown":
        await message.answer("❌ Invalid input format. Please enter the correct one! ")
        return    
    
    loading_msg = await message.answer("🔍 Checking with VirusTotal API...")
    try:
        result = await vt_api.query(input_type, query)
        
        if isinstance(result, dict) and result.get("data"): 
            formatted_result = format_vt_result(result, input_type, query)  
            await state.update_data(vt_query=query, vt_input_type=input_type)

            keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
                [types.InlineKeyboardButton(text="📝 Generate Report", callback_data="vt_generate_report")]
            ])
            await message.answer(formatted_result, parse_mode="HTML", reply_markup=keyboard)
        else:
            await loading_msg.delete()
            await message.answer("❌ No results available for the given input.")
    except Exception as e:
        await loading_msg.delete()
        await message.answer(f"❌ Error connecting to VirusTotal: {str(e)}")
        await cancel_process(message, state)
        

#wHO IS input handler
@router.message(Whois.waitingforwhoisinput, F.text)
async def handle_whois_input(message: types.Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    cancel_btn_lang = LANGUAGES.get(user_lang, LANGUAGES["en"])["risk_assessment"]
    query = message.text.strip()
    if query == cancel_btn_lang["cancel"]:
        await cancel_process(message, state)
        return

    await message.answer("🔍Scanning....")
    try:
        result = await query_whois(query)

        if result:
            await message.answer(result, parse_mode="HTML")
        else:
            await message.answer("❌ No WHOIS data found for the given input.")
    except Exception as e:
        await message.answer(f"❌ Error during WHOIS lookup: {str(e)}")
        await cancel_process(message, state)
        

#Log files handler
@router.message(F.document, UploadFile.waitingforfile)
async def receive_log_file(message: Message, state: FSMContext):
    file_id = message.document.file_id
    file_name = message.document.file_name
    file_extension = file_name.split('.')[-1].lower()

    if file_extension not in ['log', 'csv', 'json']:
        await message.answer("❌ Unsupported file format. Please upload a CSV or JSON file.")
        return

    try:
        file = await message.bot.download(file=file_id)
        content = file
        
        result = await process_log_file(content, file_extension)
        if result["status"] == "success":
            await message.answer("✅ Log file received! Processing...")
            report = result["report"]
            await message.answer(f"📊 Log Analysis Report:\n\n{report}")
            await db.save_log_metadata(message.from_user.id, file_name)

        else:
            await message.answer(f"❌ Error processing log: {result['message']}")
            await cancel_process(message, state)


    except Exception as e:
        await message.answer(f"❌ Failed to process file: {str(e)}")
        await cancel_process(message, state)


#Subscribtions
@router.message(lambda message: message.text == "My Subscriptions")
async def subscription(message: types.Message, state: FSMContext):
    chat_id = message.chat.id
    message_id = message.message_id

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

    navigation_buttons = [
        types.InlineKeyboardButton(text="Exit", callback_data="delete_msg"),
    ]
    buttons.append(navigation_buttons)

    keyboard = types.InlineKeyboardMarkup(inline_keyboard=buttons)

    await message.answer(
        text="🔔 *My Subscriptions*\n\nSelect vendors to subscribe:\n✓ = already subscribed",
        parse_mode="Markdown",
        reply_markup=keyboard
    )



''' Continue defining the function from here. '''

@router.message(F.text)
async def handle_message(message: Message, state: FSMContext):
    user_lang = await db.get_user_language(message.chat.id)
    menu = LANGUAGES.get(user_lang, LANGUAGES["en"])["main_menu"]
    tools = LANGUAGES.get(user_lang, LANGUAGES["en"])["risk_assessment"]

    COMMANDS = {
        menu["bulletins"]: send_bulletins,
        menu["recommendation"]: subs,
        menu["settings"]: settings,
        menu["tools"]: risk_assessment,
        menu["help"]: help_and_about,
        tools["full_scan"]: full_scan,
        tools["virus_total"]: virusTotal,
        tools["shodan"]: shodan,
        tools["censys"]: censys,
        tools["abuse_ipdb"]: abuse_ipdb,
        tools["whois"]: whois,
        tools["hibp"]: hibp,
        tools["hybrid_analysis"]: hybrid_analysis,
        tools["analyze_file"]:analyze_file,
        tools["back"]: action_back,
        tools["cancel"]: cancel_process,
        
    } 

    handler = COMMANDS.get(message.text)

    if handler is None:
        return

    if handler in [full_scan, virusTotal, shodan, censys, whois, analyze_file, cancel_process]:
        await handler(message, state)
    else:
        await handler(message)