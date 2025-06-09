import logging
import asyncio
from aiogram import Bot, Dispatcher
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from bot.database.db import Database
from bot.config import BOT_TOKEN
from bot.handlers import message_handler, callback_handler
from bot.command_handlers import start
from bot.command_handlers.search import inline_search
from bot.command_handlers import menu
from bot.notification_logic.notify import NotificationService  
from bot.api_services.nvd_service import NVDService

# Configure logging
logging.basicConfig(
    lev2el=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/bot.log"),
        logging.StreamHandler()
    ])

async def check_and_notify():
    try:
        nvd_service = NVDService()
        notification_service = NotificationService(BOT_TOKEN)
        
        await nvd_service.get_cve_bulletin()
        await notification_service.send_cve_notifications()

    except Exception as e:
        logging.error(f"❌ Error in check_and_notify: {e}")

async def main():
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    db = Database()
    await db.init_db()

    dp.include_router(start.router)
    dp.include_router(menu.router)
    dp.inline_query.register(inline_search)

    dp.include_router(message_handler.router)
    dp.include_router(callback_handler.router)
    

    scheduler = AsyncIOScheduler()
    scheduler.add_job(check_and_notify, "interval", minutes=15)
    scheduler.start()

    try:
        logging.info("🤖 Bot is running...")
        await dp.start_polling(bot)
    except Exception as e:
        logging.error(f"❌ Error: {e}")
    finally:
        logging.info("🛑 Bot is shutting down...")
        await bot.session.close()
        scheduler.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("🛑 Bot stopped by user.")
