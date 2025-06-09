import re

from aiogram.types import Message

MAX_LENGTH = 4096

async def send_long_message(message: Message, text: str, parse_mode="HTML"):
    chunks = [text[i:i + MAX_LENGTH] for i in range(0, len(text), MAX_LENGTH)]
    for chunk in chunks:
        await message.answer(chunk, parse_mode=parse_mode)


def escape_md(text: str) -> str:
    """
    Escapes special characters for Telegram Markdown V2 formatting.
    """
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', text)


def convert_markdown_to_html(text):
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    
    text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
    
    text = re.sub(r'`(.*?)`', r'<code>\1</code>', text)
    
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
    
    text = text.replace('---', '\n━━━━━━━━━━━━━━━━━━━━\n')
    
    return text