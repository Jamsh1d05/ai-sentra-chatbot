import json
import os
import redis
from dotenv import load_dotenv

load_dotenv()

#Redis client
redis_client = redis.Redis(host="localhost", port=6379, db=0)

#Bot variables
BOT_TOKEN = os.getenv('BOT_TOKEN')
GIT_HUB_TOKEN = os.getenv('GIT_HUB')
NVD_TOKEN = os.getenv('NVD_API')
VIRUS_TOTAL_TOKEN = os.getenv('VIRUS_TOTAL')
SHODAN_API_KEY = os.getenv('SHODAN_KEY')
CENSYS_API_ID = os.getenv('CENSYS_API_ID')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')

if not BOT_TOKEN:
    raise ValueError("Telegram Bot token is missing!")

elif not GIT_HUB_TOKEN:
    raise ValueError("GitHub token is missing!")

elif not NVD_TOKEN:
    raise ValueError("NVD API token is missing")

elif not VIRUS_TOTAL_TOKEN:
    raise ValueError("Virus total token missing!")

elif not SHODAN_API_KEY:
    raise ValueError("Shodan API key is missing!")
'''
elif not CENSYS_API_ID and not CENSYS_API_SECRET:
    raise ValueError("Censys API ID and SECRET key is missing!")
''' 

#Path to dictionary
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LANGUAGE_FILE = os.path.join(BASE_DIR, "locales", "languages.json")

#json dictionary
with open(LANGUAGE_FILE, "r", encoding="utf-8") as file:
    LANGUAGES = json.load(file)
