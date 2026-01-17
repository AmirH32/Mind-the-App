# utils/config.py
import os
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_SEARCH_ENGINE_ID = os.getenv("GOOGLE_SEARCH_ENGINE_ID")
SEARCH_RESULTS_FILE = os.getenv("SEARCH_RESULTS_FILE")
EXPANDED_QUERIES_FILE = os.getenv("EXPANDED_QUERIES_FILE")
DOWNLOAD_DIRECTORY = os.getenv("DOWNLOAD_DIRECTORY")
DIRECT_DOWNLOADS_FILE = os.getenv("DIRECT_DOWNLOADS_FILE")
