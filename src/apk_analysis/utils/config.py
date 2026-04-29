# utils/config.py
import os
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path)

APK_DIR = os.getenv("APK_DIR")
OUTPUT_CSV = os.getenv("OUTPUT_CSV")
JSON_PATH = os.getenv("JSON_PATH")
