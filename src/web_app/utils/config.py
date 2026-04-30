from dotenv import load_dotenv
import os

load_dotenv()

S_KEY = os.getenv("S_KEY")
MODELS_FOLDER = os.getenv("MODELS_FOLDER")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER")
JSON_PATH = os.getenv("JSON_PATH")
