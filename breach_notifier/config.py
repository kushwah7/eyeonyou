# config.py
from dotenv import load_dotenv
import os

load_dotenv()

# API Keys
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_NUMBER = os.getenv("TWILIO_NUMBER")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///breach_notifier.db")

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
INTELX_API_KEY = os.getenv("INTELX_API_KEY")
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")
