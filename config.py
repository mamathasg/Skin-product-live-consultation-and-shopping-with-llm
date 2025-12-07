import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database Configuration
DB_URL = os.getenv("DB_URL", "mysql+pymysql://root:password@127.0.0.1/skincare_ecommerce")

# Create SQLAlchemy engine
engine = create_engine(DB_URL, echo=True)

# Function to get a raw DB connection
def get_db_connection():
    connection = engine.raw_connection()
    return connection

# Twilio account connection details
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_API_KEY_SID = os.getenv("TWILIO_API_KEY_SID")
TWILIO_API_KEY_SECRET = os.getenv("TWILIO_API_KEY_SECRET")

# LLM API Key
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

