import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybersentinel-ultra-secret-key-2024')
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRY_HOURS = 24

    # Database
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MONGO_URI = os.environ.get('MONGO_URI', '')
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'cyber_sentinel')
    
    # ML Models path
    MODELS_DIR = os.path.join(BASE_DIR, 'models')

    # External APIs (loaded securely from .env)
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')
    GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', '')
    GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-3.6-flash')

    # Admin seed credentials
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@cybersentinel.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@2024')
    ADMIN_NAME = 'Super Admin'

    # Request timeout for link inspection
    REQUEST_TIMEOUT = 8

    # CORS
    CORS_ORIGINS = ['http://localhost:5500', 'http://127.0.0.1:5500',
                    'http://localhost:3000', 'http://127.0.0.1:3000',
                    'null']  # for file:// protocol
                    