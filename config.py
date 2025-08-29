import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'production-secret-key-change-this')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'secure_uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///political_events.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-this')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'admin@political.com')
    
    # Encryption key for file storage
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    # Hyperverge KYC Configuration
    HYPERVERGE_API_KEY = os.environ.get('HYPERVERGE_API_KEY')
    HYPERVERGE_API_SECRET = os.environ.get('HYPERVERGE_API_SECRET')
    
    # WhatsApp Business API Configuration
    WHATSAPP_ACCESS_TOKEN = os.environ.get('WHATSAPP_ACCESS_TOKEN')
    WHATSAPP_PHONE_NUMBER_ID = os.environ.get('WHATSAPP_PHONE_NUMBER_ID')
    WHATSAPP_BUSINESS_ACCOUNT_ID = os.environ.get('WHATSAPP_BUSINESS_ACCOUNT_ID')
    
    # Razorpay Configuration
    RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID')
    RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET')
    
    # Google Maps Configuration
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY')
    
    # Freshdesk CRM Configuration
    FRESHDESK_DOMAIN = os.environ.get('FRESHDESK_DOMAIN')
    FRESHDESK_API_KEY = os.environ.get('FRESHDESK_API_KEY')
    
    # Redis Configuration (for Celery)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Commission Configuration
    PLATFORM_COMMISSION_RATE = float(os.environ.get('PLATFORM_COMMISSION_RATE', '0.05'))  # 5%
    PAYMENT_GATEWAY_FEE_RATE = float(os.environ.get('PAYMENT_GATEWAY_FEE_RATE', '0.02'))  # 2%
    VOLUNTEER_PAYOUT_FEE_RATE = float(os.environ.get('VOLUNTEER_PAYOUT_FEE_RATE', '0.01'))  # 1%
    
    # Political Party Domains
    POLITICAL_PARTY_DOMAINS = [
        'dmk.in', 'aiadmk.in', 'bjp.org', 'inc.in', 'cpi.org',
        'cpim.org', 'ncp.org', 'sp.org', 'bsp.org', 'aap.org',
        'tdp.org', 'ysrcp.org', 'jdu.org', 'rjd.org', 'lsp.org'
    ]
    
    # OTP Configuration
    OTP_EXPIRY_MINUTES = int(os.environ.get('OTP_EXPIRY_MINUTES', '10'))
    MAX_OTP_ATTEMPTS = int(os.environ.get('MAX_OTP_ATTEMPTS', '3'))
    
    # Auto Matcher Configuration
    MATCH_SCORE_THRESHOLD = float(os.environ.get('MATCH_SCORE_THRESHOLD', '0.7'))
    MAX_VOLUNTEERS_PER_EVENT = int(os.environ.get('MAX_VOLUNTEERS_PER_EVENT', '5'))
    LOCATION_RADIUS_KM = float(os.environ.get('LOCATION_RADIUS_KM', '10.0'))

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///political_events_dev.db'

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///political_events_test.db'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
