"""
Auth0 Configuration for Political Event Management System
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Auth0Config:
    """Auth0 configuration settings"""
    
    # Auth0 Domain (replace with your Auth0 domain)
    AUTH0_DOMAIN = os.getenv('AUTH0_DOMAIN', '')
    
    # Auth0 Client ID (replace with your Auth0 client ID)
    AUTH0_CLIENT_ID = os.getenv('AUTH0_CLIENT_ID', '')
    
    # Auth0 Client Secret (replace with your Auth0 client secret)
    AUTH0_CLIENT_SECRET = os.getenv('AUTH0_CLIENT_SECRET', '')
    
    # Auth0 Audience (API identifier)
    AUTH0_AUDIENCE = os.getenv('AUTH0_AUDIENCE', 'https://your-api-identifier')
    
    # Callback URL (where Auth0 redirects after login)
    AUTH0_CALLBACK_URL = os.getenv('AUTH0_CALLBACK_URL', 'http://localhost:5000/callback')
    
    # Logout URL (where Auth0 redirects after logout)
    AUTH0_LOGOUT_URL = os.getenv('AUTH0_LOGOUT_URL', 'http://localhost:5000')
    
    # Auth0 API Base URL
    AUTH0_API_BASE_URL = f'https://{AUTH0_DOMAIN}'
    
    # Auth0 Authorization URL
    AUTH0_AUTHORIZE_URL = f'https://{AUTH0_DOMAIN}/authorize'
    
    # Auth0 Token URL
    AUTH0_TOKEN_URL = f'https://{AUTH0_DOMAIN}/oauth/token'
    
    # Auth0 User Info URL
    AUTH0_USERINFO_URL = f'https://{AUTH0_DOMAIN}/userinfo'
    
    # Auth0 Logout URL
    AUTH0_LOGOUT_REDIRECT_URL = f'https://{AUTH0_DOMAIN}/v2/logout'
    
    # Scopes for user authentication
    AUTH0_SCOPE = 'openid profile email'
    
    # Session secret for Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
    
    @classmethod
    def get_auth0_config(cls):
        """Get Auth0 configuration as dictionary"""
        return {
            'AUTH0_DOMAIN': cls.AUTH0_DOMAIN,
            'AUTH0_CLIENT_ID': cls.AUTH0_CLIENT_ID,
            'AUTH0_CLIENT_SECRET': cls.AUTH0_CLIENT_SECRET,
            'AUTH0_AUDIENCE': cls.AUTH0_AUDIENCE,
            'AUTH0_CALLBACK_URL': cls.AUTH0_CALLBACK_URL,
            'AUTH0_LOGOUT_URL': cls.AUTH0_LOGOUT_URL,
            'AUTH0_API_BASE_URL': cls.AUTH0_API_BASE_URL,
            'AUTH0_AUTHORIZE_URL': cls.AUTH0_AUTHORIZE_URL,
            'AUTH0_TOKEN_URL': cls.AUTH0_TOKEN_URL,
            'AUTH0_USERINFO_URL': cls.AUTH0_USERINFO_URL,
            'AUTH0_LOGOUT_REDIRECT_URL': cls.AUTH0_LOGOUT_REDIRECT_URL,
            'AUTH0_SCOPE': cls.AUTH0_SCOPE,
            'SECRET_KEY': cls.SECRET_KEY
        }
