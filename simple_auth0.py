"""
Simplified Auth0 Integration
"""

import requests
from urllib.parse import urlencode
from flask import session, redirect, url_for, flash, current_app
from auth0_config import Auth0Config


class SimpleAuth0:
    """Simplified Auth0 integration that reads settings from environment variables"""

    def __init__(self):
        self.domain = Auth0Config.AUTH0_DOMAIN
        self.client_id = Auth0Config.AUTH0_CLIENT_ID
        self.client_secret = Auth0Config.AUTH0_CLIENT_SECRET
        self.callback_url = Auth0Config.AUTH0_CALLBACK_URL
        self.logout_url = Auth0Config.AUTH0_LOGOUT_URL
        self.scope = Auth0Config.AUTH0_SCOPE

    def get_login_url(self):
        """Get Auth0 login URL"""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.callback_url,
            'scope': self.scope,
            # Use the userinfo endpoint as a generic audience if none provided
            'audience': f'https://{self.domain}/userinfo'
        }

        auth_url = f'https://{self.domain}/authorize?{urlencode(params)}'
        return auth_url

    def get_logout_url(self):
        """Get Auth0 logout URL"""
        params = {
            'client_id': self.client_id,
            'returnTo': self.logout_url
        }

        logout_url = f'https://{self.domain}/v2/logout?{urlencode(params)}'
        return logout_url

    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        token_url = f'https://{self.domain}/oauth/token'

        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.callback_url
        }

        response = requests.post(token_url, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Token exchange failed: {response.status_code} - {response.text}")
            return None

    def get_user_info(self, access_token):
        """Get user info from Auth0"""
        userinfo_url = f'https://{self.domain}/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.get(userinfo_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"User info failed: {response.status_code} - {response.text}")
            return None


# Global instance
simple_auth0 = SimpleAuth0()

