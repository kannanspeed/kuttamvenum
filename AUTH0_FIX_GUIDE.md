# Auth0 Configuration Fix Guide

## 🚨 Current Issue
```
invalid_request: Unknown client: KncNo39qJoF1M1h3T170TBM1CPWbDiAm
```

This error means Auth0 doesn't recognize the client ID. Here's how to fix it:

## 🔧 Step-by-Step Fix

### 1. **Verify Auth0 Application**
1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Make sure you're in the correct tenant: `dev-aclor2aljjfjnkuw.us.auth0.com`
3. Go to **Applications** → **Applications**
4. Find your application or create a new one

### 2. **Check Application Settings**
In your Auth0 application settings, verify:

#### **Application Type**
- **Type**: Regular Web Application
- **Token Endpoint Authentication Method**: Post

#### **Application URIs**
- **Allowed Callback URLs**: `http://localhost:5000/callback`
- **Allowed Logout URLs**: `http://localhost:5000`
- **Allowed Web Origins**: `http://localhost:5000`

#### **Application Login URI**
- **Application Login URI**: `http://localhost:5000/auth0/login`

### 3. **Get Correct Credentials**
1. In your Auth0 application settings, go to the **Settings** tab
2. Copy the **Domain**, **Client ID**, and **Client Secret**
3. Update the credentials in `simple_auth0.py` if they're different

### 4. **Update Credentials (if needed)**
If the credentials are different, update `simple_auth0.py`:

```python
def __init__(self):
    self.domain = 'YOUR_AUTH0_DOMAIN'  # Replace with your domain
    self.client_id = 'YOUR_CLIENT_ID'  # Replace with your client ID
    self.client_secret = 'YOUR_CLIENT_SECRET'  # Replace with your client secret
    self.callback_url = 'http://localhost:5000/callback'
    self.logout_url = 'http://localhost:5000'
    self.scope = 'openid profile email'
```

### 5. **Test the Configuration**
1. Start your Flask app: `python app.py`
2. Visit: `http://localhost:5000`
3. Click "Sign In with Auth0"
4. You should be redirected to Auth0 login page

## 🔍 Troubleshooting

### **If still getting "Unknown client" error:**

1. **Check Tenant**: Make sure you're in the correct Auth0 tenant
2. **Check Application**: Verify the application exists and is active
3. **Check Client ID**: Copy the exact Client ID from Auth0 dashboard
4. **Check Application Type**: Must be "Regular Web Application"

### **If getting other errors:**

1. **Callback URL mismatch**: Make sure callback URL in Auth0 matches exactly
2. **Application not saved**: Click "Save Changes" in Auth0 dashboard
3. **Wrong tenant**: Make sure you're in the correct Auth0 tenant

## 📋 Required Auth0 Settings Summary

```
Application Type: Regular Web Application
Token Endpoint Authentication Method: Post

Allowed Callback URLs: http://localhost:5000/callback
Allowed Logout URLs: http://localhost:5000
Allowed Web Origins: http://localhost:5000
Application Login URI: http://localhost:5000/auth0/login
```

## 🎯 Expected Flow After Fix

1. User clicks "Sign In with Auth0"
2. Redirected to Auth0 login page
3. User authenticates with Auth0
4. Redirected back to `/callback`
5. User created in local database
6. Redirected to dashboard

## 📞 Need Help?

If you're still having issues:
1. Double-check all Auth0 settings
2. Make sure you're in the correct Auth0 tenant
3. Verify the application is active
4. Check that all URLs match exactly

The issue is definitely in the Auth0 application configuration, not in our code!

