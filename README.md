# Political Event Management System

A comprehensive web application for managing political events, user registrations, and event attendance tracking with QR code functionality.

## Features

- **User Management**: Registration, approval system, and profile management
- **Event Management**: Create, manage, and track political events
- **QR Code Integration**: Generate and scan QR codes for event check-ins
- **Admin Dashboard**: Comprehensive admin interface for managing users and events
- **Activity Logging**: Track all user and admin activities
- **Email Notifications**: Automated email notifications for approvals/rejections
- **Security**: JWT authentication, rate limiting, input validation, and file encryption

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: File-based storage with pickle
- **Authentication**: JWT tokens
- **Security**: Werkzeug password hashing, input sanitization
- **QR Codes**: qrcode library
- **Email**: Flask-Mail

## Deployment on Render

### Prerequisites

1. A Render account (free tier available)
2. A GitHub repository with your code
3. Gmail account for email notifications (optional)

### Step-by-Step Deployment

#### 1. Prepare Your Repository

Ensure your repository contains these files:
- `app.py` - Main Flask application
- `requirements.txt` - Python dependencies
- `render.yaml` - Render configuration (optional)
- `runtime.txt` - Python version specification
- `templates/` - HTML templates
- `static/` - CSS, JS, and other static files

#### 2. Deploy on Render

**Option A: Using render.yaml (Recommended)**

1. Push your code to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com/)
3. Click "New +" and select "Blueprint"
4. Connect your GitHub repository
5. Render will automatically detect the `render.yaml` file
6. Click "Apply" to deploy

**Option B: Manual Deployment**

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" and select "Web Service"
3. Connect your GitHub repository
4. Configure the service:
   - **Name**: `political-event-management`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free

#### 3. Environment Variables

Set these environment variables in your Render service:

**Required:**
- `SECRET_KEY` - Flask secret key (auto-generated)
- `JWT_SECRET_KEY` - JWT signing key (auto-generated)
- `ENCRYPTION_KEY` - File encryption key (auto-generated)

**Optional (for email notifications):**
- `MAIL_SERVER` - SMTP server (e.g., `smtp.gmail.com`)
- `MAIL_PORT` - SMTP port (e.g., `587`)
- `MAIL_USE_TLS` - Use TLS (e.g., `true`)
- `MAIL_USERNAME` - Your email address
- `MAIL_PASSWORD` - Your email password or app password
- `MAIL_DEFAULT_SENDER` - Default sender email

#### 4. Gmail Setup (Optional)

If you want email notifications:

1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a password for "Mail"
3. Use this app password in the `MAIL_PASSWORD` environment variable

### Default Credentials

After deployment, you can log in with:
- **Admin**: `admin@political.com` / `admin123`

### Local Development

1. Clone the repository:
```bash
git clone <your-repo-url>
cd political-event-management
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

5. Access the application at `http://localhost:5000`

### File Structure

```
political-event-management/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── render.yaml           # Render deployment config
├── runtime.txt           # Python version
├── .gitignore           # Git ignore file
├── README.md            # This file
├── templates/           # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── admin_dashboard.html
│   ├── user_dashboard.html
│   └── ...
├── static/              # Static files
│   ├── css/
│   ├── js/
│   └── uploads/
└── data/               # Data storage (created automatically)
    ├── users.pkl
    ├── events.pkl
    ├── admin.pkl
    └── ...
```

### Security Features

- **Password Hashing**: Secure password storage using Werkzeug
- **JWT Authentication**: Token-based authentication
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive input sanitization
- **File Encryption**: Secure file storage
- **CSP Headers**: Content Security Policy protection
- **XSS Protection**: Cross-site scripting prevention

### API Endpoints

- `GET /` - Home page
- `GET/POST /login` - User authentication
- `GET/POST /register` - User registration
- `GET /user_dashboard` - User dashboard
- `GET /admin_dashboard` - Admin dashboard
- `GET /admin/users` - User management
- `GET /admin/events` - Event management
- `POST /admin/add_event` - Create new event
- `GET /join_event/<event_id>` - Join an event
- `GET /scan_qr/<event_id>` - Scan QR code for check-in

### Troubleshooting

**Common Issues:**

1. **Build fails**: Check that all dependencies are in `requirements.txt`
2. **Runtime errors**: Check the logs in Render dashboard
3. **Email not working**: Verify Gmail app password and environment variables
4. **File upload issues**: Ensure `secure_uploads` directory exists

**Logs:**
- Check Render dashboard → Your service → Logs
- Application logs are also stored in `app.log`

### Support

For issues or questions:
1. Check the Render logs
2. Verify environment variables
3. Test locally first
4. Check the application logs in `app.log`

## License

This project is open source and available under the MIT License.

