# 🚀 Political Event Management System

A comprehensive platform for managing political events, volunteer coordination, and party administration.

## ✨ Features

### Core Features
- **User Management** - Registration, approval, and profile management
- **Event Management** - Create, manage, and track political events
- **Volunteer Coordination** - Register volunteers and track participation
- **Admin Dashboard** - Comprehensive admin interface with analytics
- **Activity Logging** - Track all user and admin activities
- **File Management** - Secure document upload and storage

### Advanced Features
- **WhatsApp Integration** - OTP verification and group management
- **Google Maps** - Location-based services and mapping
- **Freshdesk CRM** - Support ticket system
- **Auto Matcher** - Intelligent volunteer-event matching
- **Political Party Verification** - Email domain verification for party admins
- **Terms & Conditions** - Legal framework and compliance

## 🛠️ Technology Stack

- **Backend**: Flask, SQLAlchemy, Python
- **Database**: SQLite (development), PostgreSQL (production)
- **Authentication**: JWT, SHA256 password hashing
- **Security**: Input validation, file encryption, CSP headers
- **APIs**: WhatsApp Business, Google Maps, Freshdesk CRM
- **Deployment**: Gunicorn, Render

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd political-event-management
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create environment file**
   ```bash
   cp env_template.txt .env
   # Edit .env with your configuration
   ```

4. **Initialize database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   - URL: http://127.0.0.1:5000
   - Admin Login: admin@political.com / admin123

## 📋 Environment Configuration

Create a `.env` file with the following variables:

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-this-in-production

# Database Configuration
DATABASE_URL=sqlite:///political_platform.db

# Encryption Key
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# Optional: WhatsApp Business API
WHATSAPP_ACCESS_TOKEN=your-whatsapp-access-token
WHATSAPP_PHONE_NUMBER_ID=your-whatsapp-phone-number-id

# Optional: Google Maps API
GOOGLE_MAPS_API_KEY=your-google-maps-api-key

# Optional: Freshdesk CRM
FRESHDESK_API_KEY=your-freshdesk-api-key
FRESHDESK_DOMAIN=your-domain.freshdesk.com

# Optional: Email (Gmail)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=admin@political.com

# Optional: Redis (for background tasks)
REDIS_URL=redis://localhost:6379/0
```

## 🔧 API Endpoints

### Core Endpoints
- `GET /` - Home page
- `GET /login` - Login page
- `POST /login` - User authentication
- `GET /register` - Registration page
- `POST /register` - User registration
- `GET /user_dashboard` - User dashboard
- `GET /admin_dashboard` - Admin dashboard

### API Endpoints
- `POST /api/whatsapp/send-otp` - Send WhatsApp OTP
- `POST /api/whatsapp/verify-otp` - Verify WhatsApp OTP
- `POST /api/whatsapp/create-group` - Create WhatsApp group
- `POST /api/support/ticket` - Create support ticket
- `GET /api/support/tickets` - Get support tickets
- `GET /api/matching/volunteers/<event_id>` - Find matching volunteers
- `POST /api/matching/auto-assign` - Auto-assign volunteers
- `POST /api/maps/geocode` - Geocode address
- `POST /api/maps/distance` - Calculate distance
- `GET /api/maps/event-map/<event_id>` - Get event map
- `GET /terms` - Terms and conditions

## 📊 Database Models

- **User** - User profiles and verification
- **Event** - Event management and details
- **Registration** - Event participation tracking
- **WhatsAppGroup** - Communication group management
- **SupportTicket** - CRM integration
- **VolunteerSkill** - Skill-based matching
- **AutoMatch** - Matching algorithm results
- **UserAgreement** - Terms acceptance tracking
- **AdminUser** - Admin user management
- **ActivityLog** - Activity tracking

## 🔐 Security Features

- **JWT Authentication** - Secure session management
- **Password Hashing** - SHA256 with salt
- **Input Validation** - Comprehensive data validation
- **File Encryption** - Secure document storage
- **CSP Headers** - Content Security Policy
- **Rate Limiting** - API protection (configurable)

## 🚀 Deployment

### Local Development
   ```bash
python app.py
```

### Production Deployment
1. Set `FLASK_ENV=production` in `.env`
2. Configure production database URL
3. Set secure session cookies
4. Use Gunicorn or similar WSGI server

### Render Deployment
- Already configured with `render.yaml`
- Automatic deployment from GitHub
- Environment variables configured in Render dashboard

## 📞 Support

For support and questions:
- Check the `UPDATED_MINIMAL_SETUP.md` for detailed setup instructions
- Review application logs for error messages
- Use the support ticket system for issues

## 📄 License

This project is licensed under the MIT License.

---

**Ready to revolutionize political event management! 🎉**



This project is open source and available under the MIT License.




This project is open source and available under the MIT License.


