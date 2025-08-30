# 🚀 MINIMAL SETUP FOR TESTING

## **Quick Start Without External APIs**

If you want to test the application **immediately** without setting up all external APIs, follow this minimal setup:

### **Step 1: Create Minimal .env File**

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-this-in-production

# Database Configuration
DATABASE_URL=sqlite:///political_platform.db

# Encryption Key
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# Optional: Email (Gmail)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=admin@political.com

# Optional: Redis (for background tasks)
REDIS_URL=redis://localhost:6379/0
```

### **Step 2: Install Dependencies**

```bash
pip install Flask==2.2.5 Werkzeug==2.2.3 PyJWT==2.7.0 cryptography==39.0.2 marshmallow==3.19.0 requests==2.31.0 SQLAlchemy==2.0.23 Flask-SQLAlchemy==3.0.5 Flask-Migrate==4.0.5 python-dotenv==1.0.0
```

### **Step 3: Initialize Database**

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### **Step 4: Run Application**

```bash
python app.py
```

### **Step 5: Access Application**

- **URL:** http://127.0.0.1:5000
- **Admin Login:** admin@political.com / admin123

---

## **✅ WHAT WILL WORK WITHOUT APIs**

### **Core Features (100% Functional)**
- ✅ User registration and login
- ✅ Admin dashboard
- ✅ Event creation and management
- ✅ Volunteer registration
- ✅ Basic user dashboard
- ✅ File upload and storage
- ✅ Activity logging
- ✅ Database operations

### **Features with Mock/Disabled APIs**
- ⚠️ KYC Verification (will show "API not configured")
- ⚠️ WhatsApp OTP (will show "WhatsApp not configured")
- ⚠️ Payment Processing (will show "Razorpay not configured")
- ⚠️ Google Maps (will show "Maps not configured")
- ⚠️ CRM Support (will show "CRM not configured")
- ⚠️ Auto Matching (will work with basic logic)

---

## **🔧 GRADUAL API INTEGRATION**

You can add APIs **one by one** as needed:

### **Phase 1: Core Functionality**
- Start with minimal setup above
- Test all basic features

### **Phase 2: Add WhatsApp (Recommended First)**
- Most impactful for user experience
- Relatively low cost
- Easy to set up

### **Phase 3: Add Payment Gateway**
- Essential for monetization
- Razorpay is most popular in India

### **Phase 4: Add KYC Verification**
- Important for trust and compliance
- Can be added later

### **Phase 5: Add Maps and CRM**
- Nice-to-have features
- Can be added last

---

## **💡 PRO TIPS**

1. **Start Small:** Begin with minimal setup, add APIs gradually
2. **Test Locally:** All features work locally without external APIs
3. **Use Free Tiers:** Most services offer free tiers for testing
4. **Monitor Costs:** Set up billing alerts for paid services
5. **Backup Data:** Regular database backups are important

---

## **🚨 IMPORTANT NOTES**

- **Security:** Change default secret keys in production
- **Database:** SQLite is fine for testing, use PostgreSQL for production
- **File Storage:** Local storage works, consider cloud storage for production
- **SSL:** Use HTTPS in production (Let's Encrypt is free)

---

**Ready to start testing! 🎉**
