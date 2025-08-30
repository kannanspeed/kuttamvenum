# 🔑 COMPREHENSIVE API SETUP GUIDE

## **📋 SUMMARY OF REQUIRED APIs**

| Priority | API Service | Purpose | Monthly Cost | Setup Time |
|----------|-------------|---------|--------------|------------|
| **🔥 Critical** | WhatsApp Business | OTP & Communication | ₹250-1000 | 2-3 hours |
| **🔥 Critical** | Razorpay | Payments & Payouts | 2% + GST | 1-2 hours |
| **🔥 Critical** | Hyperverge | KYC Verification | ₹500-2000 | 1-2 hours |
| **⚡ Important** | Google Maps | Location Services | $0-50 | 30 mins |
| **⚡ Important** | Freshdesk | Support Tickets | $0-15 | 30 mins |
| **💡 Optional** | Gmail/SendGrid | Email Notifications | $0-15 | 15 mins |
| **💡 Optional** | Redis | Background Tasks | $0-5 | 15 mins |

---

## **🔥 CRITICAL APIs (Must Have)**

### **1. 📱 WhatsApp Business API**

**Why Critical:** User verification and communication backbone

#### **Setup Steps:**
1. **Create Meta Business Account**
   - Go to [business.facebook.com](https://business.facebook.com)
   - Create a business account
   - Add your business details

2. **Set Up WhatsApp Business**
   - Go to WhatsApp > Getting Started
   - Add your business phone number
   - Complete business verification

3. **Get API Credentials**
   - Go to System Users > Add System User
   - Assign WhatsApp Business API permissions
   - Generate access token

4. **Configure Webhook**
   - Set webhook URL: `https://yourdomain.com/api/whatsapp/webhook`
   - Verify token: Generate a random string

#### **Required Environment Variables:**
```env
WHATSAPP_ACCESS_TOKEN=your-access-token-here
WHATSAPP_PHONE_NUMBER_ID=your-phone-number-id
WHATSAPP_VERIFY_TOKEN=your-webhook-verify-token
```

#### **Cost:** ₹0.50-1 per message
#### **Free Tier:** 1000 messages/month

---

### **2. 💳 Razorpay Payment Gateway**

**Why Critical:** Payment processing and automated payouts

#### **Setup Steps:**
1. **Create Razorpay Account**
   - Go to [razorpay.com](https://razorpay.com)
   - Sign up for business account
   - Complete KYC verification

2. **Get API Keys**
   - Go to Settings > API Keys
   - Generate new key pair
   - Save both Key ID and Key Secret

3. **Configure Webhook**
   - Go to Settings > Webhooks
   - Add webhook URL: `https://yourdomain.com/api/payments/webhook`
   - Select events: payment.captured, payout.processed

4. **Set Up Payout Account**
   - Add bank account for payouts
   - Complete verification

#### **Required Environment Variables:**
```env
RAZORPAY_KEY_ID=your-key-id-here
RAZORPAY_KEY_SECRET=your-key-secret-here
RAZORPAY_WEBHOOK_SECRET=your-webhook-secret
```

#### **Cost:** 2% + GST per transaction
#### **Free Tier:** No setup fees

---

### **3. 🔐 Hyperverge KYC API**

**Why Critical:** User verification and compliance

#### **Setup Steps:**
1. **Create Hyperverge Account**
   - Go to [hyperverge.co](https://hyperverge.co)
   - Sign up for business account
   - Complete business verification

2. **Get API Credentials**
   - Go to API Keys section
   - Generate new API key and secret
   - Save both credentials

3. **Configure Webhook (Optional)**
   - Set webhook URL for real-time updates
   - Configure notification settings

#### **Required Environment Variables:**
```env
HYPERVERGE_API_KEY=your-api-key-here
HYPERVERGE_API_SECRET=your-api-secret-here
```

#### **Cost:** ₹2-5 per verification
#### **Free Tier:** 50 verifications/month

---

## **⚡ IMPORTANT APIs (Should Have)**

### **4. 🗺️ Google Maps API**

**Why Important:** Location-based features and mapping

#### **Setup Steps:**
1. **Create Google Cloud Account**
   - Go to [console.cloud.google.com](https://console.cloud.google.com)
   - Create new project
   - Enable billing (required for API usage)

2. **Enable Maps APIs**
   - Go to APIs & Services > Library
   - Enable these APIs:
     - Maps JavaScript API
     - Geocoding API
     - Distance Matrix API
     - Places API

3. **Create API Key**
   - Go to APIs & Services > Credentials
   - Create API key
   - Restrict key to your domain

#### **Required Environment Variables:**
```env
GOOGLE_MAPS_API_KEY=your-maps-api-key-here
```

#### **Cost:** $200 free credit/month, then pay-per-use
#### **Free Tier:** Usually sufficient for most applications

---

### **5. 🎫 Freshdesk CRM**

**Why Important:** Customer support and ticket management

#### **Setup Steps:**
1. **Create Freshdesk Account**
   - Go to [freshdesk.com](https://freshdesk.com)
   - Sign up for free account
   - Complete setup wizard

2. **Get API Key**
   - Go to Admin > API
   - Generate new API key
   - Save the key securely

3. **Configure Ticket Types**
   - Create ticket types for different issues
   - Set up automation rules

#### **Required Environment Variables:**
```env
FRESHDESK_API_KEY=your-api-key-here
FRESHDESK_DOMAIN=your-domain.freshdesk.com
```

#### **Cost:** Free tier available, paid from $15/month
#### **Free Tier:** 10 agents, unlimited tickets

---

## **💡 OPTIONAL APIs (Nice to Have)**

### **6. 📧 Email Service (Gmail/SendGrid)**

#### **Gmail Setup:**
1. Enable 2-factor authentication
2. Generate App Password
3. Use SMTP settings

#### **SendGrid Setup:**
1. Create SendGrid account
2. Verify sender domain
3. Get API key

#### **Required Environment Variables:**
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=admin@political.com
```

#### **Cost:** Free (Gmail) or $15/month (SendGrid)

---

### **7. 🗄️ Redis (for Background Tasks)**

#### **Local Setup:**
```bash
# Install Redis locally
# Windows: Download from redis.io
# Mac: brew install redis
# Linux: sudo apt-get install redis-server
```

#### **Cloud Setup:**
- Use Redis Cloud or AWS ElastiCache
- Get connection string

#### **Required Environment Variables:**
```env
REDIS_URL=redis://localhost:6379/0
```

#### **Cost:** Free (local) or $5/month (cloud)

---

## **💰 COST OPTIMIZATION STRATEGIES**

### **Phase 1: MVP (Minimal Viable Product)**
- **Budget:** ₹500-1000/month
- **APIs:** WhatsApp + Razorpay only
- **Features:** Core functionality + payments

### **Phase 2: Enhanced Features**
- **Budget:** ₹1500-2500/month
- **APIs:** Add KYC + Maps
- **Features:** Full verification + location services

### **Phase 3: Complete Platform**
- **Budget:** ₹2500-4000/month
- **APIs:** All APIs
- **Features:** Complete platform with support

---

## **🚀 QUICK START CHECKLIST**

### **Week 1: Core Setup**
- [ ] Set up WhatsApp Business API
- [ ] Configure Razorpay payment gateway
- [ ] Test basic functionality

### **Week 2: Verification**
- [ ] Set up Hyperverge KYC
- [ ] Test user verification flow
- [ ] Configure Google Maps

### **Week 3: Support & Optimization**
- [ ] Set up Freshdesk CRM
- [ ] Configure email notifications
- [ ] Set up Redis for background tasks

### **Week 4: Production Ready**
- [ ] Security audit
- [ ] Performance optimization
- [ ] Go live!

---

## **🔧 TROUBLESHOOTING**

### **Common Issues:**

1. **WhatsApp API Errors**
   - Check phone number verification
   - Verify webhook configuration
   - Ensure proper message templates

2. **Razorpay Integration Issues**
   - Verify API keys
   - Check webhook signature
   - Test in sandbox mode first

3. **KYC Verification Failures**
   - Check image quality
   - Verify API credentials
   - Test with sample data

4. **Maps API Errors**
   - Check API key restrictions
   - Verify billing setup
   - Monitor usage quotas

---

## **📞 SUPPORT RESOURCES**

- **WhatsApp Business:** [Meta Business Support](https://business.facebook.com/support)
- **Razorpay:** [Razorpay Support](https://razorpay.com/support)
- **Hyperverge:** [Hyperverge Support](https://hyperverge.co/support)
- **Google Maps:** [Google Cloud Support](https://cloud.google.com/support)
- **Freshdesk:** [Freshdesk Support](https://freshdesk.com/support)

---

**🎉 Ready to set up your APIs and launch your platform!**
