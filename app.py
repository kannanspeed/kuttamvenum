from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import uuid
import jwt
import logging
import pickle
from datetime import datetime, timedelta
from functools import wraps
import qrcode
from cryptography.fernet import Fernet
import bleach
from marshmallow import Schema, fields, validate, validates_schema, ValidationError
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database Configuration
db = SQLAlchemy()
migrate = Migrate()

# Production Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'production-secret-key-change-this')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'secure_uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///political_platform.db')
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
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
    
    # WhatsApp Business API
    WHATSAPP_API_KEY = os.environ.get('WHATSAPP_API_KEY')
    WHATSAPP_API_SECRET = os.environ.get('WHATSAPP_API_SECRET')
    WHATSAPP_PHONE_NUMBER_ID = os.environ.get('WHATSAPP_PHONE_NUMBER_ID')
    WHATSAPP_ACCESS_TOKEN = os.environ.get('WHATSAPP_ACCESS_TOKEN')
    
    # Google Maps API
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY')
    
    # Freshdesk CRM
    FRESHDESK_API_KEY = os.environ.get('FRESHDESK_API_KEY')
    FRESHDESK_DOMAIN = os.environ.get('FRESHDESK_DOMAIN')
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Platform Configuration
    PLATFORM_NAME = os.environ.get('PLATFORM_NAME', 'Political Event Management System')
    
    # OTP Configuration
    OTP_EXPIRY_MINUTES = int(os.environ.get('OTP_EXPIRY_MINUTES', 10))
    OTP_LENGTH = int(os.environ.get('OTP_LENGTH', 6))
    
    # Auto Matcher Configuration
    AUTO_MATCH_RADIUS_KM = float(os.environ.get('AUTO_MATCH_RADIUS_KM', 50))
    AUTO_MATCH_SCORE_THRESHOLD = float(os.environ.get('AUTO_MATCH_SCORE_THRESHOLD', 0.7))
    
    # Political Party Email Domains
    POLITICAL_PARTY_DOMAINS = os.environ.get('POLITICAL_PARTY_DOMAINS', 'dmk.in,aiadmk.in,bjp.org,inc.in').split(',')
    
    # File Upload Configuration
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 10485760))  # 10MB
    ALLOWED_EXTENSIONS = os.environ.get('ALLOWED_EXTENSIONS', 'jpg,jpeg,png,pdf').split(',')
    
    # Security Configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PERMANENT_SESSION_LIFETIME', 3600))

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

app.config.from_object(Config)

# Initialize database
db.init_app(app)
migrate.init_app(app, db)

# Import database models
from models import *

# Initialize extensions (simplified for deployment)
# mail = Mail(app)  # Disabled for deployment
# limiter = Limiter(...)  # Disabled for deployment

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize encryption
cipher = Fernet(app.config['ENCRYPTION_KEY'])

# Data files for persistence
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, 'users.pkl')
EVENTS_FILE = os.path.join(DATA_DIR, 'events.pkl')
REGISTRATIONS_FILE = os.path.join(DATA_DIR, 'registrations.pkl')
ADMIN_FILE = os.path.join(DATA_DIR, 'admin.pkl')
ACTIVITIES_FILE = os.path.join(DATA_DIR, 'activities.pkl')
SESSIONS_FILE = os.path.join(DATA_DIR, 'sessions.pkl')

# In-memory data with persistence
def load_data():
    """Load data from pickle files"""
    try:
        with open(USERS_FILE, 'rb') as f:
            users_db = pickle.load(f)
    except:
        users_db = {}
    
    try:
        with open(EVENTS_FILE, 'rb') as f:
            events_db = pickle.load(f)
    except:
        events_db = {}
    
    try:
        with open(REGISTRATIONS_FILE, 'rb') as f:
            registrations_db = pickle.load(f)
    except:
        registrations_db = {}
    
    try:
        with open(ADMIN_FILE, 'rb') as f:
            admin_credentials = pickle.load(f)
    except:
        admin_credentials = {
            'admin@political.com': {
                'id': str(uuid.uuid4()),
                'password': generate_password_hash('admin123', method='sha256'),
                'role': 'admin',
                'created_at': datetime.utcnow().isoformat()
            }
        }
        save_admin(admin_credentials)
        print(f"DEBUG: Admin credentials created with password hash: {admin_credentials['admin@political.com']['password']}")
    
    try:
        with open(ACTIVITIES_FILE, 'rb') as f:
            activities_db = pickle.load(f)
    except:
        activities_db = []
    
    try:
        with open(SESSIONS_FILE, 'rb') as f:
            sessions_db = pickle.load(f)
    except:
        sessions_db = {}
    
    return users_db, events_db, registrations_db, admin_credentials, activities_db, sessions_db

def save_users(users_db):
    with open(USERS_FILE, 'wb') as f:
        pickle.dump(users_db, f)

def save_events(events_db):
    with open(EVENTS_FILE, 'wb') as f:
        pickle.dump(events_db, f)

def save_registrations(registrations_db):
    with open(REGISTRATIONS_FILE, 'wb') as f:
        pickle.dump(registrations_db, f)

def save_admin(admin_credentials):
    with open(ADMIN_FILE, 'wb') as f:
        pickle.dump(admin_credentials, f)

def save_activities(activities_db):
    with open(ACTIVITIES_FILE, 'wb') as f:
        pickle.dump(activities_db, f)

def save_sessions(sessions_db):
    with open(SESSIONS_FILE, 'wb') as f:
        pickle.dump(sessions_db, f)

# Load initial data
users_db, events_db, registrations_db, admin_credentials, activities_db, sessions_db = load_data()

# Validation Schemas
class UserRegistrationSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=2, max=100))
    email = fields.Email(required=True)
    phone = fields.Str(required=True, validate=validate.Regexp(r'^\d{10}$', error="Phone must be 10 digits"))
    location = fields.Str(required=True, validate=validate.Length(min=2, max=200))
    password = fields.Str(required=True, validate=validate.Length(min=8, error="Password must be at least 8 characters"))
    confirm_password = fields.Str(required=True)
    terms = fields.Bool(required=True, validate=validate.Equal(True, error="You must agree to the terms and conditions"))
    
    @validates_schema
    def validate_passwords(self, data, **kwargs):
        if data.get('password') != data.get('confirm_password'):
            raise ValidationError('Passwords do not match', 'confirm_password')

class EventCreationSchema(Schema):
    title = fields.Str(required=True, validate=validate.Length(min=5, max=200))
    description = fields.Str(required=True, validate=validate.Length(min=10, max=2000))
    party_name = fields.Str(required=True, validate=validate.Length(min=2, max=100))
    date = fields.Date(required=True)
    time = fields.Time(required=True)

# Security Functions
def sanitize_input(data):
    """Sanitize HTML input to prevent XSS"""
    if isinstance(data, str):
        return bleach.clean(data, tags=[], attributes={}, strip=True)
    elif isinstance(data, dict):
        return {key: sanitize_input(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    return data

def generate_jwt_token(user_id, role):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'user_id' not in session or session.get('role') != 'admin':
                flash('Admin access required')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Error in require_admin decorator: {e}")
            import traceback
            traceback.print_exc()
            return f"Decorator error: {str(e)}", 500
    return decorated_function

def log_activity(action, description=None, target_user_id=None):
    """Log user/admin activity"""
    global activities_db
    
    activity = {
        'id': str(uuid.uuid4()),
        'user_id': session.get('user_id') if session.get('role') == 'user' else None,
        'admin_email': session.get('user_id') if session.get('role') == 'admin' else None,
        'action': action,
        'description': description,
        'target_user_id': target_user_id,
        'ip_address': request.remote_addr,
        'user_agent': request.user_agent.string,
        'created_at': datetime.utcnow().isoformat()
    }
    
    activities_db.append(activity)
    save_activities(activities_db)
    
    logger.info(f"Activity logged: {action} by {session.get('user_id', 'anonymous')} - {description}")

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
    return response

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test_session')
def test_session():
    """Test route to check session status"""
    session_info = {
        'user_id': session.get('user_id'),
        'role': session.get('role'),
        'all_session_data': dict(session)
    }
    return jsonify(session_info)

@app.route('/test_admin')
def test_admin():
    """Test route to check admin credentials"""
    admin_info = {
        'admin_exists': 'admin@political.com' in admin_credentials,
        'admin_password_hash': admin_credentials.get('admin@political.com', {}).get('password', 'NOT_FOUND'),
        'password_check': check_password_hash(admin_credentials.get('admin@political.com', {}).get('password', ''), 'admin123') if 'admin@political.com' in admin_credentials else False
    }
    return jsonify(admin_info)

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")  # Disabled for deployment
def login():
    if request.method == 'POST':
        try:
            print("DEBUG: Login POST request received")
            data = sanitize_input(request.form.to_dict())
            email = data.get('email')
            password = data.get('password')
            
            print(f"DEBUG: Login attempt for email: {email}")
            print(f"DEBUG: Admin credentials keys: {list(admin_credentials.keys())}")
            print(f"DEBUG: Email in admin_credentials: {email in admin_credentials}")
            
            # Check admin users
            if email in admin_credentials:
                print(f"DEBUG: Found admin email, checking password...")
                password_check = check_password_hash(admin_credentials[email]['password'], password)
                print(f"DEBUG: Password check result: {password_check}")
                
                if password_check:
                    session['user_id'] = email
                    session['role'] = 'admin'
                    print(f"DEBUG: Admin login successful, session set: {dict(session)}")
                    log_activity('admin_login', f'Admin {email} logged in')
                    flash('Welcome Admin!')
                    print("DEBUG: Redirecting to admin_dashboard")
                    return redirect(url_for('admin_dashboard'))
                else:
                    print(f"DEBUG: Admin password check failed")
            
            # Check regular users
            if email in users_db and users_db[email]['status'] == 'approved':
                if check_password_hash(users_db[email]['password'], password):
                    session['user_id'] = email
                    session['role'] = 'user'
                    log_activity('user_login', f'User {email} logged in')
                    flash(f'Welcome {users_db[email]["name"]}!')
                    return redirect(url_for('user_dashboard'))
            
            log_activity('login_failed', f'Failed login attempt for {email}')
            flash('Invalid credentials or account not approved')
        except Exception as e:
            print(f"DEBUG: Login error: {e}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during login')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("3 per minute")  # Disabled for deployment
def register():
    if request.method == 'POST':
        schema = UserRegistrationSchema()
        try:
            data = schema.load(sanitize_input(request.form.to_dict()))
        except ValidationError as err:
            for field, errors in err.messages.items():
                for error in errors:
                    flash(f"{field}: {error}")
            return render_template('register.html')
        
        # Check if user already exists
        if data['email'] in users_db:
            flash('Email already registered')
            return render_template('register.html')
        
        # Check phone number
        for user in users_db.values():
            if user['phone'] == data['phone']:
                flash('Phone number already registered')
                return render_template('register.html')
        
        # Create new user
        user_id = str(uuid.uuid4())
        users_db[data['email']] = {
            'id': user_id,
            'name': data['name'],
            'email': data['email'],
            'phone': data['phone'],
            'location': data['location'],
            'password': generate_password_hash(data['password'], method='sha256'),
            'status': 'pending',
            'adhar_front': None,
            'adhar_back': None,
            'selfie': None,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        save_users(users_db)
        log_activity('user_registration', f'New user registered: {data["email"]}')
        flash('Registration successful! Please upload your documents for verification.')
        return redirect(url_for('upload_documents', user_id=user_id))
    
    return render_template('register.html')

@app.route('/upload_documents/<user_id>', methods=['GET', 'POST'])
# @limiter.limit("10 per hour")  # Disabled for deployment
def upload_documents(user_id):
    user = None
    for u in users_db.values():
        if u['id'] == user_id:
            user = u
            break
    
    if not user:
        flash('User not found')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        adhar_front = request.files.get('adhar_front')
        adhar_back = request.files.get('adhar_back')
        selfie = request.files.get('selfie')
        
        if adhar_front and adhar_back and selfie:
            try:
                user['adhar_front'] = save_secure_file(adhar_front, 'adhar_front', user_id)
                user['adhar_back'] = save_secure_file(adhar_back, 'adhar_back', user_id)
                user['selfie'] = save_secure_file(selfie, 'selfie', user_id)
                user['updated_at'] = datetime.utcnow().isoformat()
                
                save_users(users_db)
                log_activity('documents_uploaded', f'Documents uploaded for user {user["email"]}', user_id)
                flash('Documents uploaded successfully! Please wait for admin approval.')
                return redirect(url_for('login'))
            except Exception as e:
                flash('Error uploading files. Please try again.')
                logger.error(f"File upload error: {e}")
    
    return render_template('upload_documents.html', user=user)

@app.route('/user_dashboard')
@require_auth
def user_dashboard():
    try:
        if session['role'] != 'user':
            return redirect(url_for('login'))
        
        user = users_db.get(session['user_id'])
        if not user:
            flash('User not found')
            return redirect(url_for('login'))
        
        events = list(events_db.values())
        
        # Convert datetime strings for templates
        convert_datetime_strings(events)
        
        user_registrations = [r for r in registrations_db.values() if r['user_email'] == session['user_id']]
        
        # Convert datetime strings for registrations as well
        convert_datetime_strings(user_registrations)
        
        return render_template('user_dashboard.html', user=user, events=events, registrations=user_registrations)
    except Exception as e:
        print(f"User dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return f"Error in user dashboard: {str(e)}", 500

@app.route('/admin_dashboard')
@require_admin
def admin_dashboard():
    try:
        print(f"DEBUG: Admin dashboard accessed by {session.get('user_id')}")
        print(f"DEBUG: Session data: {dict(session)}")
        
        pending_users = [u for u in users_db.values() if u['status'] == 'pending']
        print(f"DEBUG: Found {len(pending_users)} pending users")
        
        stats = {
            'total_users': len(users_db),
            'pending_users': len(pending_users),
            'approved_users': len([u for u in users_db.values() if u['status'] == 'approved']),
            'rejected_users': len([u for u in users_db.values() if u['status'] == 'rejected']),
            'total_events': len(events_db),
            'total_registrations': len(registrations_db)
        }
        print(f"DEBUG: Stats calculated: {stats}")
        
        # Get recent activities and convert datetime strings
        print(f"DEBUG: Processing {len(activities_db)} activities")
        recent_activities = safe_sort_by_created_at(activities_db)[:10]
        convert_datetime_strings(recent_activities)
        print(f"DEBUG: Processed {len(recent_activities)} recent activities")
        
        # Get recent events and fix datetime strings
        print(f"DEBUG: Processing {len(events_db)} events")
        events = list(events_db.values())[:5]
        convert_datetime_strings(events)
        print(f"DEBUG: Processed {len(events)} recent events")
        
        print("DEBUG: Rendering admin dashboard template")
        return render_template('admin_dashboard.html', 
                             pending_users=pending_users, 
                             stats=stats, 
                             recent_activities=recent_activities,
                             events=events)
    except Exception as e:
        print(f"Admin dashboard error: {e}")
        import traceback
        traceback.print_exc()
        return f"Error in admin dashboard: {str(e)}", 500

@app.route('/admin/users')
@require_admin
def admin_users():
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')
    
    users = list(users_db.values())
    
    if status_filter:
        users = [u for u in users if u['status'] == status_filter]
    
    if search:
        search = search.lower()
        users = [u for u in users if 
                search in u['name'].lower() or 
                search in u['email'].lower() or 
                search in u['phone']]
    
    # Convert datetime strings before sorting and rendering
    convert_datetime_strings(users)
    
    # Sort by created_at using safe sorting
    users = safe_sort_by_created_at(users)
    
    # Create mock pagination object
    class MockPagination:
        def __init__(self, items):
            self.items = items
            self.total = len(items)
            self.pages = 1
            self.page = 1
            self.has_prev = False
            self.has_next = False
    
    users_paginated = MockPagination(users)
    
    return render_template('admin_users.html', users=users_paginated, status_filter=status_filter, search=search)

@app.route('/admin/user_history/<user_id>')
@require_admin
def user_history(user_id):
    user = None
    for u in users_db.values():
        if u['id'] == user_id:
            user = u
            break
    
    if not user:
        flash('User not found')
        return redirect(url_for('admin_users'))
    
    # Get activities for this user
    user_activities = [a for a in activities_db if 
                      a.get('user_id') == user_id or 
                      a.get('target_user_id') == user_id]
    
    # Convert datetime strings before sorting
    convert_datetime_strings(user_activities)
    
    # Sort by created_at using safe sorting
    user_activities = safe_sort_by_created_at(user_activities)
    
    # Get registrations for this user
    user_registrations = [r for r in registrations_db.values() if r['user_id'] == user_id]
    
    # Add event details to registrations and convert datetime strings
    for reg in user_registrations:
        event = events_db.get(reg['event_id'])
        if event:
            event = event.copy()  # Don't modify original
            convert_datetime_strings([event])
            reg['event'] = event
    
    return render_template('user_history.html', user=user, activities=user_activities, registrations=user_registrations)

@app.route('/admin/approve_user/<user_id>')
@require_admin
def approve_user(user_id):
    user = None
    for u in users_db.values():
        if u['id'] == user_id:
            user = u
            break
    
    if user:
        user['status'] = 'approved'
        user['updated_at'] = datetime.utcnow().isoformat()
        save_users(users_db)
        
        log_activity('user_approved', f'User {user["email"]} approved by admin', user_id)
        
        # Send approval email (disabled for deployment)
        # send_approval_email(user['email'], user['name'], 'approved')
        
        flash(f'User {user["name"]} approved successfully!')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/reject_user/<user_id>')
@require_admin
def reject_user(user_id):
    user = None
    for u in users_db.values():
        if u['id'] == user_id:
            user = u
            break
    
    if user:
        user['status'] = 'rejected'
        user['updated_at'] = datetime.utcnow().isoformat()
        save_users(users_db)
        
        log_activity('user_rejected', f'User {user["email"]} rejected by admin', user_id)
        
        # Send rejection email (disabled for deployment)
        # send_approval_email(user['email'], user['name'], 'rejected')
        
        flash(f'User {user["name"]} rejected!')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/events')
@require_admin
def admin_events():
    events = list(events_db.values())
    
    # Convert datetime strings before sorting and rendering  
    convert_datetime_strings(events)
    
    # Sort by created_at using safe sorting
    events = safe_sort_by_created_at(events)
    
    # Add registration stats
    for event in events:
        event_registrations = [r for r in registrations_db.values() if r['event_id'] == event['id']]
        event['total_registrations'] = len(event_registrations)
        event['checked_in'] = len([r for r in event_registrations if r['status'] == 'checked_in'])
    
    return render_template('admin_events.html', events=events)

@app.route('/admin/add_event', methods=['GET', 'POST'])
@require_admin
def add_event():
    if request.method == 'POST':
        schema = EventCreationSchema()
        try:
            data = schema.load(sanitize_input(request.form.to_dict()))
        except ValidationError as err:
            for field, errors in err.messages.items():
                for error in errors:
                    flash(f"{field}: {error}")
            return render_template('add_event.html')
        
        image_path = None
        image = request.files.get('image')
        if image:
            image_path = save_secure_file(image, 'event', 'admin')
        
        # Generate QR code
        qr_code_path = generate_qr_code(data['title'])
        
        event_id = str(uuid.uuid4())
        events_db[event_id] = {
            'id': event_id,
            'title': data['title'],
            'description': data['description'],
            'image': image_path,
            'party_name': data['party_name'],
            'date': data['date'].isoformat(),
            'time': data['time'].isoformat(),
            'qr_code': qr_code_path,
            'status': 'upcoming',
            'created_by': session['user_id'],
            'created_at': datetime.utcnow().isoformat()
        }
        
        save_events(events_db)
        log_activity('event_created', f'Event "{data["title"]}" created')
        flash('Event created successfully!')
        return redirect(url_for('admin_events'))
    
    return render_template('add_event.html')

@app.route('/admin/activity_logs')
@require_admin
def activity_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    
    activities = activities_db.copy()
    
    if action_filter:
        activities = [a for a in activities if action_filter.lower() in a['action'].lower()]
    
    # Convert datetime strings before sorting
    convert_datetime_strings(activities)
    
    # Sort by created_at using safe sorting
    activities = safe_sort_by_created_at(activities)
    
    # Simple pagination
    per_page = 50
    start = (page - 1) * per_page
    end = start + per_page
    
    class MockPagination:
        def __init__(self, items, page, per_page):
            self.items = items[start:end]
            self.total = len(items)
            self.pages = (len(items) + per_page - 1) // per_page
            self.page = page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1 if self.has_prev else None
            self.next_num = page + 1 if self.has_next else None
        
        def iter_pages(self):
            for i in range(1, self.pages + 1):
                yield i
    
    activities_paginated = MockPagination(activities, page, per_page)
    
    return render_template('activity_logs.html', activities=activities_paginated, action_filter=action_filter)

@app.route('/join_event/<event_id>')
@require_auth
def join_event(event_id):
    if session['role'] != 'user':
        return redirect(url_for('login'))
    
    user = users_db.get(session['user_id'])
    event = events_db.get(event_id)
    
    if not event:
        flash('Event not found')
        return redirect(url_for('user_dashboard'))
    
    # Check if already registered
    existing_reg = None
    for reg in registrations_db.values():
        if reg['user_id'] == user['id'] and reg['event_id'] == event_id:
            existing_reg = reg
            break
    
    if existing_reg:
        flash('You are already registered for this event!')
        return redirect(url_for('user_dashboard'))
    
    reg_id = str(uuid.uuid4())
    registrations_db[reg_id] = {
        'id': reg_id,
        'user_id': user['id'],
        'user_email': user['email'],
        'event_id': event_id,
        'status': 'registered',
        'check_in_time': None,
        'created_at': datetime.utcnow().isoformat()
    }
    
    save_registrations(registrations_db)
    log_activity('event_joined', f'Joined event: {event["title"]}')
    flash(f'Successfully joined "{event["title"]}"!')
    return redirect(url_for('user_dashboard'))

@app.route('/scan_qr/<event_id>')
@require_auth
def scan_qr(event_id):
    if session['role'] != 'user':
        return redirect(url_for('login'))
    
    user = users_db.get(session['user_id'])
    event = events_db.get(event_id)
    
    if not event:
        flash('Event not found')
        return redirect(url_for('user_dashboard'))
    
    registration = None
    for reg in registrations_db.values():
        if reg['user_id'] == user['id'] and reg['event_id'] == event_id:
            registration = reg
            break
    
    if not registration:
        flash('You are not registered for this event!')
        return redirect(url_for('user_dashboard'))
    
    registration['status'] = 'checked_in'
    registration['check_in_time'] = datetime.utcnow().isoformat()
    
    save_registrations(registrations_db)
    log_activity('event_checkin', f'Checked in to event: {event["title"]}')
    flash(f'Successfully checked in to "{event["title"]}"!')
    return redirect(url_for('user_dashboard'))

@app.route('/api/event_stats/<event_id>')
@require_admin
def event_stats(event_id):
    event_registrations = [r for r in registrations_db.values() if r['event_id'] == event_id]
    
    total_registered = len(event_registrations)
    checked_in = len([r for r in event_registrations if r['status'] == 'checked_in'])
    not_attended = total_registered - checked_in
    
    return jsonify({
        'total_registered': total_registered,
        'checked_in': checked_in,
        'not_attended': not_attended
    })

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_activity('logout', f'User {user_id} logged out')
    session.clear()
    flash('You have been logged out successfully')
    return redirect(url_for('index'))

# Helper functions
def convert_datetime_strings(data):
    """Convert datetime strings to datetime objects for templates"""
    try:
        if isinstance(data, list):
            for item in data:
                convert_datetime_strings(item)
        elif isinstance(data, dict):
            for key, value in data.items():
                if key == 'time' and isinstance(value, str):
                    try:
                        # Handle time strings like '18:00:00' FIRST
                        data[key] = datetime.strptime(value, '%H:%M:%S').time()
                    except Exception as e:
                        print(f"Error converting time: {value}, error: {e}")
                        data[key] = datetime.utcnow().time()
                elif key == 'date' and isinstance(value, str):
                    try:
                        # Handle date strings like '2024-12-31'
                        data[key] = datetime.strptime(value, '%Y-%m-%d').date()
                    except Exception as e:
                        print(f"Error converting date: {value}, error: {e}")
                        data[key] = datetime.utcnow().date()
                elif key in ['created_at', 'updated_at', 'check_in_time'] and isinstance(value, str):
                    try:
                        data[key] = datetime.fromisoformat(value)
                    except Exception as e:
                        print(f"Error converting {key}: {value}, error: {e}")
                        data[key] = datetime.utcnow()
    except Exception as e:
        print(f"DEBUG: Error in convert_datetime_strings: {e}")
        import traceback
        traceback.print_exc()

def safe_sort_by_created_at(items):
    """Safely sort items by created_at, handling mixed string/datetime types"""
    def get_sort_key(item):
        created_at = item.get('created_at')
        if isinstance(created_at, str):
            try:
                # Only try fromisoformat for ISO datetime strings
                if 'T' in created_at or len(created_at) > 10:
                    return datetime.fromisoformat(created_at)
                else:
                    return datetime.min
            except Exception as e:
                print(f"Safe sort error for created_at '{created_at}': {e}")
                return datetime.min
        elif isinstance(created_at, datetime):
            return created_at
        else:
            return datetime.min
    
    return sorted(items, key=get_sort_key, reverse=True)

def save_secure_file(file, prefix, user_id):
    """Save file with security checks and encryption"""
    if not file or file.filename == '':
        return None
    
    # Validate file
    allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
    max_size = 5 * 1024 * 1024  # 5MB
    
    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in allowed_extensions:
        raise ValueError("Invalid file type")
    
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > max_size:
        raise ValueError("File too large")
    
    # Generate secure filename
    secure_filename_str = f"{prefix}_{user_id}_{uuid.uuid4()}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename_str)
    
    # Encrypt and save file
    file_content = file.read()
    encrypted_content = cipher.encrypt(file_content)
    
    with open(filepath, 'wb') as f:
        f.write(encrypted_content)
    
    return secure_filename_str

def get_secure_file(filename):
    """Retrieve and decrypt file"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return None
    
    with open(filepath, 'rb') as f:
        encrypted_content = f.read()
    
    try:
        decrypted_content = cipher.decrypt(encrypted_content)
        return decrypted_content
    except:
        return None

def generate_qr_code(event_title):
    """Generate QR code for event"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(f"event:{event_title}:{uuid.uuid4()}")
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    filename = f"qr_{uuid.uuid4()}.png"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    img.save(filepath)
    return filename

def send_approval_email(email, name, status):
    """Send email notification for user approval/rejection (disabled for deployment)"""
    # Email functionality disabled for deployment
    logger.info(f"Email would be sent to {email} for {status} (disabled)")
    pass

# ============================================================================
# NEW FEATURE API ROUTES
# ============================================================================

# Import service classes
from services.email_verification import PoliticalPartyVerification
from services.whatsapp_service import WhatsAppService, WhatsAppGroupService
from services.crm_service import FreshdeskCRM
from services.auto_matcher import AutoMatcher
from services.maps_service import GoogleMapsService

# Initialize services
party_verification = PoliticalPartyVerification()
whatsapp_service = WhatsAppService()
whatsapp_group_service = WhatsAppGroupService()
crm_service = FreshdeskCRM()
auto_matcher = AutoMatcher()
maps_service = GoogleMapsService()

# KYC Verification Routes (Disabled - KYC service removed)
@app.route('/api/kyc/verify', methods=['POST'])
def kyc_verify():
    """KYC verification disabled - service removed"""
    return jsonify({'success': False, 'error': 'KYC verification service has been removed from this version'}), 501

@app.route('/api/kyc/status/<user_id>', methods=['GET'])
def kyc_status(user_id):
    """KYC status check disabled - service removed"""
    return jsonify({'success': False, 'error': 'KYC verification service has been removed from this version'}), 501

# WhatsApp Routes
@app.route('/api/whatsapp/send-otp', methods=['POST'])
def send_whatsapp_otp():
    """Send OTP via WhatsApp"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        
        if not phone_number:
            return jsonify({'success': False, 'error': 'Phone number required'}), 400
        
        result = whatsapp_service.send_otp(phone_number)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"WhatsApp OTP error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whatsapp/verify-otp', methods=['POST'])
def verify_whatsapp_otp():
    """Verify OTP sent via WhatsApp"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        otp = data.get('otp')
        
        if not all([phone_number, otp]):
            return jsonify({'success': False, 'error': 'Phone number and OTP required'}), 400
        
        result = whatsapp_service.verify_otp(phone_number, otp)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"WhatsApp OTP verification error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whatsapp/create-group', methods=['POST'])
def create_whatsapp_group():
    """Create WhatsApp group for event coordination"""
    try:
        data = request.get_json()
        group_name = data.get('group_name')
        event_id = data.get('event_id')
        admin_phone = data.get('admin_phone')
        
        if not all([group_name, event_id, admin_phone]):
            return jsonify({'success': False, 'error': 'Group name, event ID, and admin phone required'}), 400
        
        result = whatsapp_group_service.create_group(group_name, admin_phone)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"WhatsApp group creation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Payment Routes (Disabled - Payment service removed)
@app.route('/api/payments/create-order', methods=['POST'])
def create_payment_order():
    """Payment processing disabled - service removed"""
    return jsonify({'success': False, 'error': 'Payment processing service has been removed from this version'}), 501

@app.route('/api/payments/verify', methods=['POST'])
def verify_payment():
    """Payment verification disabled - service removed"""
    return jsonify({'success': False, 'error': 'Payment processing service has been removed from this version'}), 501

@app.route('/api/payments/payout', methods=['POST'])
def create_payout():
    """Payout processing disabled - service removed"""
    return jsonify({'success': False, 'error': 'Payment processing service has been removed from this version'}), 501

# CRM Support Routes
@app.route('/api/support/ticket', methods=['POST'])
def create_support_ticket():
    """Create support ticket in Freshdesk"""
    try:
        data = request.get_json()
        subject = data.get('subject')
        description = data.get('description')
        email = data.get('email')
        priority = data.get('priority', 1)
        
        if not all([subject, description, email]):
            return jsonify({'success': False, 'error': 'Subject, description, and email required'}), 400
        
        result = crm_service.create_ticket(subject, description, email, priority)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Support ticket creation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/support/tickets', methods=['GET'])
def get_support_tickets():
    """Get all support tickets"""
    try:
        result = crm_service.get_tickets()
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Get support tickets error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Auto Matcher Routes
@app.route('/api/matching/volunteers/<event_id>', methods=['GET'])
def get_matching_volunteers(event_id):
    """Get volunteers that match an event"""
    try:
        result = auto_matcher.find_matching_volunteers(event_id)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Volunteer matching error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/matching/auto-assign', methods=['POST'])
def auto_assign_volunteers():
    """Automatically assign volunteers to events"""
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'success': False, 'error': 'Event ID required'}), 400
        
        result = auto_matcher.auto_assign_volunteers(event_id)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Auto assignment error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Google Maps Routes
@app.route('/api/maps/geocode', methods=['POST'])
def geocode_address():
    """Geocode an address using Google Maps"""
    try:
        data = request.get_json()
        address = data.get('address')
        
        if not address:
            return jsonify({'success': False, 'error': 'Address required'}), 400
        
        result = maps_service.geocode_address(address)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Geocoding error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/maps/distance', methods=['POST'])
def calculate_distance():
    """Calculate distance between two points"""
    try:
        data = request.get_json()
        origin = data.get('origin')
        destination = data.get('destination')
        
        if not all([origin, destination]):
            return jsonify({'success': False, 'error': 'Origin and destination required'}), 400
        
        result = maps_service.calculate_distance(origin, destination)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Distance calculation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/maps/event-map/<event_id>', methods=['GET'])
def get_event_map(event_id):
    """Get map with event and volunteer locations"""
    try:
        result = maps_service.create_event_map(event_id)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Event map creation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Terms and Conditions Route
@app.route('/terms')
def terms_conditions():
    """Display terms and conditions"""
    return render_template('terms_conditions.html')

if __name__ == '__main__':
    print("=" * 80)
    print("🚀 COMPREHENSIVE POLITICAL EVENT MANAGEMENT SYSTEM WITH ALL FEATURES")
    print("=" * 80)
    print("✅ Admin Login: admin@political.com / admin123")
    print("✅ Database: SQLAlchemy with migration support")
    print("✅ Security: JWT, Input validation, File encryption")
    print("✅ Core Features: Activity logging, Admin history, Event management")
    print("✅ NEW FEATURES IMPLEMENTED:")
    print("   🏛️  Political Party Email Verification")
    print("   📱 WhatsApp OTP & Group Management")
    print("   🎫 Freshdesk CRM Support")
    print("   🤖 Auto Matcher/Scheduler")
    print("   🗺️  Google Maps Integration")
    print("   📋 Terms & Conditions")
    print("   ⚠️  KYC & Payment services removed")
    print("✅ Server starting at http://127.0.0.1:5000")
    print("=" * 80)
    
    # For production deployment
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
