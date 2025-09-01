from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import enum

db = SQLAlchemy()

class UserType(enum.Enum):
    NORMAL = "normal"
    ADMIN = "admin"
    POLITICAL_PARTY = "political_party"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    whatsapp_phone = db.Column(db.String(15))
    location = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.Enum(UserType), default=UserType.NORMAL, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    
    # Verification Fields
    verification_status = db.Column(db.String(20), default='pending')  # pending, verified, failed
    verification_score = db.Column(db.Float)
    
    # Political Party Specific Fields
    is_party_admin = db.Column(db.Boolean, default=False)
    party_name = db.Column(db.String(100))
    party_domain = db.Column(db.String(100))
    party_verification_status = db.Column(db.String(20), default='pending')
    organization_email = db.Column(db.String(120))  # For political party verification
    
    # WhatsApp Verification
    whatsapp_verified = db.Column(db.Boolean, default=False)
    whatsapp_otp = db.Column(db.String(6))
    otp_expires_at = db.Column(db.DateTime)
    otp_attempts = db.Column(db.Integer, default=0)
    
    # Document Storage
    adhar_front = db.Column(db.String(200))
    adhar_back = db.Column(db.String(200))
    selfie = db.Column(db.String(200))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    registrations = db.relationship('Registration', backref='user', lazy=True)
    support_tickets = db.relationship('SupportTicket', backref='user', lazy=True)
    volunteer_skills = db.relationship('VolunteerSkill', backref='user', lazy=True)
    auto_matches = db.relationship('AutoMatch', backref='volunteer', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)
    agreements = db.relationship('UserAgreement', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'uuid': self.uuid,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'whatsapp_phone': self.whatsapp_phone,
            'location': self.location,
            'user_type': self.user_type.value if self.user_type else None,
            'status': self.status,
            'verification_status': self.verification_status,
            'is_party_admin': self.is_party_admin,
            'party_name': self.party_name,
            'whatsapp_verified': self.whatsapp_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @property
    def is_approved(self):
        return self.status == 'approved'
    
    @property
    def is_political_party(self):
        return self.user_type == UserType.POLITICAL_PARTY
    
    @property
    def is_admin(self):
        return self.user_type == UserType.ADMIN

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    party_name = db.Column(db.String(100), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    event_time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    qr_code = db.Column(db.String(200))
    status = db.Column(db.String(20), default='upcoming')  # upcoming, ongoing, completed, cancelled
    max_volunteers = db.Column(db.Integer, default=50)
    payment_amount = db.Column(db.Integer, default=0)  # Amount in paise
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    registrations = db.relationship('Registration', backref='event', lazy=True)
    requirements = db.relationship('EventRequirement', backref='event', lazy=True)
    auto_matches = db.relationship('AutoMatch', backref='event', lazy=True)
    whatsapp_groups = db.relationship('WhatsAppGroup', backref='event', lazy=True)

class Registration(db.Model):
    __tablename__ = 'registrations'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    status = db.Column(db.String(20), default='registered')  # registered, checked_in, completed, cancelled
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    payment_status = db.Column(db.String(20), default='pending')  # pending, paid, refunded
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id'),)

class Payment(db.Model):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    payment_id = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))
    amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    currency = db.Column(db.String(3), default='INR')
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, refunded
    payment_method = db.Column(db.String(50))
    razorpay_order_id = db.Column(db.String(100))
    razorpay_payment_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Payout(db.Model):
    __tablename__ = 'payouts'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    payout_id = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    registration_id = db.Column(db.Integer, db.ForeignKey('registrations.id'))
    amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, failed
    bank_account = db.Column(db.String(50))
    ifsc_code = db.Column(db.String(20))
    account_holder_name = db.Column(db.String(100))
    razorpay_payout_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)

class CommissionTransaction(db.Model):
    __tablename__ = 'commission_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.id'), nullable=False)
    commission_amount = db.Column(db.Integer, nullable=False)  # Amount in paise
    commission_percentage = db.Column(db.Float, nullable=False)
    commission_type = db.Column(db.String(50))  # platform_fee, payment_gateway_fee, payout_fee
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class WhatsAppGroup(db.Model):
    __tablename__ = 'whatsapp_groups'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    group_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('GroupMember', backref='group', lazy=True)

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('whatsapp_groups.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    phone_number = db.Column(db.String(15))
    role = db.Column(db.String(20), default='member')  # admin, member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)

class SupportTicket(db.Model):
    __tablename__ = 'support_tickets'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    ticket_id = db.Column(db.String(100), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.Integer, default=1)  # 1=low, 2=medium, 3=high, 4=urgent
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, closed
    category = db.Column(db.String(50))  # technical, payment, general
    freshdesk_ticket_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class VolunteerSkill(db.Model):
    __tablename__ = 'volunteer_skills'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    skill_name = db.Column(db.String(100), nullable=False)
    proficiency_level = db.Column(db.Integer, default=1)  # 1-5 scale
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EventRequirement(db.Model):
    __tablename__ = 'event_requirements'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    required_skill = db.Column(db.String(100), nullable=False)
    min_proficiency = db.Column(db.Integer, default=1)
    priority = db.Column(db.Integer, default=1)  # 1=optional, 2=preferred, 3=required
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AutoMatch(db.Model):
    __tablename__ = 'auto_matches'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    match_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='suggested')  # suggested, accepted, declined, pending
    volunteer_response = db.Column(db.String(20))  # accept, decline, pending
    auto_assigned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)

class UserAgreement(db.Model):
    __tablename__ = 'user_agreements'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    agreement_type = db.Column(db.String(50), nullable=False)  # terms, privacy, volunteer_agreement, party_agreement
    version = db.Column(db.String(20), nullable=False)
    accepted_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

class AgreementVersion(db.Model):
    __tablename__ = 'agreement_versions'
    
    id = db.Column(db.Integer, primary_key=True)
    agreement_type = db.Column(db.String(50), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    effective_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminUser(db.Model):
    __tablename__ = 'admin_users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='admin')  # admin, super_admin
    permissions = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    admin_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    activity_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    event_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
