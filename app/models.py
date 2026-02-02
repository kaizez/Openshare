from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime

db = SQLAlchemy()
ph = PasswordHasher()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)

    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(255), nullable=True)
    profile_picture_url = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_login_location = db.Column(db.String(255), nullable=True)

    # Password reset fields
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # 2FA OTP fields (for password reset)
    otp_secret = db.Column(db.String(10), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)

    # MFA TOTP fields (for login authentication)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)

    # Admin security fields
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)  # First admin, no MAC check needed
    whitelisted_devices = db.Column(db.Text, nullable=True)  # JSON array of device fingerprints
    whitelisted_ips = db.Column(db.Text, nullable=True)  # JSON array of IP addresses

    # MAC address verification for admins
    registered_mac_address = db.Column(db.String(17), nullable=True)  # XX:XX:XX:XX:XX:XX format
    mac_address_registered = db.Column(db.Boolean, default=False)  # Whether MAC is set up

    # Account lockout and login attempt tracking
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def verify_password(self, password):
        if not self.password_hash:
            return False
        try:
            ph.verify(self.password_hash, password)
            return True
        except VerifyMismatchError:
            return False

    def is_oauth_user(self):
        return self.oauth_provider is not None

    def is_locked(self):
        """Check if account is currently locked"""
        if not self.account_locked:
            return False

        # Check if lock has expired
        if self.locked_until and datetime.utcnow() >= self.locked_until:
            # Auto-unlock
            self.account_locked = False
            self.locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
            return False

        return True

    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        self.last_failed_login = datetime.utcnow()

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.account_locked = True
            # Lock for 15 minutes
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

        db.session.commit()

    def reset_failed_login_attempts(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.account_locked = False
        self.locked_until = None
        db.session.commit()

    def __repr__(self):
        return f'<User {self.username}>'


class LoginHistory(db.Model):
    """Track login history for ML-based anomaly detection"""
    __tablename__ = 'login_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Login details
    ip_address = db.Column(db.String(45), nullable=True)
    location = db.Column(db.String(255), nullable=True)
    device_fingerprint = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)

    # Risk assessment
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default='low')
    risk_factors = db.Column(db.Text, nullable=True)  # JSON array

    # Login result
    success = db.Column(db.Boolean, default=True)
    failure_reason = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<LoginHistory user={self.user_id} timestamp={self.timestamp}>'
