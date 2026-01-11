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

    # 2FA OTP fields
    otp_secret = db.Column(db.String(10), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)

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

    def __repr__(self):
        return f'<User {self.username}>'
