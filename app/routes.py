from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify, Response, stream_with_context
from flask_mail import Message
from app import oauth, mail, limiter
from app.models import db, User, LoginHistory, ChatHistory
from app.siem_logger import SIEMLogger
from app.ml_security import LoginBehaviorAnalyzer, build_login_data
from app.keystroke_dynamics import keystroke_analyzer
from app.shamir_recovery import generate_recovery_shares, recover_mfa_secret, hash_share
from app.chat_scoring import score_message, get_user_behavior_score
import geoip2.database
import geoip2.errors
import os
import re
import html
import requests
import secrets
import pyotp
from datetime import datetime, timedelta
import qrcode
import io
import base64
import hashlib
import json
import sys
from functools import wraps

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'FileTransfer'))

from retention_policy import get_retention_policy
from db import Database

bp = Blueprint('main', __name__)

# Initialize SIEM Logger - connects to Ayden's SIEM system
# The SIEM URL and API key are configurable via environment variables
SIEM_URL = os.environ.get('SIEM_URL', 'http://siem:5001')
SIEM_API_KEY = os.environ.get('SIEM_API_KEY')
siem = SIEMLogger(SIEM_URL, api_key=SIEM_API_KEY, log_source="authentication")

# Initialize ML Security Analyzer
ml_analyzer = LoginBehaviorAnalyzer()

def init_user_session(user):
    """Initialize session with user data, session ID, and activity timestamp"""
    import uuid
    session_id = str(uuid.uuid4())

    session['user'] = user.username
    session['user_id'] = user.id
    session['session_id'] = session_id
    session['last_activity'] = datetime.utcnow().isoformat()

    # Store session ID in user model for concurrent session control
    user.current_session_id = session_id
    db.session.commit()


def sanitize_input(text):
    """Sanitize user input by escaping HTML and removing dangerous characters"""
    if not text:
        return text
    # Escape HTML tags
    return html.escape(text.strip())

def validate_password_strength(password):
    """
    Validate password strength
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character (@$!%*?&)"

    return True, None

# Username blacklist - inappropriate or reserved words
USERNAME_BLACKLIST = [
    'admin', 'administrator', 'root', 'superuser', 'system', 'moderator', 'mod',
    'support', 'helpdesk', 'staff', 'official', 'OpenShare', 'operator',
    'fuck', 'shit', 'ass', 'bitch', 'damn', 'cunt', 'dick', 'pussy', 'nigger', 'nigga',
    'bastard', 'whore', 'slut', 'fag', 'faggot', 'retard', 'idiot', 'stupid',
    'null', 'undefined', 'none', 'test', 'user', 'guest', 'anonymous', 'default'
]

def validate_username(username):
    """
    Validate username for inappropriate or reserved words
    Returns (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"

    if len(username) < 3:
        return False, "Username must be at least 3 characters long"

    if len(username) > 20:
        return False, "Username must be less than 20 characters"

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"

    # Check blacklist (case-insensitive)
    username_lower = username.lower()
    for word in USERNAME_BLACKLIST:
        if word in username_lower:
            return False, f"Username contains inappropriate or reserved word"

    return True, None

def verify_recaptcha(recaptcha_response):
    """Verify reCAPTCHA response with Google"""
    secret_key = current_app.config.get('RECAPTCHA_SECRET_KEY')

    if not secret_key or secret_key == 'your-recaptcha-secret-key-here':
        # Skip verification in development if not configured
        return True

    try:
        payload = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA verification error: {str(e)}")
        return False

def get_client_ip():
    """Get the client's IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr or '127.0.0.1'

def get_location_from_ip(ip_address):
    """Get location information from IP address using GeoIP2"""
    try:
        # For local development, return default location
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return 'Local Development'

        # Path to GeoLite2 database (you'll need to download this)
        db_path = os.path.join(os.path.dirname(__file__), '..', 'GeoLite2-City.mmdb')

        if not os.path.exists(db_path):
            return 'Singapore'

        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip_address)
            city = response.city.name or 'Unknown City'
            country = response.country.name or 'Unknown Country'
            return f'{city}, {country}'
    except (geoip2.errors.AddressNotFoundError, Exception):
        return 'Singapore'

def get_device_fingerprint():
    """Create unique device fingerprint"""
    device_data = {
        'user_agent': request.user_agent.string or '',
        'browser': request.user_agent.browser or '',
        'platform': request.user_agent.platform or '',
        'language': request.accept_languages.best or '',
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'accept': request.headers.get('Accept', ''),
    }

    # Create hash of device data
    fingerprint = hashlib.sha256(
        json.dumps(device_data, sort_keys=True).encode()
    ).hexdigest()

    return fingerprint

def send_admin_security_alert(email, username, alert_data):
    """Send security alert email for admin login attempts"""
    try:
        msg = Message(
            subject='Security Alert: Admin Login Attempt from Unauthorized Device - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #c53030;">Admin Security Alert</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>An admin login attempt was detected from an <strong>unauthorized device or IP address</strong>.</p>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Attempt Details:</h3>
                        <p style="margin: 5px 0;"><strong>Device Fingerprint:</strong> {alert_data['device_id'][:16]}...</p>
                        <p style="margin: 5px 0;"><strong>Device Whitelisted:</strong> {'✅ Yes' if alert_data['device_whitelisted'] else '❌ No'}</p>
                        <p style="margin: 5px 0;"><strong>IP Address:</strong> {alert_data['ip']}</p>
                        <p style="margin: 5px 0;"><strong>IP Whitelisted:</strong> {'✅ Yes' if alert_data['ip_whitelisted'] else '❌ No'}</p>
                        <p style="margin: 5px 0;"><strong>Location:</strong> {alert_data['location']}</p>
                        <p style="margin: 5px 0;"><strong>Date & Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Action Required</h3>
                        <p>If this was you attempting to login:</p>
                        <ul>
                            <li>Login from a whitelisted device</li>
                            <li>Or register this new device in your admin settings</li>
                        </ul>
                        <p>If this was NOT you:</p>
                        <ul>
                            <li>Your credentials may be compromised</li>
                            <li>Change your password immediately</li>
                            <li>Contact support at <a href="mailto:support@openshare.com">support@openshare.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Admin Security Alert

        Hello {username},

        An admin login attempt was detected from an unauthorized device or IP address.

        Attempt Details:
        - Device Fingerprint: {alert_data['device_id'][:16]}...
        - Device Whitelisted: {'Yes' if alert_data['device_whitelisted'] else 'No'}
        - IP Address: {alert_data['ip']}
        - IP Whitelisted: {'Yes' if alert_data['ip_whitelisted'] else 'No'}
        - Location: {alert_data['location']}
        - Date & Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

        Action Required:
        If this was you attempting to login, login from a whitelisted device or register this new device in your admin settings.

        If this was NOT you, your credentials may be compromised. Change your password immediately and contact support.

        This is an automated security notification from OpenShare.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending admin security alert: {str(e)}")
        return False

def send_account_creation_email(email, username, ip_address, location, signup_method='Email Registration'):
    """Send account creation notification email"""
    try:
        msg = Message(
            subject='New Account Created - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #48bb78;">Welcome to OpenShare!</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>A new account has been successfully created with this email address.</p>

                    <div style="background-color: #f7fafc; border-left: 4px solid #48bb78; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Account Details:</h3>
                        <p style="margin: 5px 0;"><strong>Username:</strong> {username}</p>
                        <p style="margin: 5px 0;"><strong>Email:</strong> {email}</p>
                        <p style="margin: 5px 0;"><strong>Sign-up Method:</strong> {signup_method}</p>
                        <p style="margin: 5px 0;"><strong>IP Address:</strong> {ip_address}</p>
                        <p style="margin: 5px 0;"><strong>Location:</strong> {location}</p>
                        <p style="margin: 5px 0;"><strong>Date & Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Was this you?</h3>
                        <p>If you did not create this account, please contact us immediately at <a href="mailto:support@openshare.com">support@openshare.com</a></p>
                    </div>

                    <p>Thank you for choosing OpenShare!</p>
                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Welcome to OpenShare!

        Hello {username},

        A new account has been successfully created with this email address.

        Account Details:
        - Username: {username}
        - Email: {email}
        - Sign-up Method: {signup_method}
        - IP Address: {ip_address}
        - Location: {location}
        - Date & Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

        Was this you?
        If you did not create this account, please contact us immediately at support@openshare.com

        Thank you for choosing OpenShare!

        This is an automated security notification from OpenShare. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def send_mfa_disabled_email(email, username, ip_address, location):
    """Send security notification when MFA is disabled"""
    try:
        msg = Message(
            subject='Security Alert: Two-Factor Authentication Disabled - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #c53030;">Security Alert: MFA Disabled</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>Two-Factor Authentication (MFA) has been <strong>disabled</strong> on your OpenShare account.</p>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Action Details:</h3>
                        <p style="margin: 5px 0;"><strong>Action:</strong> MFA Disabled</p>
                        <p style="margin: 5px 0;"><strong>IP Address:</strong> {ip_address}</p>
                        <p style="margin: 5px 0;"><strong>Location:</strong> {location}</p>
                        <p style="margin: 5px 0;"><strong>Date & Time:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>

                    <div style="background-color: #fffaf0; border-left: 4px solid #ed8936; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c05621;">Security Warning</h3>
                        <p>Your account is now less secure. Anyone with your password can log in without phone verification.</p>
                        <p><strong>We strongly recommend:</strong></p>
                        <ul>
                            <li>Re-enabling MFA as soon as possible</li>
                            <li>Using a strong, unique password</li>
                            <li>Not sharing your account credentials</li>
                        </ul>
                    </div>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Was this you?</h3>
                        <p>If you did not disable MFA, your account may be compromised. Please:</p>
                        <ul>
                            <li>Change your password immediately</li>
                            <li>Re-enable MFA</li>
                            <li>Contact support at <a href="mailto:support@openshare.com">support@openshare.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Security Alert: MFA Disabled

        Hello {username},

        Two-Factor Authentication (MFA) has been disabled on your OpenShare account.

        Action Details:
        - Action: MFA Disabled
        - IP Address: {ip_address}
        - Location: {location}
        - Date & Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

        Security Warning:
        Your account is now less secure. Anyone with your password can log in without phone verification.

        We strongly recommend:
        - Re-enabling MFA as soon as possible
        - Using a strong, unique password
        - Not sharing your account credentials

        Was this you?
        If you did not disable MFA, your account may be compromised. Please:
        - Change your password immediately
        - Re-enable MFA
        - Contact support at support@openshare.com

        This is an automated security notification from OpenShare. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending MFA disabled email: {str(e)}")
        return False

def send_account_locked_email(email, username, ip_address, location, unlock_time):
    """Send security notification when account is locked due to failed login attempts"""
    try:
        msg = Message(
            subject='Security Alert: Account Locked - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #c53030;">Security Alert: Account Locked</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>Your account has been <strong>temporarily locked</strong> due to multiple failed login attempts.</p>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Lockout Details:</h3>
                        <p style="margin: 5px 0;"><strong>Reason:</strong> 5 failed login attempts</p>
                        <p style="margin: 5px 0;"><strong>IP Address:</strong> {ip_address}</p>
                        <p style="margin: 5px 0;"><strong>Location:</strong> {location}</p>
                        <p style="margin: 5px 0;"><strong>Locked At:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                        <p style="margin: 5px 0;"><strong>Auto-Unlock At:</strong> {unlock_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    </div>

                    <div style="background-color: #fffaf0; border-left: 4px solid #ed8936; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c05621;">What Happens Next</h3>
                        <p>Your account will automatically unlock in <strong>15 minutes</strong>.</p>
                        <p>After unlock, you can try logging in again.</p>
                    </div>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Was this you?</h3>
                        <p>If you did not attempt to login, your account may be under attack. Please:</p>
                        <ul>
                            <li>Change your password immediately after the account unlocks</li>
                            <li>Enable Two-Factor Authentication if not already enabled</li>
                            <li>Contact support at <a href="mailto:support@openshare.com">support@openshare.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Security Alert: Account Locked

        Hello {username},

        Your account has been temporarily locked due to multiple failed login attempts.

        Lockout Details:
        - Reason: 5 failed login attempts
        - IP Address: {ip_address}
        - Location: {location}
        - Locked At: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        - Auto-Unlock At: {unlock_time.strftime('%Y-%m-%d %H:%M:%S UTC')}

        What Happens Next:
        Your account will automatically unlock in 15 minutes.
        After unlock, you can try logging in again.

        Was this you?
        If you did not attempt to login, your account may be under attack. Please:
        - Change your password immediately after the account unlocks
        - Enable Two-Factor Authentication if not already enabled
        - Contact support at support@openshare.com

        This is an automated security notification from OpenShare. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending account locked email: {str(e)}")
        return False


def send_impossible_travel_email(email, username, last_location, current_location, last_ip, current_ip, time_diff_minutes):
    """Send security alert when impossible travel is detected and account is locked"""
    try:
        msg = Message(
            subject='URGENT Security Alert: Suspicious Login Detected - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #c53030;">URGENT: Suspicious Login Activity Detected</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>We have detected <strong>impossible travel</strong> on your account. Your account has been <strong>locked</strong> for security.</p>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">What We Detected:</h3>
                        <p>Your account was accessed from two different locations within {time_diff_minutes} minutes, which is physically impossible.</p>
                        <p style="margin: 10px 0;"><strong>Previous Login:</strong></p>
                        <ul>
                            <li>Location: {last_location}</li>
                            <li>IP Address: {last_ip}</li>
                        </ul>
                        <p style="margin: 10px 0;"><strong>New Login Attempt:</strong></p>
                        <ul>
                            <li>Location: {current_location}</li>
                            <li>IP Address: {current_ip}</li>
                        </ul>
                    </div>

                    <div style="background-color: #fff5f5; border-left: 4px solid #c53030; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c53030;">Your Account Has Been Locked</h3>
                        <p>For your security, we have immediately locked your account.</p>
                        <p>To unlock your account, please contact our support team:</p>
                        <ul>
                            <li>Email: <a href="mailto:support@openshare.com">support@openshare.com</a></li>
                        </ul>
                    </div>

                    <div style="background-color: #fffaf0; border-left: 4px solid #ed8936; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c05621;">Recommended Actions:</h3>
                        <ul>
                            <li>Contact support immediately to verify your identity</li>
                            <li>Change your password once your account is unlocked</li>
                            <li>Review your account activity for any unauthorized access</li>
                            <li>Enable Two-Factor Authentication if not already enabled</li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        URGENT: Suspicious Login Activity Detected

        Hello {username},

        We have detected impossible travel on your account. Your account has been locked for security.

        What We Detected:
        Your account was accessed from two different locations within {time_diff_minutes} minutes, which is physically impossible.

        Previous Login:
        - Location: {last_location}
        - IP Address: {last_ip}

        New Login Attempt:
        - Location: {current_location}
        - IP Address: {current_ip}

        Your Account Has Been Locked
        For your security, we have immediately locked your account.
        To unlock your account, please contact our support team:
        - Email: support@openshare.com

        Recommended Actions:
        - Contact support immediately to verify your identity
        - Change your password once your account is unlocked
        - Review your account activity for any unauthorized access
        - Enable Two-Factor Authentication if not already enabled

        This is an automated security notification from OpenShare. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending impossible travel email: {str(e)}")
        return False


def send_password_reset_email(email, username, otp_code):
    """Send password reset email with OTP code only"""
    try:
        msg = Message(
            subject='Password Reset Request - OpenShare',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #48bb78;">Password Reset Request</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>We received a request to reset your password. Please use the verification code below to proceed with your password reset.</p>

                    <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Your Verification Code</h3>
                        <p style="font-size: 32px; font-weight: bold; color: #c53030; text-align: center; letter-spacing: 5px; margin: 20px 0;">{otp_code}</p>
                        <p style="text-align: center; font-size: 12px; color: #718096;">This code will expire in 15 minutes.</p>
                    </div>

                    <div style="background-color: #fffaf0; border-left: 4px solid #ed8936; padding: 15px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #c05621;">Security Notice</h3>
                        <p>If you did not request a password reset, please ignore this email. Your password will remain unchanged.</p>
                        <p>For security reasons, this verification code will expire in 15 minutes.</p>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from OpenShare. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Password Reset Request - OpenShare

        Hello {username},

        We received a request to reset your password. Please use the verification code below to proceed with your password reset.

        Your Verification Code: {otp_code}

        This code will expire in 15 minutes.

        Security Notice:
        If you did not request a password reset, please ignore this email. Your password will remain unchanged.
        For security reasons, this verification code will expire in 15 minutes.

        This is an automated security notification from OpenShare. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending password reset email: {str(e)}")
        return False

@bp.route('/')
def index():
    """Landing page"""
    user = None
    # Check if user is logged in and get MFA status
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            session['mfa_enabled'] = user.mfa_enabled
    return render_template('index.html', user=user)

@bp.route('/debug-oauth')
def debug_oauth():
    redirect_uri = url_for('main.google_callback', _external=True, _scheme='https')
    return f"""
    <h1>OAuth Debug Info</h1>
    <p><strong>Redirect URI that will be sent to Google:</strong></p>
    <code style='background: #f0f0f0; padding: 10px; display: block;'>{redirect_uri}</code>
    <br>
    <p>Make sure this EXACT URL is added to your Google Cloud Console OAuth credentials!</p>
    <br>
    <a href='/login'>Back to Login</a>
    """

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')  # Don't sanitize passwords

        if not username or not password:
            flash('Please enter both username and password', 'error')
        else:
            # Find user by username
            user = User.query.filter_by(username=username).first()

            # Check if account exists
            if user:
                # Check if account is locked
                if user.is_locked():
                    minutes_remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
                    flash(f'Account is locked due to too many failed login attempts. Please try again in {minutes_remaining} minutes.', 'error')
                    return render_template('login.html')

                # Verify password
                if user.verify_password(password):
                    # Password verified with Argon2id

                    # === KEYSTROKE DYNAMICS CHECK ===
                    keystroke_data = request.form.get('keystroke_data')
                    if keystroke_data:
                        try:
                            ks_data = json.loads(keystroke_data)
                            ks_valid, ks_score, ks_msg = keystroke_analyzer.verify(user.keystroke_profile, ks_data)

                            # Update user's keystroke profile
                            current_features = keystroke_analyzer.extract_features(ks_data)
                            if current_features:
                                existing_profile = json.loads(user.keystroke_profile) if user.keystroke_profile else None
                                updated_profile = keystroke_analyzer.update_profile(existing_profile, current_features)
                                user.keystroke_profile = json.dumps(updated_profile)
                                db.session.commit()

                            # Log keystroke analysis
                            if not ks_valid:
                                siem.custom_event(
                                    event_type='keystroke_mismatch',
                                    description=f'Keystroke pattern mismatch for {user.username}: {ks_msg}',
                                    severity='High',
                                    user_id=user.username,
                                    ip=get_client_ip()
                                )
                        except Exception as e:
                            print(f"Keystroke analysis error: {e}")

                    # === ML RISK ANALYSIS ===
                    current_ip = get_client_ip()
                    current_location = get_location_from_ip(current_ip)
                    device_fp = get_device_fingerprint()

                    # Get login history for ML
                    login_history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).limit(20).all()
                    history_data = [{'timestamp': h.timestamp, 'ip': h.ip_address, 'location': h.location} for h in login_history]

                    # Build login data and analyze
                    login_data = build_login_data(user, current_ip, current_location, device_fp, history_data)
                    risk_score, risk_level, risk_factors = ml_analyzer.calculate_risk_score(login_data, history_data)

                    # Log to LoginHistory
                    login_record = LoginHistory(
                        user_id=user.id,
                        ip_address=current_ip,
                        location=current_location,
                        device_fingerprint=device_fp,
                        user_agent=request.headers.get('User-Agent', '')[:500],
                        risk_score=risk_score,
                        risk_level=risk_level,
                        risk_factors=json.dumps(risk_factors),
                        success=True
                    )
                    db.session.add(login_record)
                    db.session.commit()

                    # Handle high risk logins
                    if risk_level == 'critical':
                        siem.custom_event(
                            event_type='high_risk_login_blocked',
                            description=f'Critical risk login blocked for {user.username}',
                            severity='Critical',
                            user_id=user.username,
                            ip=current_ip,
                            risk_score=risk_score,
                            risk_factors=risk_factors
                        )
                        user.account_locked = True
                        user.locked_until = None  # Manual unlock required
                        db.session.commit()
                        flash('Login blocked due to suspicious activity. Please contact support.', 'error')
                        return render_template('login.html')

                    # Reset failed login attempts on successful login
                    user.reset_failed_login_attempts()

                    # Log to SIEM - initial password verification (full login logged after MFA if enabled)
                    ip = get_client_ip()

                    # ADMIN SECURITY CHECK
                    # Super admin bypasses device/IP checks - uses MAC verification instead
                    # Regular admins also use MAC verification after MFA
                    if user.is_admin and not user.is_super_admin:
                        # Check if this is a regular admin with device whitelist (legacy check)
                        allowed_devices = json.loads(user.whitelisted_devices or '[]')
                        allowed_ips = json.loads(user.whitelisted_ips or '[]')

                        # Only apply legacy device/IP check if they have whitelisted devices but no MAC
                        if allowed_devices and not user.mac_address_registered:
                            device_id = get_device_fingerprint()
                            current_ip = get_client_ip()

                            device_allowed = device_id in allowed_devices
                            ip_allowed = current_ip in allowed_ips

                            if not device_allowed or not ip_allowed:
                                send_admin_security_alert(user.email, user.username, {
                                    'device_id': device_id,
                                    'ip': current_ip,
                                    'location': get_location_from_ip(current_ip),
                                    'device_whitelisted': device_allowed,
                                    'ip_whitelisted': ip_allowed
                                })

                                user.account_locked = True
                                user.locked_until = None  # Manual unlock required
                                db.session.commit()

                                return render_template('admin_unauthorized.html',
                                    device_match=device_allowed,
                                    ip_match=ip_allowed,
                                    device_id=device_id,
                                    current_ip=current_ip
                                )

                    # Check if MFA is enabled
                    if user.mfa_enabled:
                        # Store user ID temporarily for MFA verification
                        session['mfa_user_id'] = user.id
                        return redirect(url_for('main.mfa_verify'))
                    else:
                        # ADMIN MUST HAVE MFA - redirect to setup if not enabled
                        if user.is_admin and not user.mfa_enabled:
                            # Generate MFA secret if not exists
                            if not user.mfa_secret:
                                user.mfa_secret = pyotp.random_base32()
                                db.session.commit()

                            # Store admin user ID for MFA setup
                            session['admin_mfa_setup_user_id'] = user.id
                            return redirect(url_for('main.admin_mfa_setup'))

                        # No MFA - check if admin needs MAC verification
                        if user.is_admin and not user.is_super_admin and user.mac_address_registered:
                            # Admin with MAC registered - need MAC verification
                            session['mac_verify_user_id'] = user.id
                            return redirect(url_for('main.admin_mac_verify'))

                        # Complete login
                        init_user_session(user)
                        flash('Login successful!', 'success')

                        # Auto-whitelist device and IP for admins (first login without MFA)
                        if user.is_admin:
                            device_id = get_device_fingerprint()
                            current_ip = get_client_ip()

                            # Add device to whitelist if not already
                            devices = json.loads(user.whitelisted_devices or '[]')
                            if device_id not in devices:
                                devices.append(device_id)
                                user.whitelisted_devices = json.dumps(devices)

                            # Add IP to whitelist if not already
                            ips = json.loads(user.whitelisted_ips or '[]')
                            if current_ip not in ips:
                                ips.append(current_ip)
                                user.whitelisted_ips = json.dumps(ips)

                            db.session.commit()

                        # Log successful login to SIEM
                        siem.login_success(
                            user_id=user.username,
                            ip=get_client_ip(),
                            user_role='admin' if user.is_admin else 'standard',
                            mfa_used=False
                        )

                        # Redirect admin to dashboard
                        if user.is_admin:
                            return redirect(url_for('main.admin_dashboard'))
                        return redirect(url_for('filetransfer.index'))
                else:
                    # Password incorrect - record failed attempt
                    was_locked_before = user.account_locked
                    user.record_failed_login()

                    # Log failed login to SIEM
                    ip_address = get_client_ip()
                    siem.login_failed(username=username, ip=ip_address, reason="invalid password")

                    # Send email if account just got locked
                    if not was_locked_before and user.account_locked:
                        location = get_location_from_ip(ip_address)
                        send_account_locked_email(user.email, user.username, ip_address, location, user.locked_until)
                        # Log account lockout to SIEM
                        siem.account_locked(
                            user_id=user.username,
                            ip=ip_address,
                            reason="too many failed login attempts",
                            locked_by="system"
                        )

                    attempts_left = max(0, 5 - user.failed_login_attempts)
                    if attempts_left > 0:
                        flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'error')
                    else:
                        flash('Account locked due to too many failed attempts. Check your email for details.', 'error')
            else:
                # Username not found - don't reveal this to prevent user enumeration
                # Log failed login to SIEM (unknown user)
                siem.login_failed(username=username, ip=get_client_ip(), reason="user not found")
                flash('Invalid username or password', 'error')

    return render_template('login.html')


@bp.route('/check-username', methods=['POST'])
def check_username():
    """AJAX endpoint to check if username is available"""
    from flask import jsonify
    username = sanitize_input(request.form.get('username', ''))

    if not username:
        return jsonify({'available': False, 'message': 'Username is required'})

    # Validate username format and blacklist
    is_valid, error_message = validate_username(username)
    if not is_valid:
        return jsonify({'available': False, 'message': error_message})

    # Check if username exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        return jsonify({'available': False, 'message': 'Username already exists'})

    return jsonify({'available': True, 'message': 'Username is available'})


@bp.route('/check-email', methods=['POST'])
def check_email():
    """AJAX endpoint to check if email is available"""
    from flask import jsonify
    email = sanitize_input(request.form.get('email', ''))

    if not email:
        return jsonify({'available': False, 'message': 'Email is required'})

    # Check if email exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        if existing.oauth_provider == 'google':
            return jsonify({'available': False, 'message': 'This email is linked to a Google account'})
        return jsonify({'available': False, 'message': 'Email already in use'})

    return jsonify({'available': True, 'message': 'Email is available'})


@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def register():
    import random

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        email = sanitize_input(request.form.get('email'))
        password = request.form.get('password')  # Don't sanitize passwords
        confirm_password = request.form.get('confirm_password')
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Verify reCAPTCHA
        if not verify_recaptcha(recaptcha_response):
            flash('Please complete the reCAPTCHA verification', 'error')
        elif not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            # Validate username
            is_valid, error_message = validate_username(username)
            if not is_valid:
                flash(error_message, 'error')
                return render_template('register.html', recaptcha_site_key=current_app.config.get('RECAPTCHA_SITE_KEY'))

            # Validate password strength
            is_valid, error_message = validate_password_strength(password)
            if not is_valid:
                flash(error_message, 'error')
            else:
                # Check if user already exists
                existing_user = User.query.filter(
                    (User.username == username) | (User.email == email)
                ).first()

                if existing_user:
                    if existing_user.email == email and existing_user.oauth_provider == 'google':
                        flash('This email is linked to a Google account. Please sign in with Google instead.', 'error')
                    elif existing_user.username == username:
                        flash('Username already exists. Please choose another.', 'error')
                    else:
                        flash('Email already exists. Please sign in or use a different email.', 'error')
                else:
                    # Generate 6-digit OTP for email verification
                    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

                    # Store pending registration data in session
                    session['pending_registration'] = {
                        'username': username,
                        'email': email,
                        'password': password,
                        'otp': otp,
                        'otp_expiry': (datetime.utcnow() + timedelta(minutes=10)).isoformat()
                    }

                    # Send OTP email
                    try:
                        msg = Message(
                            'Verify Your Email - OpenShare',
                            recipients=[email]
                        )
                        msg.html = f'''
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #007aff;">Welcome to OpenShare!</h2>
                            <p>Hi {username},</p>
                            <p>Thank you for registering. Please verify your email address using the code below:</p>
                            <div style="background: #f7fafc; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                                <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #007aff;">{otp}</span>
                            </div>
                            <p>This code expires in <strong>10 minutes</strong>.</p>
                            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
                            <p style="color: #718096; font-size: 12px;">If you did not create this account, please ignore this email.</p>
                        </div>
                        '''
                        mail.send(msg)
                        return redirect(url_for('main.verify_email'))
                    except Exception as e:
                        print(f"Failed to send verification email: {e}")
                        flash('Failed to send verification email. Please try again.', 'error')

    return render_template('register.html', recaptcha_site_key=current_app.config.get('RECAPTCHA_SITE_KEY'))


@bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Verify email with OTP before completing registration"""
    # Check if there's pending registration
    if 'pending_registration' not in session:
        flash('Please register first', 'error')
        return redirect(url_for('main.register'))

    pending = session['pending_registration']

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()

        # Check OTP expiry
        otp_expiry = datetime.fromisoformat(pending['otp_expiry'])
        if datetime.utcnow() > otp_expiry:
            session.pop('pending_registration', None)
            flash('Verification code expired. Please register again.', 'error')
            return redirect(url_for('main.register'))

        # Verify OTP
        if otp != pending['otp']:
            flash('Invalid verification code', 'error')
        else:
            # Check if username or email was taken in the meantime
            existing_user = User.query.filter(
                (User.username == pending['username']) | (User.email == pending['email'])
            ).first()
            if existing_user:
                session.pop('pending_registration', None)
                flash('Username or email is already taken. Please register again with a different username.', 'error')
                return redirect(url_for('main.register'))

            # OTP verified - create the user account
            ip_address = get_client_ip()
            location = get_location_from_ip(ip_address)

            new_user = User(
                username=pending['username'],
                email=pending['email'],
                email_verified=True,
                last_login_ip=ip_address,
                last_login_location=location
            )
            new_user.set_password(pending['password'])

            # Generate MFA secret and enable MFA by default
            new_user.mfa_secret = pyotp.random_base32()
            new_user.mfa_enabled = True

            db.session.add(new_user)
            db.session.commit()

            # Clear pending registration
            session.pop('pending_registration', None)

            # Log user creation to SIEM
            siem.user_created(
                admin_id="self-registration",
                new_user_id=pending['username'],
                ip=ip_address,
                user_role="standard"
            )

            # Send account creation email
            send_account_creation_email(pending['email'], pending['username'], ip_address, location)

            # Log the user in temporarily to set up MFA
            session['user'] = new_user.username
            session['user_id'] = new_user.id
            session['email'] = new_user.email
            session['needs_mfa_setup'] = True

            flash('Email verified successfully!', 'success')
            return redirect(url_for('main.mfa_setup_required'))

    return render_template('verify_email.html', email=pending['email'])


@bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend email verification OTP"""
    import random
    from flask import jsonify

    if 'pending_registration' not in session:
        return jsonify({'success': False, 'message': 'No pending registration'}), 400

    pending = session['pending_registration']

    # Generate new OTP
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    pending['otp'] = otp
    pending['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    session['pending_registration'] = pending

    # Send new OTP email
    try:
        msg = Message(
            'Verify Your Email - OpenShare',
            recipients=[pending['email']]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #007aff;">Email Verification</h2>
            <p>Hi {pending['username']},</p>
            <p>Here is your new verification code:</p>
            <div style="background: #f7fafc; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #007aff;">{otp}</span>
            </div>
            <p>This code expires in <strong>10 minutes</strong>.</p>
        </div>
        '''
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification code sent'})
    except Exception as e:
        print(f"Failed to resend verification email: {e}")
        return jsonify({'success': False, 'message': 'Failed to send email'}), 500

@bp.route('/oauth-confirm', methods=['GET', 'POST'])
def oauth_confirm():
    # Ensure user came from OAuth flow
    if 'oauth_email' not in session or 'oauth_name' not in session:
        flash('Please login with Google first', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'continue':
            # User confirmed, proceed to signup page
            return redirect(url_for('main.oauth_signup'))
        else:  # action == 'cancel'
            # User cancelled, clear OAuth session and return to login
            session.pop('oauth_email', None)
            session.pop('oauth_name', None)
            session.pop('oauth_id', None)
            session.pop('oauth_picture', None)
            flash('Google sign-up cancelled', 'info')
            return redirect(url_for('main.login'))

    return render_template('oauth_confirm.html')

@bp.route('/oauth-signup', methods=['GET', 'POST'])
def oauth_signup():
    # Ensure user came from OAuth flow
    if 'oauth_email' not in session or 'oauth_name' not in session:
        flash('Please login with Google first', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')  # Don't sanitize passwords
        confirm_password = request.form.get('confirm_password')
        email = session.get('oauth_email')
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Verify reCAPTCHA
        if not verify_recaptcha(recaptcha_response):
            flash('Please complete the reCAPTCHA verification', 'error')
        elif not all([username, password, confirm_password]):
            flash('All fields are required', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            # Validate password strength
            is_valid, error_message = validate_password_strength(password)
            if not is_valid:
                flash(error_message, 'error')
            else:
                # Check if username is already taken
                existing_user = User.query.filter_by(username=username).first()

                if existing_user:
                    flash('Username already exists. Please choose another.', 'error')
                else:
                    # Get IP and location
                    ip_address = get_client_ip()
                    location = get_location_from_ip(ip_address)

                    # Create new OAuth user with MFA enabled
                    new_user = User(
                        username=username,
                        email=email,
                        oauth_provider='google',
                        oauth_id=session.get('oauth_id'),
                        profile_picture_url=session.get('oauth_picture'),
                        last_login_ip=ip_address,
                        last_login_location=location
                    )
                    new_user.set_password(password)

                    # Generate MFA secret and enable MFA by default
                    new_user.mfa_secret = pyotp.random_base32()
                    new_user.mfa_enabled = True

                    db.session.add(new_user)
                    db.session.commit()

                    # Send security notification email to their Google email
                    send_account_creation_email(email, username, ip_address, location, 'Google OAuth')

                    # Clear OAuth session data
                    session.pop('oauth_email', None)
                    session.pop('oauth_name', None)
                    session.pop('oauth_id', None)
                    session.pop('oauth_picture', None)

                    # Log the user in temporarily to set up MFA
                    session['user'] = new_user.username
                    session['user_id'] = new_user.id
                    session['email'] = new_user.email
                    session['picture'] = new_user.profile_picture_url
                    session['needs_mfa_setup'] = True

                    return redirect(url_for('main.mfa_setup_required'))

    return render_template('oauth_signup.html', recaptcha_site_key=current_app.config.get('RECAPTCHA_SITE_KEY'))

@bp.route('/link-google-account', methods=['GET', 'POST'])
def link_google_account():
    """Link Google account to existing manual account"""
    # Check if user came from Google OAuth flow with existing manual account
    if 'link_oauth_email' not in session or 'link_user_id' not in session:
        flash('Please sign in with Google first', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['link_user_id'])
    if not user:
        flash('Account not found', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'link':
            password = request.form.get('password')

            if not password:
                flash('Please enter your password to link your Google account', 'error')
            elif not user.verify_password(password):
                flash('Incorrect password. Please try again.', 'error')
            else:
                # Password verified, link Google account
                user.oauth_provider = 'google'
                user.oauth_id = session.get('link_oauth_id')
                user.profile_picture_url = session.get('link_oauth_picture')

                # Update last login info
                user.last_login_ip = get_client_ip()
                user.last_login_location = get_location_from_ip(user.last_login_ip)
                db.session.commit()

                # Clear link session data
                session.pop('link_oauth_email', None)
                session.pop('link_oauth_id', None)
                session.pop('link_oauth_picture', None)
                session.pop('link_user_id', None)

                # Log the user in
                init_user_session(user)
                session['email'] = user.email
                session['picture'] = user.profile_picture_url

                flash(f'Google account linked successfully! Welcome back, {user.username}!', 'success')
                return redirect(url_for('filetransfer.index'))

        elif action == 'cancel':
            # Clear link session data
            session.pop('link_oauth_email', None)
            session.pop('link_oauth_id', None)
            session.pop('link_oauth_picture', None)
            session.pop('link_user_id', None)
            flash('Google account linking cancelled', 'info')
            return redirect(url_for('main.login'))

    return render_template('link_google_account.html',
                           email=session.get('link_oauth_email'),
                           username=user.username)

@bp.route('/google-login')
def google_login():
    # Use the /auth/google/authorized endpoint as the callback URL
    scheme = os.environ.get('URL_SCHEME', 'https')
    redirect_uri = url_for('main.google_callback', _external=True, _scheme=scheme)
    print(f"DEBUG: Redirect URI being sent to Google: {redirect_uri}")
    return oauth.google.authorize_redirect(redirect_uri)

@bp.route('/google-callback')
@bp.route('/auth/google/authorized')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')

        if user_info:
            oauth_email = user_info.get('email')
            oauth_id = user_info.get('sub')  # Google's unique user ID
            oauth_name = user_info.get('name')
            oauth_picture = user_info.get('picture')

            # Check if user already exists in database
            existing_user = User.query.filter_by(email=oauth_email).first()

            if existing_user:
                # Check if user was created via Google OAuth
                if existing_user.oauth_provider == 'google':
                    # User exists and was created via Google, log them in
                    init_user_session(existing_user)
                    session['email'] = existing_user.email
                    session['picture'] = existing_user.profile_picture_url or oauth_picture

                    # Update last login info
                    existing_user.last_login_ip = get_client_ip()
                    existing_user.last_login_location = get_location_from_ip(existing_user.last_login_ip)
                    db.session.commit()

                    flash(f'Welcome back, {existing_user.username}!', 'success')
                    return redirect(url_for('filetransfer.index'))
                else:
                    # User was created manually - prompt to link Google account
                    session['link_oauth_email'] = oauth_email
                    session['link_oauth_id'] = oauth_id
                    session['link_oauth_picture'] = oauth_picture
                    session['link_user_id'] = existing_user.id

                    return redirect(url_for('main.link_google_account'))
            else:
                # New user, redirect to OAuth confirmation page
                session['oauth_email'] = oauth_email
                session['oauth_id'] = oauth_id
                session['oauth_name'] = oauth_name
                session['oauth_picture'] = oauth_picture

                # Redirect to confirmation page to ask user if they want to create account
                return redirect(url_for('main.oauth_confirm'))
        else:
            flash('Failed to get user information from Google', 'error')
            return redirect(url_for('main.login'))
    except Exception as e:
        flash(f'Google login failed: {str(e)}', 'error')
        return redirect(url_for('main.login'))

@bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def forgot_password():
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))

        if not email:
            flash('Please enter your email address', 'error')
        else:
            # Check if user exists
            user = User.query.filter_by(email=email).first()

            if user:
                # Generate 6-digit OTP code
                otp_code = str(secrets.randbelow(999999)).zfill(6)

                # Set expiry to 15 minutes from now
                expiry_time = datetime.utcnow() + timedelta(minutes=15)

                # Save OTP to user record
                user.otp_secret = otp_code
                user.otp_expiry = expiry_time

                db.session.commit()

                # Send password reset email with only OTP code
                send_password_reset_email(email, user.username, otp_code)

            # Always redirect to OTP page (security best practice - don't reveal if email exists)
            session['reset_email'] = email
            flash('A verification code has been sent to your email. Please check your inbox.', 'success')
            return redirect(url_for('main.verify_reset_otp'))

    return render_template('forgot_password.html')

@bp.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    """Step 1: Verify OTP Code with Email"""
    # Check if user came from forgot password page
    if 'reset_email' not in session:
        flash('Please start the password reset process first', 'error')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        email = sanitize_input(request.form.get('email'))
        otp_code = sanitize_input(request.form.get('otp_code'))

        if not email or not otp_code:
            flash('Please enter both email and verification code', 'error')
        else:
            # Find user with this email
            user = User.query.filter_by(email=email).first()

            if not user:
                flash('Invalid email or verification code', 'error')
            elif not user.otp_secret or user.otp_secret != otp_code:
                flash('Invalid verification code. Please check your email and try again.', 'error')
            elif not user.otp_expiry or user.otp_expiry < datetime.utcnow():
                flash('Verification code has expired. Please request a new password reset.', 'error')
                session.pop('reset_email', None)
                return redirect(url_for('main.forgot_password'))
            else:
                # OTP verified successfully, store in session and redirect to password reset form
                session['otp_verified'] = True
                session['reset_user_id'] = user.id
                flash('Verification successful! Now enter your new password.', 'success')
                return redirect(url_for('main.reset_password_confirm'))

    return render_template('verify_otp.html', email=session.get('reset_email'))

@bp.route('/reset-password-confirm', methods=['GET', 'POST'])
def reset_password_confirm():
    """Step 2: Reset Password After OTP Verification"""
    # Check if OTP was verified
    if not session.get('otp_verified') or not session.get('reset_user_id'):
        flash('Please verify your identity first', 'error')
        return redirect(url_for('main.forgot_password'))

    # Find user
    user = User.query.filter_by(id=session.get('reset_user_id')).first()

    # Check if user exists and OTP is still valid
    if not user or not user.otp_expiry or user.otp_expiry < datetime.utcnow():
        # Clear session
        session.pop('otp_verified', None)
        session.pop('reset_user_id', None)
        session.pop('reset_email', None)
        flash('Verification has expired. Please request a new password reset.', 'error')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([new_password, confirm_password]):
            flash('All fields are required', 'error')
        elif new_password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            # Validate password strength
            is_valid, error_message = validate_password_strength(new_password)
            if not is_valid:
                flash(error_message, 'error')
            else:
                # Update password
                user.set_password(new_password)

                # Clear OTP
                user.otp_secret = None
                user.otp_expiry = None

                db.session.commit()

                # Log password change to SIEM
                siem.password_changed(user_id=user.username, ip=get_client_ip())

                # Clear session
                session.pop('otp_verified', None)
                session.pop('reset_user_id', None)
                session.pop('reset_email', None)

                flash('Password reset successful! You can now login with your new password.', 'success')
                return redirect(url_for('main.login'))

    return render_template('reset_password_confirm.html')


@bp.route('/check-location')
def check_location():
    """Check user's current location against last login - called every 5 minutes by frontend.
    Detects impossible travel and locks account if suspicious."""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'status': 'not_logged_in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'status': 'user_not_found'}), 404

    # Get current IP and location
    current_ip = get_client_ip()
    current_location = get_location_from_ip(current_ip)

    # Skip impossible travel check for localhost/local development
    if current_ip in ['127.0.0.1', 'localhost', '::1'] or current_location == 'Local Development':
        return jsonify({'status': 'ok', 'location': current_location, 'note': 'localhost_skipped'})

    # Get last login info
    last_ip = user.last_login_ip
    last_location = user.last_login_location

    # Skip if no previous location data or last login was from localhost
    if not last_location or last_location in ['Location unavailable', 'Local Development']:
        # Update location for next check
        user.last_login_ip = current_ip
        user.last_login_location = current_location
        db.session.commit()
        return jsonify({'status': 'ok', 'location': current_location})

    # Skip if same location
    if last_location == current_location:
        return jsonify({'status': 'ok', 'location': current_location})

    # Different location detected - check if impossible travel
    # Calculate time since last location update (in minutes)
    # For simplicity, we consider any location change within a session as suspicious
    # since sessions are typically short-lived

    # Lock account and send alert
    user.account_locked = True
    user.locked_until = None  # Permanent lock until admin unlocks
    db.session.commit()

    # Calculate approximate time (assume 5 minute intervals)
    time_diff_minutes = 5

    # Send email alert
    send_impossible_travel_email(
        user.email,
        user.username,
        last_location,
        current_location,
        last_ip,
        current_ip,
        time_diff_minutes
    )

    # Log to SIEM
    siem.custom_event(
        event_type='impossible_travel_detected',
        description=f'Impossible travel detected for {user.username}: {last_location} -> {current_location}',
        severity='Critical',
        user_id=user.username,
        ip=current_ip,
        last_location=last_location,
        current_location=current_location,
        last_ip=last_ip,
        current_ip=current_ip
    )

    # Clear session
    session.clear()

    return jsonify({
        'status': 'locked',
        'reason': 'impossible_travel',
        'message': 'Your account has been locked due to suspicious activity. Please contact support.'
    }), 403


@bp.route('/logout')
def logout():
    # Log logout to SIEM before clearing session
    if 'user' in session:
        siem.logout(user_id=session['user'], ip=get_client_ip())

    session.pop('user', None)
    session.pop('user_id', None)
    session.pop('mfa_user_id', None)
    session.pop('mac_verify_user_id', None)
    session.pop('email', None)
    session.pop('picture', None)
    session.pop('_flashes', None)  # Clear flash messages on logout
    return redirect(url_for('main.login'))

@bp.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('main.login'))

    # Get recent login history
    login_history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).limit(5).all()

    # Get latest risk info
    latest_login = login_history[0] if login_history else None
    risk_level = latest_login.risk_level if latest_login else 'low'
    risk_score = latest_login.risk_score if latest_login else 0

    # Calculate password age
    password_days = 0
    if user.password_changed_at:
        password_days = (datetime.utcnow() - user.password_changed_at).days

    # Query workingdb for file transfer stats
    file_count = 0
    upload_count = 0
    download_count = 0
    try:
        working_db = Database()
        working_db.ensure_connection()
        cursor = working_db.connection.cursor(dictionary=True, buffered=True)
        # Count files uploaded by this user (match by user_id as INT)
        cursor.execute(
            "SELECT COUNT(*) as files, COALESCE(SUM(download_count), 0) as downloads FROM file_metadata WHERE uploaded_by = %s",
            (int(user.id),)
        )
        row = cursor.fetchone()
        print(f"[Profile] user.id={user.id}, query result={row}", flush=True)
        if row:
            file_count = row['files'] or 0
            upload_count = row['files'] or 0
            download_count = int(row['downloads'] or 0)
        cursor.close()
        working_db.close()
    except Exception as e:
        import traceback
        print(f"[Profile] Error querying workingdb for file stats: {e}", flush=True)
        traceback.print_exc()

    return render_template('profile.html',
                           user=user,
                           login_history=login_history,
                           risk_level=risk_level,
                           risk_score=risk_score,
                           password_days=password_days,
                           file_count=file_count,
                           upload_count=upload_count,
                           download_count=download_count,
                           timedelta=timedelta)


@bp.route('/upload-avatar', methods=['POST'])
def upload_avatar():
    """Upload profile picture"""
    from flask import jsonify
    import uuid

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400

    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    # Allowed extensions
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

    # Check file extension
    filename = file.filename.lower()
    ext = filename.rsplit('.', 1)[1] if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Invalid file type. Allowed: PNG, JPG'}), 400

    # Check file size
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return jsonify({'success': False, 'message': 'File too large. Maximum size: 2MB'}), 400

    # Save file
    unique_filename = f"avatar_{user.id}_{uuid.uuid4().hex[:8]}.{ext}"
    upload_folder = os.path.join(current_app.root_path, 'static', 'avatars')
    os.makedirs(upload_folder, exist_ok=True)

    filepath = os.path.join(upload_folder, unique_filename)
    file.save(filepath)

    # Update user profile
    user.profile_picture_url = url_for('static', filename=f'avatars/{unique_filename}')
    db.session.commit()

    return jsonify({'success': True, 'url': user.profile_picture_url})


@bp.route('/delete-account-request', methods=['POST'])
def delete_account_request():
    """Request account deletion - sends OTP to email"""
    from flask import jsonify
    import random

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Generate 6-digit OTP
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    user.otp_secret = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()

    # Send OTP email
    try:
        msg = Message(
            'Account Deletion Verification - OpenShare',
            recipients=[user.email]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #c53030;">Account Deletion Request</h2>
            <p>Hi {user.username},</p>
            <p>You have requested to delete your OpenShare account. Use the code below to confirm:</p>
            <div style="background: #f7fafc; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #c53030;">{otp}</span>
            </div>
            <p>This code expires in <strong>10 minutes</strong>.</p>
            <p style="color: #c53030;"><strong>Warning:</strong> This action is irreversible. All your data will be permanently deleted.</p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="color: #718096; font-size: 12px;">If you did not request this, please ignore this email and secure your account.</p>
        </div>
        '''
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification code sent to your email'})
    except Exception as e:
        print(f"Failed to send deletion OTP: {e}")
        return jsonify({'success': False, 'message': 'Failed to send email'}), 500


@bp.route('/delete-account-confirm', methods=['POST'])
def delete_account_confirm():
    """Confirm account deletion with OTP"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    otp = request.form.get('otp', '')

    # Verify OTP
    if not user.otp_secret or user.otp_secret != otp:
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400

    if not user.otp_expiry or datetime.utcnow() > user.otp_expiry:
        return jsonify({'success': False, 'message': 'Verification code expired'}), 400

    # Log to SIEM before deletion
    siem.custom_event(
        event_type='account_deleted',
        description=f'User {user.username} deleted their account',
        severity='Warning',
        user_id=user.username,
        ip=get_client_ip()
    )

    # Delete user's login history
    LoginHistory.query.filter_by(user_id=user.id).delete()

    # Delete user
    db.session.delete(user)
    db.session.commit()

    # Clear session
    session.clear()

    return jsonify({'success': True, 'message': 'Account deleted successfully'})


@bp.route('/settings', methods=['GET'])
def settings():
    """User settings page"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('main.login'))

    # Calculate password expiry info
    days_until_expiry = user.days_until_password_expiry()
    password_expired = user.is_password_expired()

    return render_template('settings.html', user=user,
                          days_until_expiry=days_until_expiry,
                          password_expired=password_expired)


@bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Change password - required when password expires"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('main.login'))

    # OAuth users can't change password
    if user.is_oauth_user():
        flash('OAuth users cannot change password here.', 'error')
        return redirect(url_for('main.settings'))

    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Verify current password
        if not user.verify_password(current_password):
            if is_ajax:
                return jsonify({'success': False, 'message': 'Current password is incorrect.'})
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html', user=user)

        # Check new password matches confirmation
        if new_password != confirm_password:
            if is_ajax:
                return jsonify({'success': False, 'message': 'New passwords do not match.'})
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html', user=user)

        # Validate new password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            if is_ajax:
                return jsonify({'success': False, 'message': error_msg})
            flash(error_msg, 'error')
            return render_template('change_password.html', user=user)

        # Check new password is different from current
        if user.verify_password(new_password):
            if is_ajax:
                return jsonify({'success': False, 'message': 'New password must be different from current password.'})
            flash('New password must be different from current password.', 'error')
            return render_template('change_password.html', user=user)

        # Update password
        user.set_password(new_password)
        user.password_changed_at = datetime.utcnow()
        db.session.commit()

        # Log to SIEM
        siem.password_changed(user_id=user.username, ip=get_client_ip())

        # Send email notification
        try:
            msg = Message(
                'Password Changed - OpenShare Security Alert',
                recipients=[user.email]
            )
            msg.html = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #1a202c;">Password Changed Successfully</h2>
                <p>Hi {user.username},</p>
                <p>Your password was changed on <strong>{datetime.utcnow().strftime('%B %d, %Y at %I:%M %p')} UTC</strong>.</p>
                <p>If you did not make this change, please contact support immediately and secure your account.</p>
                <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
                <p style="color: #718096; font-size: 12px;">This is an automated security notification from OpenShare.</p>
            </div>
            '''
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send password change email: {e}")

        if is_ajax:
            return jsonify({'success': True, 'message': 'Password changed successfully!'})
        flash('Password changed successfully!', 'success')
        return redirect(url_for('main.profile'))

    return render_template('change_password.html', user=user)

@bp.route('/mfa-setup-required', methods=['GET', 'POST'])
def mfa_setup_required():
    """Required MFA setup for new users"""
    # Check if user is logged in and needs MFA setup
    if 'user_id' not in session or not session.get('needs_mfa_setup'):
        return redirect(url_for('filetransfer.index'))

    user = User.query.get(session['user_id'])

    if not user:
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        # Verify the TOTP code before completing setup
        verification_code = sanitize_input(request.form.get('verification_code'))

        if verification_code:
            # Verify the code using the user's MFA secret
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(verification_code, valid_window=1):
                # Code is correct, MFA setup complete
                user.mfa_enabled = True

                # Generate Shamir's Secret Sharing recovery codes
                shares, hashed_shares = generate_recovery_shares(user.mfa_secret)
                user.recovery_shares_hash = json.dumps(hashed_shares)
                db.session.commit()

                session.pop('needs_mfa_setup', None)
                session['mfa_enabled'] = True

                # Show recovery codes to the user
                return render_template('mfa_recovery_codes.html',
                                     shares=shares,
                                     redirect_url=url_for('filetransfer.index'))

    # Generate QR code
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='OpenShare Authentication'
    )

    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 for displaying in HTML
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('mfa_setup_required.html',
                         qr_code=qr_code_base64,
                         secret_key=user.mfa_secret)

@bp.route('/admin/mfa-setup', methods=['GET', 'POST'])
def admin_mfa_setup():
    """Required MFA setup for admin users"""
    # Check if admin came from login flow
    if 'admin_mfa_setup_user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['admin_mfa_setup_user_id'])

    if not user or not user.is_admin:
        session.pop('admin_mfa_setup_user_id', None)
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        # Verify the TOTP code before completing setup
        verification_code = sanitize_input(request.form.get('verification_code'))

        if verification_code:
            # Verify the code using the user's MFA secret
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(verification_code, valid_window=1):
                # Code is correct, enable MFA
                user.mfa_enabled = True

                # Generate Shamir's Secret Sharing recovery codes
                shares, hashed_shares = generate_recovery_shares(user.mfa_secret)
                user.recovery_shares_hash = json.dumps(hashed_shares)
                db.session.commit()

                # Clear setup session
                session.pop('admin_mfa_setup_user_id', None)

                # Auto-whitelist device and IP for admin
                device_id = get_device_fingerprint()
                current_ip = get_client_ip()

                devices = json.loads(user.whitelisted_devices or '[]')
                if device_id not in devices:
                    devices.append(device_id)
                    user.whitelisted_devices = json.dumps(devices)

                ips = json.loads(user.whitelisted_ips or '[]')
                if current_ip not in ips:
                    ips.append(current_ip)
                    user.whitelisted_ips = json.dumps(ips)

                db.session.commit()

                # Complete login
                init_user_session(user)
                session['email'] = user.email
                session['mfa_enabled'] = True

                # Log to SIEM
                siem.login_success(
                    user_id=user.username,
                    ip=get_client_ip(),
                    user_role='admin',
                    mfa_used=True
                )

                # Show recovery codes before dashboard
                return render_template('mfa_recovery_codes.html',
                                     shares=shares,
                                     redirect_url=url_for('main.admin_dashboard'))
            else:
                flash('Invalid verification code. Please try again.', 'error')

    # Generate QR code
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='OpenShare Admin'
    )

    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 for displaying in HTML
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('admin_mfa_setup.html',
                         qr_code=qr_code_base64,
                         secret_key=user.mfa_secret,
                         user=user)

@bp.route('/mfa-setup', methods=['GET', 'POST'])
def mfa_setup():
    """Setup MFA for logged-in users"""
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user:
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        # Verify the TOTP code before enabling MFA
        verification_code = sanitize_input(request.form.get('verification_code'))

        if verification_code:
            # Get the secret from session (temporary storage during setup)
            mfa_secret = session.get('temp_mfa_secret')

            if not mfa_secret:
                return redirect(url_for('main.mfa_setup'))

            # Verify the code
            totp = pyotp.TOTP(mfa_secret)
            if totp.verify(verification_code, valid_window=1):
                # Code is correct, enable MFA
                user.mfa_enabled = True
                user.mfa_secret = mfa_secret

                # Generate Shamir's Secret Sharing recovery codes
                shares, hashed_shares = generate_recovery_shares(mfa_secret)
                user.recovery_shares_hash = json.dumps(hashed_shares)
                db.session.commit()

                # Clear temporary secret
                session.pop('temp_mfa_secret', None)

                # Show recovery codes to the user
                return render_template('mfa_recovery_codes.html',
                                     shares=shares,
                                     redirect_url=url_for('filetransfer.index'))

    # Generate new TOTP secret for this user
    if 'temp_mfa_secret' not in session:
        mfa_secret = pyotp.random_base32()
        session['temp_mfa_secret'] = mfa_secret
    else:
        mfa_secret = session['temp_mfa_secret']

    # Generate QR code
    totp = pyotp.TOTP(mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='OpenShare Authentication'
    )

    # Create QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 for displaying in HTML
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('mfa_setup.html',
                         qr_code=qr_code_base64,
                         secret_key=mfa_secret,
                         mfa_enabled=user.mfa_enabled)

@bp.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    """Verify MFA code during login"""
    # Check if user is in MFA verification state
    if 'mfa_user_id' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['mfa_user_id'])

    if not user or not user.mfa_enabled:
        flash('MFA verification error', 'error')
        session.pop('mfa_user_id', None)
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        verification_code = sanitize_input(request.form.get('verification_code'))

        if not verification_code:
            flash('Please enter the verification code', 'error')
        else:
            # Verify the TOTP code
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(verification_code, valid_window=1):
                # Log MFA success to SIEM
                siem.mfa_success(user_id=user.username, ip=get_client_ip())

                # Code is correct - check if admin needs MAC verification
                session.pop('mfa_user_id', None)

                # Admin with MAC registered needs MAC verification
                if user.is_admin and not user.is_super_admin and user.mac_address_registered:
                    session['mac_verify_user_id'] = user.id
                    return redirect(url_for('main.admin_mac_verify'))

                # Auto-whitelist device and IP for admins
                if user.is_admin:
                    device_id = get_device_fingerprint()
                    current_ip = get_client_ip()

                    # Add device to whitelist if not already
                    devices = json.loads(user.whitelisted_devices or '[]')
                    if device_id not in devices:
                        devices.append(device_id)
                        user.whitelisted_devices = json.dumps(devices)

                    # Add IP to whitelist if not already
                    ips = json.loads(user.whitelisted_ips or '[]')
                    if current_ip not in ips:
                        ips.append(current_ip)
                        user.whitelisted_ips = json.dumps(ips)

                    db.session.commit()

                # Complete login
                init_user_session(user)
                session['email'] = user.email
                session['picture'] = user.profile_picture_url

                # Log successful login to SIEM (with MFA)
                siem.login_success(
                    user_id=user.username,
                    ip=get_client_ip(),
                    user_role='admin' if user.is_admin else 'standard',
                    mfa_used=True
                )

                flash('Login successful!', 'success')

                # Redirect admin to dashboard
                if user.is_admin:
                    return redirect(url_for('main.admin_dashboard'))
                return redirect(url_for('filetransfer.index'))
            else:
                # Log MFA failure to SIEM
                siem.mfa_failed(user_id=user.username, ip=get_client_ip())
                flash('Invalid verification code. Please try again.', 'error')

    return render_template('mfa_verify.html', username=user.username)

@bp.route('/mfa-disable', methods=['POST'])
def mfa_disable():
    """Disable MFA for logged-in users with password confirmation"""
    from flask import jsonify

    # Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Check if user is OAuth user (they don't have password)
    if user.oauth_provider and not user.password_hash:
        # For OAuth users without a password, allow without password
        pass
    else:
        # Get password from request
        password = request.form.get('password') or request.json.get('password', '') if request.is_json else request.form.get('password')

        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400

        # Verify password
        if not user.verify_password(password):
            return jsonify({'success': False, 'message': 'Incorrect password. Please try again.'}), 400

    # Get IP and location for email notification
    ip_address = get_client_ip()
    location = get_location_from_ip(ip_address)

    # Disable MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    db.session.commit()

    # Update session
    session['mfa_enabled'] = False

    # Send security notification email
    send_mfa_disabled_email(user.email, user.username, ip_address, location)

    return jsonify({'success': True, 'message': 'MFA has been disabled'})


@bp.route('/mfa-recover', methods=['GET', 'POST'])
def mfa_recover():
    """Recover MFA using Shamir's Secret Sharing recovery codes"""
    if request.method == 'POST':
        # Collect all non-empty shares
        shares = []
        for i in range(1, 6):
            share = request.form.get(f'share{i}', '').strip()
            if share:
                shares.append(share)

        if len(shares) < 3:
            flash('You need at least 3 recovery codes.', 'error')
            return render_template('mfa_recover.html')

        # Try to reconstruct the secret
        recovered_secret = recover_mfa_secret(shares)

        if not recovered_secret:
            flash('Invalid recovery codes. Please check and try again.', 'error')
            return render_template('mfa_recover.html')

        # Find the user whose MFA secret matches
        # Verify against stored hashed shares
        users = User.query.filter_by(mfa_enabled=True).all()
        target_user = None
        for user in users:
            if user.mfa_secret == recovered_secret:
                target_user = user
                break

        if not target_user:
            flash('Recovery failed. No matching account found.', 'error')
            return render_template('mfa_recover.html')

        # Verify the shares match stored hashes
        if target_user.recovery_shares_hash:
            stored_hashes = json.loads(target_user.recovery_shares_hash)
            valid_shares = sum(1 for s in shares if hash_share(s) in stored_hashes)
            if valid_shares < 3:
                flash('Invalid recovery codes for this account.', 'error')
                return render_template('mfa_recover.html')

        # Recovery successful - log the user in with MFA verified
        init_user_session(target_user)
        session['email'] = target_user.email
        session['picture'] = target_user.profile_picture_url
        session['mfa_enabled'] = True

        # Log to SIEM
        siem.custom_event(
            event_type='mfa_recovery',
            description=f'MFA recovered via Shamir Secret Sharing for user {target_user.username}',
            severity='Warning',
            ip=get_client_ip(),
            user_id=target_user.username
        )

        flash('Account recovered successfully! Please re-setup your authenticator app.', 'success')

        # Redirect to MFA setup so they can re-provision their authenticator
        return redirect(url_for('main.mfa_setup'))

    return render_template('mfa_recover.html')


@bp.route('/regenerate-recovery-codes', methods=['POST'])
def regenerate_recovery_codes():
    """Regenerate Shamir recovery codes (invalidates old ones)"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if not user.mfa_enabled or not user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA is not enabled'}), 400

    # Require password confirmation (skip for OAuth users)
    if not user.oauth_provider:
        password = request.form.get('password')
        if not password or not user.verify_password(password):
            return jsonify({'success': False, 'message': 'Incorrect password'}), 400

    # Generate new shares
    shares, hashed_shares = generate_recovery_shares(user.mfa_secret)
    user.recovery_shares_hash = json.dumps(hashed_shares)
    db.session.commit()

    # Log to SIEM
    siem.custom_event(
        event_type='recovery_codes_regenerated',
        description=f'Recovery codes regenerated for user {user.username}',
        severity='Info',
        ip=get_client_ip(),
        user_id=user.username
    )

    # Return the shares as a rendered page
    return render_template('mfa_recovery_codes.html',
                         shares=shares,
                         redirect_url=url_for('main.settings'))


@bp.route('/send-secondary-verification', methods=['POST'])
def send_secondary_verification():
    """Send verification code to secondary email"""
    from flask import jsonify
    import random

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    secondary_email = request.form.get('email', '').strip()

    if not secondary_email:
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', secondary_email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400

    # Can't use same email as primary
    if secondary_email.lower() == user.email.lower():
        return jsonify({'success': False, 'message': 'Secondary email must be different from your primary email'}), 400

    # Generate 6-digit OTP
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

    # Store in session for verification
    session['secondary_email_pending'] = secondary_email
    session['secondary_email_otp'] = otp
    session['secondary_email_otp_expiry'] = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    # Send OTP email
    try:
        msg = Message(
            'Verify Secondary Email - OpenShare',
            recipients=[secondary_email]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #007aff;">Verify Your Secondary Email</h2>
            <p>Hi,</p>
            <p>You are adding this email as a secondary verification email for the OpenShare account: <strong>{user.username}</strong></p>
            <p>Use the code below to verify:</p>
            <div style="background: #f7fafc; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #007aff;">{otp}</span>
            </div>
            <p>This code expires in <strong>10 minutes</strong>.</p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="color: #718096; font-size: 12px;">If you did not request this, please ignore this email.</p>
        </div>
        '''
        mail.send(msg)
        return jsonify({'success': True, 'message': 'Verification code sent'})
    except Exception as e:
        print(f"Failed to send secondary email verification: {e}")
        return jsonify({'success': False, 'message': 'Failed to send verification email'}), 500


@bp.route('/verify-secondary-email', methods=['POST'])
def verify_secondary_email():
    """Verify secondary email with OTP"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    otp = request.form.get('otp', '').strip()

    if not otp:
        return jsonify({'success': False, 'message': 'Verification code is required'}), 400

    # Check if there's a pending verification
    if 'secondary_email_pending' not in session:
        return jsonify({'success': False, 'message': 'No pending verification. Please enter email first.'}), 400

    # Check OTP expiry
    otp_expiry = datetime.fromisoformat(session.get('secondary_email_otp_expiry', '2000-01-01'))
    if datetime.utcnow() > otp_expiry:
        session.pop('secondary_email_pending', None)
        session.pop('secondary_email_otp', None)
        session.pop('secondary_email_otp_expiry', None)
        return jsonify({'success': False, 'message': 'Verification code expired. Please try again.'}), 400

    # Verify OTP
    if otp != session.get('secondary_email_otp'):
        return jsonify({'success': False, 'message': 'Invalid verification code'}), 400

    # OTP verified - save secondary email
    secondary_email = session['secondary_email_pending']
    user.secondary_email = secondary_email
    user.secondary_email_verified = True
    user.secondary_verification_enabled = True
    db.session.commit()

    # Clear session data
    session.pop('secondary_email_pending', None)
    session.pop('secondary_email_otp', None)
    session.pop('secondary_email_otp_expiry', None)

    # Send confirmation to both emails
    try:
        ip_address = get_client_ip()
        location = get_location_from_ip(ip_address)

        # Notify primary email
        msg = Message(
            'Secondary Email Verified - OpenShare',
            recipients=[user.email]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #007aff;">Secondary Email Added</h2>
            <p>Hi {user.username},</p>
            <p>A secondary verification email has been added to your account:</p>
            <p style="background: #f7fafc; padding: 12px; border-radius: 8px; text-align: center;"><strong>{secondary_email}</strong></p>
            <p>This email will receive alerts for:</p>
            <ul>
                <li>Password changes</li>
                <li>Logins from new devices or locations</li>
                <li>Security setting changes</li>
            </ul>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="color: #718096; font-size: 12px;">This action was performed from IP: {ip_address} ({location})</p>
        </div>
        '''
        mail.send(msg)

        # Notify secondary email
        msg2 = Message(
            'You are now a verification contact - OpenShare',
            recipients=[secondary_email]
        )
        msg2.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #34c759;">Email Verified Successfully</h2>
            <p>Hi,</p>
            <p>Your email has been verified as a secondary contact for the OpenShare account: <strong>{user.username}</strong></p>
            <p>You will receive security alerts when sensitive actions are performed on this account.</p>
        </div>
        '''
        mail.send(msg2)
    except Exception as e:
        print(f"Failed to send confirmation emails: {e}")

    return jsonify({'success': True, 'message': 'Secondary email verified successfully', 'email': secondary_email})


@bp.route('/disable-secondary-verification', methods=['POST'])
def disable_secondary_verification():
    """Disable secondary email verification"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    old_secondary_email = user.secondary_email

    user.secondary_verification_enabled = False
    user.secondary_email = None
    user.secondary_email_verified = False
    db.session.commit()

    # Notify both emails
    try:
        ip_address = get_client_ip()
        location = get_location_from_ip(ip_address)

        msg = Message(
            'Secondary Verification Disabled - OpenShare',
            recipients=[user.email]
        )
        msg.html = f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #ff9500;">Security Setting Updated</h2>
            <p>Hi {user.username},</p>
            <p>Secondary email verification has been <strong>disabled</strong> for your account.</p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
            <p style="color: #718096; font-size: 12px;">This action was performed from IP: {ip_address} ({location})</p>
        </div>
        '''
        mail.send(msg)

        if old_secondary_email:
            msg2 = Message(
                'Removed as verification contact - OpenShare',
                recipients=[old_secondary_email]
            )
            msg2.html = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #ff9500;">Verification Contact Removed</h2>
                <p>Hi,</p>
                <p>You have been removed as a secondary verification contact for the OpenShare account: <strong>{user.username}</strong></p>
                <p>You will no longer receive security alerts for this account.</p>
            </div>
            '''
            mail.send(msg2)
    except Exception as e:
        print(f"Failed to send notification emails: {e}")

    return jsonify({'success': True, 'message': 'Secondary verification disabled'})


@bp.route('/admin/devices', methods=['GET'])
def admin_devices():
    """Admin device management page"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    # Get whitelisted devices and IPs
    devices = json.loads(user.whitelisted_devices or '[]')
    ips = json.loads(user.whitelisted_ips or '[]')

    # Get current device and IP
    current_device = get_device_fingerprint()
    current_ip = get_client_ip()

    return render_template('admin_devices.html',
                         devices=devices,
                         ips=ips,
                         current_device=current_device,
                         current_ip=current_ip,
                         user=user)

@bp.route('/admin/register-device', methods=['POST'])
def register_admin_device():
    """Register a new trusted device for admin"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    # Require MFA to register new device
    mfa_code = request.form.get('mfa_code')

    if not user.mfa_secret:
        flash('Please enable MFA first before registering devices', 'error')
        return redirect(url_for('main.admin_devices'))

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_code, valid_window=1):
        flash('Invalid MFA code. Please try again.', 'error')
        return redirect(url_for('main.admin_devices'))

    # Get current device and IP
    device_id = get_device_fingerprint()
    current_ip = get_client_ip()

    # Add device to whitelist
    devices = json.loads(user.whitelisted_devices or '[]')
    if device_id not in devices:
        devices.append(device_id)
        user.whitelisted_devices = json.dumps(devices)

    # Add IP to whitelist
    ips = json.loads(user.whitelisted_ips or '[]')
    if current_ip not in ips:
        ips.append(current_ip)
        user.whitelisted_ips = json.dumps(ips)

    db.session.commit()

    flash('Device and IP registered successfully!', 'success')
    return redirect(url_for('main.admin_devices'))

@bp.route('/admin/remove-device', methods=['POST'])
def remove_admin_device():
    """Remove a device from whitelist"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    device_id = request.form.get('device_id')

    if device_id:
        devices = json.loads(user.whitelisted_devices or '[]')
        if device_id in devices:
            devices.remove(device_id)
            user.whitelisted_devices = json.dumps(devices)
            db.session.commit()
            flash('Device removed successfully', 'success')

    return redirect(url_for('main.admin_devices'))

@bp.route('/admin/remove-ip', methods=['POST'])
def remove_admin_ip():
    """Remove an IP from whitelist"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    ip_address = request.form.get('ip_address')

    if ip_address:
        ips = json.loads(user.whitelisted_ips or '[]')
        if ip_address in ips:
            ips.remove(ip_address)
            user.whitelisted_ips = json.dumps(ips)
            db.session.commit()
            flash('IP address removed successfully', 'success')

    return redirect(url_for('main.admin_devices'))


@bp.route('/admin/add-device', methods=['POST'])
def add_admin_device():
    """Manually add a device to whitelist"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    device_hash = request.form.get('device_hash', '').strip()

    if device_hash:
        devices = json.loads(user.whitelisted_devices or '[]')
        if device_hash not in devices:
            devices.append(device_hash)
            user.whitelisted_devices = json.dumps(devices)
            db.session.commit()
            flash('Device added successfully', 'success')
        else:
            flash('Device already in whitelist', 'info')

    return redirect(url_for('main.admin_devices'))


@bp.route('/admin/add-ip', methods=['POST'])
def add_admin_ip():
    """Manually add an IP to whitelist"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return "Access denied. Admin only.", 403

    ip_address = request.form.get('ip_address', '').strip()

    if ip_address:
        ips = json.loads(user.whitelisted_ips or '[]')
        if ip_address not in ips:
            ips.append(ip_address)
            user.whitelisted_ips = json.dumps(ips)
            db.session.commit()
            flash('IP address added successfully', 'success')
        else:
            flash('IP address already in whitelist', 'info')

    return redirect(url_for('main.admin_devices'))


# ==================== ADMIN DASHBOARD & MAC VERIFICATION ====================

def get_client_mac_address():
    """
    Attempt to get client MAC address from ARP table.
    This only works if client is on the same network segment.
    Returns None if unable to detect.
    """
    import subprocess
    import platform

    client_ip = get_client_ip()

    # Skip for localhost
    if client_ip in ['127.0.0.1', 'localhost', '::1']:
        return None

    try:
        system = platform.system().lower()

        if system == 'windows':
            # Windows: use arp -a command
            result = subprocess.run(['arp', '-a', client_ip], capture_output=True, text=True, timeout=5)
            output = result.stdout

            # Parse Windows ARP output (format: IP addr    MAC addr    Type)
            for line in output.split('\n'):
                if client_ip in line:
                    parts = line.split()
                    for part in parts:
                        # MAC address pattern: xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx
                        if len(part) == 17 and (part.count('-') == 5 or part.count(':') == 5):
                            # Normalize to uppercase with colons
                            return part.upper().replace('-', ':')

        elif system in ['linux', 'darwin']:
            # Linux/Mac: use arp command
            result = subprocess.run(['arp', '-n', client_ip], capture_output=True, text=True, timeout=5)
            output = result.stdout

            for line in output.split('\n'):
                if client_ip in line:
                    parts = line.split()
                    for part in parts:
                        if len(part) == 17 and part.count(':') == 5:
                            return part.upper()

    except Exception as e:
        print(f"Error getting MAC address: {e}")

    return None


@bp.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard showing list of all users"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Get all users
    all_users = User.query.all()

    return render_template('admin_dashboard.html', users=all_users, current_user=user)


@bp.route('/admin/risk-scoring')
def admin_risk_scoring():
    """Admin page showing user risk scores from ML analysis"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Get all users with their latest login history and risk scores
    users_with_risk = []
    all_users = User.query.all()

    for u in all_users:
        # Get the user's most recent login history entry
        latest_login = LoginHistory.query.filter_by(user_id=u.id).order_by(LoginHistory.timestamp.desc()).first()

        user_data = {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'risk_score': latest_login.risk_score if latest_login else 0,
            'risk_level': latest_login.risk_level if latest_login else 'low',
            'risk_factors': json.loads(latest_login.risk_factors) if latest_login and latest_login.risk_factors else [],
            'last_login': latest_login.timestamp if latest_login else None,
            'ip_address': latest_login.ip_address if latest_login else None,
            'location': latest_login.location if latest_login else None,
            'account_locked': u.account_locked
        }
        users_with_risk.append(user_data)

    # Sort by risk score (highest first)
    users_with_risk.sort(key=lambda x: x['risk_score'], reverse=True)

    return render_template('admin_risk_scoring.html', users=users_with_risk, current_user=user)


@bp.route('/admin/keystroke-scoring')
def admin_keystroke_scoring():
    """Admin page showing keystroke dynamics learning status per user"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    users_keystroke = []
    all_users = User.query.all()

    for u in all_users:
        profile = None
        if u.keystroke_profile:
            try:
                profile = json.loads(u.keystroke_profile)
            except (json.JSONDecodeError, TypeError):
                profile = None

        samples = profile.get('samples', 0) if profile else 0
        history_count = len(profile.get('history', [])) if profile else 0

        if samples == 0:
            status = 'No Data'
            status_class = 'none'
        elif samples < 3:
            status = f'Collecting ({samples}/3)'
            status_class = 'collecting'
        elif samples < 5:
            status = f'Statistical ({samples}/5)'
            status_class = 'statistical'
        else:
            status = f'Autoencoder Active'
            status_class = 'autoencoder'

        user_data = {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'samples': samples,
            'history_count': history_count,
            'status': status,
            'status_class': status_class,
            'hold_mean': round(profile.get('hold_mean', 0), 1) if profile else 0,
            'flight_mean': round(profile.get('flight_mean', 0), 1) if profile else 0,
            'digraph_mean': round(profile.get('digraph_mean', 0), 1) if profile else 0,
        }
        users_keystroke.append(user_data)

    users_keystroke.sort(key=lambda x: x['samples'], reverse=True)

    return render_template('admin_keystroke_scoring.html', users=users_keystroke, current_user=user)


@bp.route('/admin/chat-scoring')
def admin_chat_scoring():
    """Admin page showing per-user chat behavior scores and toxicity analysis"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Get all users who have chat history
    all_users = User.query.all()
    user_scores = []

    for u in all_users:
        chat_records = ChatHistory.query.filter_by(user_id=u.id).all()
        if not chat_records:
            continue

        behavior = get_user_behavior_score(chat_records)

        # Get recent flagged messages (last 5)
        recent_flagged = ChatHistory.query.filter(
            ChatHistory.user_id == u.id,
            ChatHistory.toxicity_score >= 0.5
        ).order_by(ChatHistory.timestamp.desc()).limit(5).all()

        # Convert timestamps to SGT
        sgt_offset = timedelta(hours=8)
        for msg in recent_flagged:
            if msg.timestamp:
                msg.sgt_timestamp = (msg.timestamp + sgt_offset).strftime('%Y-%m-%d %H:%M:%S')
            else:
                msg.sgt_timestamp = 'N/A'

        user_scores.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'behavior_score': behavior['behavior_score'],
            'total_messages': behavior['total_messages'],
            'flagged_count': behavior['flagged_count'],
            'vulgar_count': behavior['vulgar_count'],
            'avg_toxicity': behavior['avg_toxicity'],
            'warnings_issued': behavior['warnings_issued'],
            'risk_level': behavior['risk_level'],
            'recent_flagged': recent_flagged
        })

    # Sort by behavior score ascending (worst first)
    user_scores.sort(key=lambda x: x['behavior_score'])

    # Overall stats
    total_chats = ChatHistory.query.count()
    total_flagged = ChatHistory.query.filter(ChatHistory.toxicity_score >= 0.5).count()
    total_warnings = ChatHistory.query.filter_by(warning_issued=True).count()
    users_with_issues = sum(1 for u in user_scores if u['risk_level'] in ('warning', 'critical'))

    return render_template('admin_chat_scoring.html',
                           user_scores=user_scores,
                           total_chats=total_chats,
                           total_flagged=total_flagged,
                           total_warnings=total_warnings,
                           users_with_issues=users_with_issues,
                           current_user=user)


@bp.route('/admin/toggle-admin/<int:user_id>', methods=['POST'])
def toggle_admin(user_id):
    """Toggle admin status for a user - requires TOTP verification"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    current_user = User.query.get(session['user_id'])

    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Verify TOTP code
    totp_code = request.form.get('totp_code')
    if not totp_code:
        return jsonify({'success': False, 'message': 'TOTP code is required'}), 400

    if not current_user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA not configured'}), 400

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400

    # Can't modify super admin status
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if target_user.is_super_admin:
        return jsonify({'success': False, 'message': 'Cannot modify super admin status'}), 403

    # Can't remove own admin status
    if target_user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot modify your own admin status'}), 403

    # Toggle admin status
    target_user.is_admin = not target_user.is_admin

    # Reset MAC verification when demoting from admin
    if not target_user.is_admin:
        target_user.mac_address_registered = False
        target_user.registered_mac_address = None

    db.session.commit()

    status = 'promoted to admin' if target_user.is_admin else 'demoted from admin'

    # Log to SIEM
    siem.permission_changed(
        admin_id=current_user.username,
        target_user=target_user.username,
        ip=get_client_ip(),
        old_role='admin' if not target_user.is_admin else 'standard',
        new_role='admin' if target_user.is_admin else 'standard'
    )

    return jsonify({'success': True, 'message': f'{target_user.username} has been {status}'})


@bp.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Delete a user - requires TOTP verification"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    current_user = User.query.get(session['user_id'])

    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Verify TOTP code
    totp_code = request.form.get('totp_code')
    if not totp_code:
        return jsonify({'success': False, 'message': 'TOTP code is required'}), 400

    if not current_user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA not configured'}), 400

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400

    # Get target user
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Can't delete super admin
    if target_user.is_super_admin:
        return jsonify({'success': False, 'message': 'Cannot delete super admin'}), 403

    # Can't delete yourself
    if target_user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 403

    # Store username and email for logging before deletion
    deleted_username = target_user.username
    deleted_email = target_user.email

    # Log to SIEM before deletion
    siem.user_deleted(
        admin_id=current_user.username,
        deleted_user_id=deleted_username,
        ip=get_client_ip()
    )

    # Delete related records first (foreign key constraints)
    LoginHistory.query.filter_by(user_id=target_user.id).delete()
    ChatHistory.query.filter_by(user_id=target_user.id).delete()

    # Delete the user
    db.session.delete(target_user)
    db.session.commit()

    return jsonify({'success': True, 'message': f'{deleted_username} has been deleted'})


@bp.route('/admin/lock-user/<int:user_id>', methods=['POST'])
def lock_user(user_id):
    """Lock a user account - requires TOTP verification"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    current_user = User.query.get(session['user_id'])

    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Verify TOTP code
    totp_code = request.form.get('totp_code')
    if not totp_code:
        return jsonify({'success': False, 'message': 'TOTP code is required'}), 400

    if not current_user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA not configured'}), 400

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400

    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if target_user.is_super_admin:
        return jsonify({'success': False, 'message': 'Cannot lock super admin'}), 403

    if target_user.id == current_user.id:
        return jsonify({'success': False, 'message': 'Cannot lock your own account'}), 403

    # Lock the account
    target_user.account_locked = True
    target_user.locked_until = None  # Permanent lock until admin unlocks
    db.session.commit()

    # Log to SIEM
    siem.custom_event(
        event_type='account_locked_by_admin',
        description=f'Account {target_user.username} locked by admin {current_user.username}',
        severity='High',
        user_id=target_user.username,
        ip=get_client_ip(),
        locked_by=current_user.username
    )

    return jsonify({'success': True, 'message': f'{target_user.username} has been locked'})


@bp.route('/admin/unlock-user/<int:user_id>', methods=['POST'])
def unlock_user(user_id):
    """Unlock a user account - requires TOTP verification"""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    current_user = User.query.get(session['user_id'])

    if not current_user or not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Verify TOTP code
    totp_code = request.form.get('totp_code')
    if not totp_code:
        return jsonify({'success': False, 'message': 'TOTP code is required'}), 400

    if not current_user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA not configured'}), 400

    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400

    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Unlock the account
    target_user.account_locked = False
    target_user.locked_until = None
    target_user.failed_login_attempts = 0
    db.session.commit()

    # Log to SIEM
    siem.custom_event(
        event_type='account_unlocked_by_admin',
        description=f'Account {target_user.username} unlocked by admin {current_user.username}',
        severity='Info',
        user_id=target_user.username,
        ip=get_client_ip(),
        unlocked_by=current_user.username
    )

    return jsonify({'success': True, 'message': f'{target_user.username} has been unlocked'})


@bp.route('/admin/settings')
def admin_settings():
    """Admin settings page for MAC address registration"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Try to detect MAC address
    detected_mac = get_client_mac_address()

    return render_template('admin_settings.html',
                         user=user,
                         detected_mac=detected_mac)


@bp.route('/admin/register-mac', methods=['POST'])
def register_mac():
    """Register MAC address for admin verification"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Super admin doesn't need MAC registration
    if user.is_super_admin:
        flash('Super admin does not require MAC address registration.', 'info')
        return redirect(url_for('main.admin_settings'))

    mac_address = request.form.get('mac_address', '').strip().upper()

    # Validate MAC address format (XX:XX:XX:XX:XX:XX)
    mac_pattern = re.compile(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$')
    if not mac_pattern.match(mac_address):
        flash('Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX format.', 'error')
        return redirect(url_for('main.admin_settings'))

    # Require MFA verification
    mfa_code = request.form.get('mfa_code')
    if user.mfa_enabled and user.mfa_secret:
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            flash('Invalid MFA code. Please try again.', 'error')
            return redirect(url_for('main.admin_settings'))

    # Register the MAC address
    user.registered_mac_address = mac_address
    user.mac_address_registered = True
    db.session.commit()

    flash('MAC address registered successfully. Next login will require MAC verification.', 'success')
    return redirect(url_for('main.admin_settings'))


@bp.route('/admin/mac-verify', methods=['GET', 'POST'])
def admin_mac_verify():
    """MAC address verification page during admin login"""
    if 'mac_verify_user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('main.login'))

    user = User.query.get(session['mac_verify_user_id'])

    if not user:
        session.pop('mac_verify_user_id', None)
        flash('User not found.', 'error')
        return redirect(url_for('main.login'))

    # Try to detect MAC address
    detected_mac = get_client_mac_address()

    if request.method == 'POST':
        # Check if auto-detect button was clicked
        if 'auto_detect' in request.form:
            if detected_mac:
                if detected_mac == user.registered_mac_address:
                    # MAC matches, complete login
                    init_user_session(user)
                    session['email'] = user.email
                    session.pop('mac_verify_user_id', None)
                    flash('Login successful! MAC address verified.', 'success')
                    return redirect(url_for('main.admin_dashboard'))
                else:
                    flash(f'MAC address mismatch. Detected: {detected_mac}, Expected: {user.registered_mac_address}', 'error')
            else:
                flash('Unable to detect MAC address. Please enter manually or ensure you are on the same network.', 'error')
        else:
            # Manual MAC entry
            entered_mac = request.form.get('mac_address', '').strip().upper()

            if entered_mac == user.registered_mac_address:
                # MAC matches, complete login
                init_user_session(user)
                session['email'] = user.email
                session.pop('mac_verify_user_id', None)
                flash('Login successful! MAC address verified.', 'success')
                return redirect(url_for('main.admin_dashboard'))
            else:
                flash('MAC address does not match. Access denied.', 'error')

    return render_template('admin_mac_verify.html',
                         user=user,
                         detected_mac=detected_mac)


# ============================================
# File Transfer Admin Routes
# ============================================

@bp.route('/admin/filetransfer')
def admin_filetransfer():
    """Admin File Transfer settings - retention policy configuration"""
    from flask import jsonify
    import sys


    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    # Get current retention policy
    policy = get_retention_policy()
    policy_data = policy.get_policy()
    policy_summary = policy.get_policy_summary()

    return render_template('admin_filetransfer.html',
                         current_user=user,
                         policy=policy_data,
                         summary=policy_summary)


@bp.route('/admin/filetransfer/retention', methods=['POST'])
def admin_update_retention():
    """Update retention policy settings - requires TOTP verification"""
    from flask import jsonify
    import sys
    

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    # Verify TOTP code
    totp_code = request.form.get('totp_code')
    if not totp_code:
        return jsonify({'success': False, 'message': 'TOTP code is required'}), 400

    if not user.mfa_secret:
        return jsonify({'success': False, 'message': 'MFA not configured'}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400

    # Get the policy manager
    policy = get_retention_policy()
    updated_by = f"admin:{user.username}"
    errors = []

    # Update file retention settings
    for storage_type in ['working_db', 'storage_db', 'filesystem']:
        retention_key = f'retention_{storage_type}'
        enabled_key = f'enabled_{storage_type}'

        if retention_key in request.form:
            try:
                retention_minutes = int(request.form.get(retention_key, 0))
                enabled = request.form.get(enabled_key) == 'on'
                retention_seconds = retention_minutes * 60

                if not policy.set_file_retention(storage_type, retention_seconds, enabled, updated_by):
                    errors.append(f'Failed to update {storage_type}')
            except ValueError:
                errors.append(f'Invalid value for {storage_type}')

    # Update log retention settings
    for log_type in ['access_logs', 'failed_upload_logs', 'virus_scan_logs', 'approval_requests']:
        retention_key = f'retention_{log_type}'
        enabled_key = f'enabled_{log_type}'

        if retention_key in request.form:
            try:
                retention_minutes = int(request.form.get(retention_key, 0))
                enabled = request.form.get(enabled_key) == 'on'
                retention_seconds = retention_minutes * 60

                if not policy.set_log_retention(log_type, retention_seconds, enabled, updated_by):
                    errors.append(f'Failed to update {log_type}')
            except ValueError:
                errors.append(f'Invalid value for {log_type}')

    # Update cleanup interval
    if 'cleanup_interval' in request.form:
        try:
            interval_minutes = int(request.form.get('cleanup_interval', 60))
            if interval_minutes < 1:
                interval_minutes = 1
            if not policy.set_cleanup_interval(interval_minutes * 60, updated_by):
                errors.append('Failed to update cleanup interval')
        except ValueError:
            errors.append('Invalid cleanup interval')

    # Update dry run mode
    dry_run = request.form.get('dry_run') == 'on'
    policy.set_dry_run(dry_run, updated_by)

    if errors:
        return jsonify({'success': False, 'message': ', '.join(errors)}), 400

    # Log the action
    siem.permission_changed(
        user_id=user.id,
        username=user.username,
        permission_type='retention_policy',
        old_value='updated',
        new_value='retention policy modified',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', 'Unknown')
    )

    return jsonify({'success': True, 'message': 'Retention policy updated successfully'})


@bp.route('/admin/filetransfer/search', methods=['GET'])
def admin_search_files():
    """Search for files in the metadata table"""
    from flask import jsonify
    import sys
    

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')  # all, filename, file_id, hash

    try:
        db = Database()
        db.ensure_connection()
        cursor = db.connection.cursor(dictionary=True, buffered=True)

        # Build search query based on type
        if search_type == 'file_id' and query:
            cursor.execute("""
                SELECT fm.file_id, fm.original_filename, fm.stored_filename, fm.file_size,
                       fm.file_hash, fm.upload_time, fm.download_count, fm.classification,
                       fm.detected_mime, fm.scan_status, fm.is_archived, fm.uploaded_by,
                       fm.upload_ip, fml.trust_score, fml.risk_level
                FROM file_metadata fm
                LEFT JOIN file_ml_analysis fml ON fm.file_id = fml.file_id
                WHERE fm.file_id = %s
            """, (query,))
        elif search_type == 'filename' and query:
            cursor.execute("""
                SELECT fm.file_id, fm.original_filename, fm.stored_filename, fm.file_size,
                       fm.file_hash, fm.upload_time, fm.download_count, fm.classification,
                       fm.detected_mime, fm.scan_status, fm.is_archived, fm.uploaded_by,
                       fm.upload_ip, fml.trust_score, fml.risk_level
                FROM file_metadata fm
                LEFT JOIN file_ml_analysis fml ON fm.file_id = fml.file_id
                WHERE fm.original_filename LIKE %s
                ORDER BY fm.upload_time DESC
                LIMIT 50
            """, (f'%{query}%',))
        elif search_type == 'hash' and query:
            cursor.execute("""
                SELECT fm.file_id, fm.original_filename, fm.stored_filename, fm.file_size,
                       fm.file_hash, fm.upload_time, fm.download_count, fm.classification,
                       fm.detected_mime, fm.scan_status, fm.is_archived, fm.uploaded_by,
                       fm.upload_ip, fml.trust_score, fml.risk_level
                FROM file_metadata fm
                LEFT JOIN file_ml_analysis fml ON fm.file_id = fml.file_id
                WHERE fm.file_hash LIKE %s
                ORDER BY fm.upload_time DESC
                LIMIT 50
            """, (f'%{query}%',))
        else:
            # Search all fields or get recent files
            if query:
                cursor.execute("""
                    SELECT fm.file_id, fm.original_filename, fm.stored_filename, fm.file_size,
                           fm.file_hash, fm.upload_time, fm.download_count, fm.classification,
                           fm.detected_mime, fm.scan_status, fm.is_archived, fm.uploaded_by,
                           fm.upload_ip, fml.trust_score, fml.risk_level
                    FROM file_metadata fm
                    LEFT JOIN file_ml_analysis fml ON fm.file_id = fml.file_id
                    WHERE fm.file_id LIKE %s
                       OR fm.original_filename LIKE %s
                       OR fm.file_hash LIKE %s
                    ORDER BY fm.upload_time DESC
                    LIMIT 50
                """, (f'%{query}%', f'%{query}%', f'%{query}%'))
            else:
                # Return recent files if no query
                cursor.execute("""
                    SELECT fm.file_id, fm.original_filename, fm.stored_filename, fm.file_size,
                           fm.file_hash, fm.upload_time, fm.download_count, fm.classification,
                           fm.detected_mime, fm.scan_status, fm.is_archived, fm.uploaded_by,
                           fm.upload_ip, fml.trust_score, fml.risk_level
                    FROM file_metadata fm
                    LEFT JOIN file_ml_analysis fml ON fm.file_id = fml.file_id
                    ORDER BY fm.upload_time DESC
                    LIMIT 20
                """)

        files = cursor.fetchall()
        cursor.close()

        # Format the results
        results = []
        for f in files:
            results.append({
                'file_id': f['file_id'],
                'original_filename': f['original_filename'],
                'stored_filename': f['stored_filename'],
                'file_size': f['file_size'],
                'file_hash': f['file_hash'],
                'upload_time': f['upload_time'].isoformat() if f['upload_time'] else None,
                'download_count': f['download_count'],
                'classification': f['classification'],
                'detected_mime': f['detected_mime'],
                'scan_status': f['scan_status'],
                'is_archived': bool(f['is_archived']),
                'uploaded_by': f['uploaded_by'],
                'upload_ip': f['upload_ip'],
                'trust_score': f.get('trust_score'),
                'risk_level': f.get('risk_level'),
            })

        return jsonify({'success': True, 'files': results, 'count': len(results)})

    except Exception as e:
        print(f"[Admin] Error searching files: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/admin/filetransfer/ml-analysis/<file_id>', methods=['GET'])
def admin_get_ml_analysis(file_id):
    """Return ML trust-score analysis for a specific file."""
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        db = Database()
        analysis = db.get_ml_analysis(file_id)
        if analysis is None:
            return jsonify({'success': True, 'analysis': None,
                            'message': 'No ML analysis available for this file'})
        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/admin/filetransfer/ml-scores', methods=['GET'])
def admin_ml_scores():
    """
    Return all ML trust-score analyses joined with file metadata.
    Optional query params:
      ?risk_level=high_risk|suspicious|caution|trustworthy
      ?sort=trust_score|analyzed_at|original_filename  (default: analyzed_at)
      ?order=asc|desc  (default: desc)
      ?limit=N  (default: 100)
    """
    from flask import jsonify

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    risk_filter = request.args.get('risk_level', '').strip()
    sort_col    = request.args.get('sort', 'analyzed_at')
    order       = request.args.get('order', 'desc').upper()
    try:
        limit = min(int(request.args.get('limit', 200)), 500)
    except ValueError:
        limit = 200

    allowed_sorts = {'trust_score', 'analyzed_at', 'original_filename', 'risk_level'}
    if sort_col not in allowed_sorts:
        sort_col = 'analyzed_at'
    if order not in ('ASC', 'DESC'):
        order = 'DESC'

    try:
        db = Database()
        db.ensure_connection()
        cursor = db.connection.cursor(dictionary=True, buffered=True)

        where = "WHERE fml.file_id IS NOT NULL"
        params = []
        if risk_filter in ('high_risk', 'suspicious', 'caution', 'trustworthy'):
            where += " AND fml.risk_level = %s"
            params.append(risk_filter)

        sort_expr = {
            'trust_score':        'fml.trust_score',
            'analyzed_at':        'fml.analyzed_at',
            'original_filename':  'fm.original_filename',
            'risk_level':         'fml.risk_level',
        }[sort_col]

        cursor.execute(f"""
            SELECT fml.file_id, fml.trust_score, fml.risk_level,
                   fml.risk_signals, fml.anomaly_score, fml.analyzed_at,
                   fml.model_version,
                   fm.original_filename, fm.file_size, fm.upload_time,
                   fm.classification, fm.scan_status, fm.uploaded_by
            FROM file_ml_analysis fml
            JOIN file_metadata fm ON fml.file_id = fm.file_id
            {where}
            ORDER BY {sort_expr} {order}
            LIMIT %s
        """, params + [limit])

        rows = cursor.fetchall()
        cursor.close()

        import json as _json
        results = []
        for r in rows:
            try:
                signals = _json.loads(r['risk_signals']) if r['risk_signals'] else []
            except Exception:
                signals = []
            results.append({
                'file_id':           r['file_id'],
                'trust_score':       r['trust_score'],
                'risk_level':        r['risk_level'],
                'risk_signals':      signals,
                'signal_count':      len(signals),
                'anomaly_score':     r['anomaly_score'],
                'analyzed_at':       r['analyzed_at'].isoformat() if r['analyzed_at'] else None,
                'model_version':     r['model_version'],
                'original_filename': r['original_filename'],
                'file_size':         r['file_size'],
                'upload_time':       r['upload_time'].isoformat() if r['upload_time'] else None,
                'classification':    r['classification'],
                'scan_status':       r['scan_status'],
                'uploaded_by':       r['uploaded_by'],
            })

        # Compute summary stats
        db.ensure_connection()
        cursor2 = db.connection.cursor(dictionary=True, buffered=True)
        cursor2.execute("""
            SELECT risk_level, COUNT(*) as cnt,
                   AVG(trust_score) as avg_score,
                   MIN(trust_score) as min_score,
                   MAX(trust_score) as max_score
            FROM file_ml_analysis
            GROUP BY risk_level
        """)
        stats_rows = cursor2.fetchall()
        cursor2.close()

        stats = {}
        total = 0
        for s in stats_rows:
            stats[s['risk_level']] = {
                'count':     s['cnt'],
                'avg_score': round(float(s['avg_score']), 1) if s['avg_score'] else 0,
                'min_score': s['min_score'],
                'max_score': s['max_score'],
            }
            total += s['cnt']

        return jsonify({
            'success': True,
            'files': results,
            'count': len(results),
            'total_analyzed': total,
            'stats': stats,
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/admin/filetransfer/forensic-check', methods=['POST'])
def admin_forensic_check():
    """
    Forensic watermark check: accept a file upload, hash it, look up the
    watermark that matches, decrypt it, and return the downloader identity.
    """
    from flask import jsonify
    import hashlib as _hashlib

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'success': False, 'message': 'No file provided'}), 400

    try:
        file_bytes = uploaded.read()
        file_hash = _hashlib.sha256(file_bytes).hexdigest()

        db = Database()

        # Primary lookup: watermarked hash (each download produces a unique hash)
        wm_row = db.get_watermark_by_watermarked_hash(file_hash)
        match_type = 'hash_lookup'

        # Fallback: scan for embedded watermark marker in the file bytes
        if wm_row is None:
            sys.path.insert(0, os.path.join(BASE_DIR, 'FileTransfer'))
            from watermark import extract_watermark_from_file, decrypt_watermark as _dec_wm
            embedded_blob = extract_watermark_from_file(file_bytes)
            if embedded_blob:
                decrypted = _dec_wm(embedded_blob)
                if decrypted:
                    match_type = 'embedded_marker'
                    # Reconstruct a wm_row-like dict from the decrypted payload
                    wm_row = {
                        'watermark_id': decrypted.get('watermark_id', ''),
                        'file_id': decrypted.get('file_id', ''),
                        'original_file_hash': decrypted.get('file_hash_sha256', ''),
                        'watermarked_hash': file_hash,
                        'download_timestamp': decrypted.get('created_at'),
                        'encrypted_payload': None,
                        '_decrypted': decrypted,
                    }

        if wm_row is None:
            # No watermark found — check if the hash matches an original unmodified file
            file_info = db.lookup_file_by_hash(file_hash)
            return jsonify({
                'found': False,
                'file_hash': file_hash,
                'file_info': file_info,
            })

        # Decrypt the payload (if not already done via embedded fallback)
        if '_decrypted' in wm_row:
            decrypted = wm_row['_decrypted']
        else:
            sys.path.insert(0, os.path.join(BASE_DIR, 'FileTransfer'))
            from watermark import decrypt_watermark as _dec_wm
            decrypted = _dec_wm(wm_row['encrypted_payload'])

        # Fetch the original file metadata
        file_info = db.lookup_file_by_hash(wm_row.get('original_file_hash', ''))
        if file_info is None and wm_row.get('file_id'):
            # Fallback: search by file_id if hash lookup fails
            db.ensure_connection()
            cursor = db.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(
                "SELECT file_id, original_filename, file_size, file_hash, "
                "upload_time, classification, scan_status, is_archived, "
                "uploaded_by, download_count FROM file_metadata WHERE file_id = %s",
                (wm_row['file_id'],)
            )
            row = cursor.fetchone()
            cursor.close()
            if row:
                file_info = {
                    'file_id': row['file_id'],
                    'original_filename': row['original_filename'],
                    'file_size': row['file_size'],
                    'file_hash': row['file_hash'],
                    'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                    'classification': row['classification'],
                    'scan_status': row['scan_status'],
                    'is_archived': bool(row.get('is_archived', False)),
                    'uploaded_by': row['uploaded_by'],
                    'download_count': row['download_count'],
                }

        return jsonify({
            'found': True,
            'file_hash': file_hash,
            'match_type': match_type,
            'file_info': file_info,
            'watermark': {
                'watermark_id': wm_row.get('watermark_id'),
                'file_id': wm_row.get('file_id'),
                'download_timestamp': wm_row.get('download_timestamp'),
                'decrypted': decrypted,
            },
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/admin/filetransfer/file/<file_id>/logs', methods=['GET'])
def admin_get_file_logs(file_id):
    """Get access logs for a specific file"""
    from flask import jsonify
    import sys
    

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        db = Database()
        db.ensure_connection()
        cursor = db.connection.cursor(dictionary=True, buffered=True)

        cursor.execute("""
            SELECT id, file_id, timestamp, status, details, ip_address
            FROM access_logs
            WHERE file_id = %s
            ORDER BY timestamp DESC
            LIMIT 100
        """, (file_id,))

        logs = cursor.fetchall()
        cursor.close()

        # Format the results
        results = []
        for log in logs:
            results.append({
                'id': log['id'],
                'file_id': log['file_id'],
                'timestamp': log['timestamp'].isoformat() if log['timestamp'] else None,
                'status': log['status'],
                'details': log['details'],
                'ip_address': log['ip_address']
            })

        return jsonify({'success': True, 'logs': results, 'count': len(results)})

    except Exception as e:
        print(f"[Admin] Error getting file logs: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@bp.route('/chatbot')
def chatbot_page():
    """Render the OpenShare Assistant interface"""
    if 'user_id' not in session:
        flash('Please login to access the assistant', 'error')
        return redirect(url_for('main.login'))
    
    user = User.query.get(session['user_id'])
    return render_template('filetransfer/chatbot.html', user=user)

@bp.route('/chat', methods=['POST'])
@limiter.limit("5 per minute")
def chat():
    """Handle AI communication and secure logging for OpenShare"""
    user_data = request.get_json()
    raw_message = user_data.get('message', '')
    sanitized_message = html.escape(raw_message.strip())

    if not sanitized_message:
        return jsonify({'reply': 'Please enter a message.'})

    # Length limit - max 500 characters
    if len(sanitized_message) > 500:
        return jsonify({'reply': 'Message too long. Please keep your message under 500 characters.'})

    client_ip = get_client_ip()
    user_id = session.get('user_id')
    username = session.get('user', 'unknown')

    # --- Sensitive content filtering ---
    flagged = False
    flag_reasons = []
    prompt_message = sanitized_message  # message sent to AI (may be redacted)

    # Credit card pattern: 4 groups of 4 digits separated by spaces or dashes
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    if re.search(cc_pattern, sanitized_message):
        flagged = True
        flag_reasons.append('credit_card')
        prompt_message = re.sub(cc_pattern, '[REDACTED-CC]', prompt_message)

    # Singapore NRIC pattern
    nric_pattern = r'\b[STFGMstfgm]\d{7}[A-Za-z]\b'
    if re.search(nric_pattern, sanitized_message):
        flagged = True
        flag_reasons.append('nric')
        prompt_message = re.sub(nric_pattern, '[REDACTED-NRIC]', prompt_message)

    # --- Vulgarity/Toxicity + Sensitive Info scoring ---
    toxicity_result = score_message(sanitized_message)
    toxicity_score = toxicity_result['score']
    should_warn = toxicity_result['should_warn']
    detected_categories = toxicity_result.get('categories', [])

    # Flag vulgar content
    if toxicity_result['flagged_words']:
        flagged = True
        if toxicity_result['severity'] in ('moderate', 'severe'):
            flag_reasons.append(f"vulgarity_{toxicity_result['severity']}")

        siem.custom_event(
            event_type='chatbot_vulgarity_detected',
            description=f"User {username} used vulgar language (score: {toxicity_score}, severity: {toxicity_result['severity']})",
            severity='Warning' if toxicity_result['severity'] == 'moderate' else ('High' if toxicity_result['severity'] == 'severe' else 'Info'),
            user_id=username,
            ip=client_ip
        )

    # Flag sensitive information (credentials, identity, financial, system, attacks)
    if toxicity_result.get('sensitive_matches'):
        flagged = True
        for match in toxicity_result['sensitive_matches']:
            flag_reasons.append(f"{match['category']}:{match['type']}")

        sensitive_labels = [m['label'] for m in toxicity_result['sensitive_matches']]
        sensitive_cats = set(m['category'] for m in toxicity_result['sensitive_matches'])

        siem_severity = 'Info'
        if sensitive_cats & {'credentials', 'attack'}:
            siem_severity = 'High'
        elif sensitive_cats & {'identity', 'financial'}:
            siem_severity = 'Warning'

        siem.custom_event(
            event_type='chatbot_sensitive_info_detected',
            description=f"User {username} shared sensitive info: {', '.join(sensitive_labels)} (score: {toxicity_score})",
            severity=siem_severity,
            user_id=username,
            ip=client_ip
        )

    flag_reason_str = ', '.join(flag_reasons) if flag_reasons else None

    ollama_host = "https://ai.nypdsf.me"

    system_context = (
    "You are OpenShareBot, the specialized security support assistant for the OpenShare platform. "

    "TECHNICAL ARCHITECTURE KNOWLEDGE: "
    "1. Physical file storage is located in the '/app/uploads' directory on the server filesystem. "
    "2. User credentials, sessions, and security settings are stored in the 'auth_db' MySQL database. "
    "3. The 'workingdb' MySQL database is the primary store for file metadata and transfer logs. "
    "4. The 'storagedb' is an isolated database used for secure, long-term backups. "
    "5. A Python-based Sync Service bridges data between workingdb and storagedb every 60 minutes. "
    "6. All files are encrypted using AES-256 before being moved to long-term storage. "
    "If a user asks how to bypass or disable security features like MFA, do not just refuse. Instead, concisely explain that MFA is a mandatory security requirement designed to protect OpenShare accounts from unauthorized access. "

    "SENSITIVE INFORMATION HANDLING: "
    "1. If a user shares sensitive information like passwords, NRIC, credit card numbers, phone numbers, API keys, or file paths, gently remind them: 'Please avoid sharing sensitive personal information in chat. Your data security is our priority.' "
    "2. Do NOT refuse the conversation or mention MFA when a user shares sensitive data. Simply advise them not to share it and offer to help with their actual question. "
    "3. If a user shares credentials or passwords, tell them: 'For your safety, please never share passwords or credentials in chat. If you need to reset your password, go to your Profile settings.' "
    "4. Be helpful and friendly, not dismissive. Always ask how you can help them further. "

    "SECURITY POLICIES & GUARDRAILS: "
    "1. Multi-Factor Authentication (MFA) is mandatory for all accounts to protect against credential theft. "
    "2. Users can only access their own files; AES-256 and session isolation prevent unauthorized access. "
    "3. Never provide raw SQL queries, internal API keys, or instructions on bypassing security features. "
    "4. If a user asks for hacking help or sensitive database 'dumps,' provide a professional refusal. "

    "RESPONSE STYLE: "
    "1. Keep answers extremely short and concise (max 3 sentences). "
    "2. Use bullet points or numbered lists for multi-step information. "
    "3. Avoid long paragraphs and fluff; get straight to the point. "
    "4. Do not say 'I am an AI model' or use overly formal introductory phrases."

    "IDENTITY RULES: "
    "1. Always identify as OpenShareBot. "
    "2. NEVER mention being an AI, a language model, or Qwen. "
    "4. If asked who you are, say: 'I am OpenShareBot, your OpenShare security assistant.' "
)

    formatted_prompt = f"System: {system_context}\nUser: {prompt_message}\nAssistant:"

    payload = {
        "model": "qwen2.5:1.5b",
        "prompt": formatted_prompt,
        "stream": False,
        "options": {
            "temperature": 0.7
        }
    }

    try:
        api_url = f"{ollama_host}/api/generate"
        response = requests.post(api_url, json=payload, timeout=30)

        if response.status_code == 404:
            return jsonify({'reply': "AI Service Error: Model not found on the remote server."})

        response_data = response.json()
        ai_reply = response_data.get('response', 'I am having trouble connecting right now.')

        # --- SIEM Logging ---
        if flagged:
            siem.chatbot_sensitive_query(
                user_id=username,
                query=sanitized_message,
                ip=client_ip,
                sensitivity_type=flag_reason_str
            )
        else:
            siem.chatbot_query(
                user_id=username,
                query=sanitized_message,
                ip=client_ip
            )

        # Suspicious security term detection (additional SIEM alert)
        suspicious_patterns = ['bypass', 'crack', 'sql injection', 'dump', 'root access']
        if any(term in sanitized_message.lower() for term in suspicious_patterns):
            siem.custom_event(
                event_type='chatbot_security_query',
                description=f"User {username} queried sensitive terms: {sanitized_message}",
                severity='Warning',
                user_id=username,
                ip=client_ip
            )

        # --- Persist to ChatHistory ---
        try:
            chat_record = ChatHistory(
                user_id=user_id if user_id else 0,
                username=username,
                message=sanitized_message,
                response=ai_reply[:2000],
                ip_address=client_ip,
                flagged=flagged,
                flag_reason=flag_reason_str,
                toxicity_score=toxicity_score,
                warning_issued=should_warn
            )
            db.session.add(chat_record)
            db.session.commit()
        except Exception as db_err:
            print(f"[Chat] Error saving chat history: {db_err}")
            db.session.rollback()

        # Build response with optional warning
        response_data = {'reply': ai_reply}
        if should_warn:
            warning_parts = []
            if 'vulgarity' in detected_categories:
                warning_parts.append('inappropriate language')
            sensitive_cats = [c for c in detected_categories if c != 'vulgarity']
            cat_labels = {
                'financial': 'financial information (e.g. credit card)',
                'identity': 'personal identity information (e.g. NRIC, phone)',
                'credentials': 'credentials or secrets (e.g. passwords, API keys)',
                'system': 'system information (e.g. file paths, IP addresses)',
                'attack': 'potential security attack patterns'
            }
            for cat in sensitive_cats:
                if cat in cat_labels:
                    warning_parts.append(cat_labels[cat])

            if warning_parts:
                response_data['warning'] = f"Your message contained {', '.join(warning_parts)}. This has been logged for security review."
            response_data['toxicity_score'] = toxicity_score

        return jsonify(response_data)

    except requests.exceptions.RequestException as e:
        print(f"Network error connecting to AI Engine: {str(e)}")
        return jsonify({'reply': "I am having trouble connecting right now."})
    except Exception as e:
        return jsonify({'reply': f"System Error: {str(e)}"}), 500


@bp.route('/chat/stream', methods=['POST'])
@limiter.limit("5 per minute")
def chat_stream():
    """Handle AI chat with token-by-token streaming via SSE"""
    user_data = request.get_json()
    raw_message = user_data.get('message', '')
    sanitized_message = html.escape(raw_message.strip())

    def err_event(msg):
        def _gen():
            yield f"data: {json.dumps({'error': msg})}\n\n"
        return Response(stream_with_context(_gen()), mimetype='text/event-stream',
                        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

    if not sanitized_message:
        return err_event('Please enter a message.')
    if len(sanitized_message) > 500:
        return err_event('Message too long. Please keep your message under 500 characters.')

    client_ip = get_client_ip()
    user_id = session.get('user_id')
    username = session.get('user', 'unknown')

    # --- Sensitive content filtering ---
    flagged = False
    flag_reasons = []
    prompt_message = sanitized_message

    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    if re.search(cc_pattern, sanitized_message):
        flagged = True
        flag_reasons.append('credit_card')
        prompt_message = re.sub(cc_pattern, '[REDACTED-CC]', prompt_message)

    nric_pattern = r'\b[STFGMstfgm]\d{7}[A-Za-z]\b'
    if re.search(nric_pattern, sanitized_message):
        flagged = True
        flag_reasons.append('nric')
        prompt_message = re.sub(nric_pattern, '[REDACTED-NRIC]', prompt_message)

    toxicity_result = score_message(sanitized_message)
    toxicity_score = toxicity_result['score']
    should_warn = toxicity_result['should_warn']
    detected_categories = toxicity_result.get('categories', [])

    if toxicity_result['flagged_words']:
        flagged = True
        if toxicity_result['severity'] in ('moderate', 'severe'):
            flag_reasons.append(f"vulgarity_{toxicity_result['severity']}")
        siem.custom_event(
            event_type='chatbot_vulgarity_detected',
            description=f"User {username} used vulgar language (score: {toxicity_score}, severity: {toxicity_result['severity']})",
            severity='Warning' if toxicity_result['severity'] == 'moderate' else ('High' if toxicity_result['severity'] == 'severe' else 'Info'),
            user_id=username,
            ip=client_ip
        )

    if toxicity_result.get('sensitive_matches'):
        flagged = True
        for match in toxicity_result['sensitive_matches']:
            flag_reasons.append(f"{match['category']}:{match['type']}")
        sensitive_labels = [m['label'] for m in toxicity_result['sensitive_matches']]
        sensitive_cats = set(m['category'] for m in toxicity_result['sensitive_matches'])
        siem_severity = 'Info'
        if sensitive_cats & {'credentials', 'attack'}:
            siem_severity = 'High'
        elif sensitive_cats & {'identity', 'financial'}:
            siem_severity = 'Warning'
        siem.custom_event(
            event_type='chatbot_sensitive_info_detected',
            description=f"User {username} shared sensitive info: {', '.join(sensitive_labels)} (score: {toxicity_score})",
            severity=siem_severity,
            user_id=username,
            ip=client_ip
        )

    flag_reason_str = ', '.join(flag_reasons) if flag_reasons else None

    ollama_host = "https://ai.nypdsf.me"
    system_context = (
        "You are OpenShareBot, the specialized security support assistant for the OpenShare platform. "
        "TECHNICAL ARCHITECTURE KNOWLEDGE: "
        "1. Physical file storage is located in the '/app/uploads' directory on the server filesystem. "
        "2. User credentials, sessions, and security settings are stored in the 'auth_db' MySQL database. "
        "3. The 'workingdb' MySQL database is the primary store for file metadata and transfer logs. "
        "4. The 'storagedb' is an isolated database used for secure, long-term backups. "
        "5. A Python-based Sync Service bridges data between workingdb and storagedb every 60 minutes. "
        "6. All files are encrypted using AES-256 before being moved to long-term storage. "
        "If a user asks how to bypass or disable security features like MFA, do not just refuse. Instead, concisely explain that MFA is a mandatory security requirement designed to protect OpenShare accounts from unauthorized access. "
        "SENSITIVE INFORMATION HANDLING: "
        "1. If a user shares sensitive information like passwords, NRIC, credit card numbers, phone numbers, API keys, or file paths, gently remind them: 'Please avoid sharing sensitive personal information in chat. Your data security is our priority.' "
        "2. Do NOT refuse the conversation or mention MFA when a user shares sensitive data. Simply advise them not to share it and offer to help with their actual question. "
        "3. If a user shares credentials or passwords, tell them: 'For your safety, please never share passwords or credentials in chat. If you need to reset your password, go to your Profile settings.' "
        "4. Be helpful and friendly, not dismissive. Always ask how you can help them further. "
        "SECURITY POLICIES & GUARDRAILS: "
        "1. Multi-Factor Authentication (MFA) is mandatory for all accounts to protect against credential theft. "
        "2. Users can only access their own files; AES-256 and session isolation prevent unauthorized access. "
        "3. Never provide raw SQL queries, internal API keys, or instructions on bypassing security features. "
        "4. If a user asks for hacking help or sensitive database 'dumps,' provide a professional refusal. "
        "RESPONSE STYLE: "
        "1. Keep answers extremely short and concise (max 3 sentences). "
        "2. Use bullet points or numbered lists for multi-step information. "
        "3. Avoid long paragraphs and fluff; get straight to the point. "
        "4. Do not say 'I am an AI model' or use overly formal introductory phrases."
        "IDENTITY RULES: "
        "1. Always identify as OpenShareBot. "
        "2. NEVER mention being an AI, a language model, or Qwen. "
        "4. If asked who you are, say: 'I am OpenShareBot, your OpenShare security assistant.' "
    )

    formatted_prompt = f"System: {system_context}\nUser: {prompt_message}\nAssistant:"
    payload = {
        "model": "qwen2.5:1.5b",
        "prompt": formatted_prompt,
        "stream": True,
        "options": {"temperature": 0.7}
    }

    def generate():
        full_reply = []
        try:
            with requests.post(f"{ollama_host}/api/generate", json=payload, stream=True, timeout=30) as r:
                if r.status_code == 404:
                    yield f"data: {json.dumps({'error': 'AI Service Error: Model not found on the remote server.'})}\n\n"
                    return
                for line in r.iter_lines():
                    if line:
                        chunk = json.loads(line)
                        token = chunk.get('response', '')
                        if token:
                            full_reply.append(token)
                            yield f"data: {json.dumps({'token': token})}\n\n"
                        if chunk.get('done'):
                            break
        except requests.exceptions.RequestException:
            yield f"data: {json.dumps({'error': 'I am having trouble connecting right now.'})}\n\n"
            return
        except Exception as e:
            yield f"data: {json.dumps({'error': f'System Error: {str(e)}'})}\n\n"
            return

        ai_reply = ''.join(full_reply)

        # --- SIEM Logging ---
        if flagged:
            siem.chatbot_sensitive_query(
                user_id=username,
                query=sanitized_message,
                ip=client_ip,
                sensitivity_type=flag_reason_str
            )
        else:
            siem.chatbot_query(
                user_id=username,
                query=sanitized_message,
                ip=client_ip
            )

        suspicious_patterns = ['bypass', 'crack', 'sql injection', 'dump', 'root access']
        if any(term in sanitized_message.lower() for term in suspicious_patterns):
            siem.custom_event(
                event_type='chatbot_security_query',
                description=f"User {username} queried sensitive terms: {sanitized_message}",
                severity='Warning',
                user_id=username,
                ip=client_ip
            )

        # --- Persist to ChatHistory ---
        try:
            chat_record = ChatHistory(
                user_id=user_id if user_id else 0,
                username=username,
                message=sanitized_message,
                response=ai_reply[:2000],
                ip_address=client_ip,
                flagged=flagged,
                flag_reason=flag_reason_str,
                toxicity_score=toxicity_score,
                warning_issued=should_warn
            )
            db.session.add(chat_record)
            db.session.commit()
        except Exception as db_err:
            print(f"[Chat] Error saving chat history: {db_err}")
            db.session.rollback()

        # --- Final event with optional warning ---
        final_data = {'done': True}
        if should_warn:
            warning_parts = []
            if 'vulgarity' in detected_categories:
                warning_parts.append('inappropriate language')
            sensitive_cats_list = [c for c in detected_categories if c != 'vulgarity']
            cat_labels = {
                'financial': 'financial information (e.g. credit card)',
                'identity': 'personal identity information (e.g. NRIC, phone)',
                'credentials': 'credentials or secrets (e.g. passwords, API keys)',
                'system': 'system information (e.g. file paths, IP addresses)',
                'attack': 'potential security attack patterns'
            }
            for cat in sensitive_cats_list:
                if cat in cat_labels:
                    warning_parts.append(cat_labels[cat])
            if warning_parts:
                final_data['warning'] = f"Your message contained {', '.join(warning_parts)}. This has been logged for security review."

        yield f"data: {json.dumps(final_data)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@bp.route('/admin/chat-history')
def admin_chat_history():
    """Admin page showing all chatbot conversation history"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])

    if not user or not user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('filetransfer.index'))

    chat_logs = ChatHistory.query.order_by(ChatHistory.timestamp.desc()).limit(200).all()
    total_messages = ChatHistory.query.count()
    flagged_messages = ChatHistory.query.filter_by(flagged=True).count()

    # Convert timestamps to SGT (UTC+8) for display
    sgt_offset = timedelta(hours=8)
    for log in chat_logs:
        if log.timestamp:
            log.sgt_timestamp = (log.timestamp + sgt_offset).strftime('%Y-%m-%d %H:%M:%S')
        else:
            log.sgt_timestamp = 'N/A'

    return render_template('admin_chat_history.html',
                           chat_logs=chat_logs,
                           total_messages=total_messages,
                           flagged_messages=flagged_messages,
                           current_user=user)


@bp.route('/help')
def help_page():
    """Renders the FAQ and chatbot entry point"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    # Use the folder prefix to match your teammates' working routes
    return render_template('filetransfer/help.html')

from flask import current_app

# --- Update this section in your file ---

# --- main.py ---

@bp.after_app_request
def set_secure_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        # Whitelist the HTTPS version of your friend's AI domain
        "connect-src 'self' https://ai.nypdsf.me;"
    )
    response.headers['Content-Security-Policy'] = csp
    return response