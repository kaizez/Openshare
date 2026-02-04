from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_mail import Message
from app import oauth, mail, limiter
from app.models import db, User
from app.siem_logger import SIEMLogger
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

bp = Blueprint('main', __name__)

# Initialize SIEM Logger - connects to Ayden's SIEM system
# The SIEM URL is configurable via environment variable
SIEM_URL = os.environ.get('SIEM_URL', 'http://siem:5001')
siem = SIEMLogger(SIEM_URL, log_source="authentication")

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
            return 'Location unavailable'

        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip_address)
            city = response.city.name or 'Unknown City'
            country = response.country.name or 'Unknown Country'
            return f'{city}, {country}'
    except (geoip2.errors.AddressNotFoundError, Exception):
        return 'Location unavailable'

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
            subject='Security Alert: Admin Login Attempt from Unauthorized Device - MOVEit',
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
                            <li>Contact support at <a href="mailto:support@moveit.com">support@moveit.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from MOVEit. Please do not reply to this email.
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

        This is an automated security notification from MOVEit.
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
            subject='New Account Created - MOVEit',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #48bb78;">Welcome to MOVEit!</h2>
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
                        <p>If you did not create this account, please contact us immediately at <a href="mailto:support@moveit.com">support@moveit.com</a></p>
                    </div>

                    <p>Thank you for choosing MOVEit!</p>
                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from MOVEit. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Welcome to MOVEit!

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
        If you did not create this account, please contact us immediately at support@moveit.com

        Thank you for choosing MOVEit!

        This is an automated security notification from MOVEit. Please do not reply to this email.
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
            subject='Security Alert: Two-Factor Authentication Disabled - MOVEit',
            recipients=[email]
        )

        msg.html = f'''
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #c53030;">Security Alert: MFA Disabled</h2>
                    <p>Hello <strong>{username}</strong>,</p>
                    <p>Two-Factor Authentication (MFA) has been <strong>disabled</strong> on your MOVEit account.</p>

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
                            <li>Contact support at <a href="mailto:support@moveit.com">support@moveit.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from MOVEit. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Security Alert: MFA Disabled

        Hello {username},

        Two-Factor Authentication (MFA) has been disabled on your MOVEit account.

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
        - Contact support at support@moveit.com

        This is an automated security notification from MOVEit. Please do not reply to this email.
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
            subject='Security Alert: Account Locked - MOVEit',
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
                            <li>Contact support at <a href="mailto:support@moveit.com">support@moveit.com</a></li>
                        </ul>
                    </div>

                    <p style="color: #718096; font-size: 12px; margin-top: 30px;">
                        This is an automated security notification from MOVEit. Please do not reply to this email.
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
        - Contact support at support@moveit.com

        This is an automated security notification from MOVEit. Please do not reply to this email.
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
            subject='URGENT Security Alert: Suspicious Login Detected - MOVEit',
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
                            <li>Email: <a href="mailto:support@moveit.com">support@moveit.com</a></li>
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
                        This is an automated security notification from MOVEit. Please do not reply to this email.
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
        - Email: support@moveit.com

        Recommended Actions:
        - Contact support immediately to verify your identity
        - Change your password once your account is unlocked
        - Review your account activity for any unauthorized access
        - Enable Two-Factor Authentication if not already enabled

        This is an automated security notification from MOVEit. Please do not reply to this email.
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
            subject='Password Reset Request - MOVEit',
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
                        This is an automated security notification from MOVEit. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        '''

        msg.body = f'''
        Password Reset Request - MOVEit

        Hello {username},

        We received a request to reset your password. Please use the verification code below to proceed with your password reset.

        Your Verification Code: {otp_code}

        This code will expire in 15 minutes.

        Security Notice:
        If you did not request a password reset, please ignore this email. Your password will remain unchanged.
        For security reasons, this verification code will expire in 15 minutes.

        This is an automated security notification from MOVEit. Please do not reply to this email.
        '''

        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending password reset email: {str(e)}")
        return False

# Index route moved to FileTransfer blueprint
# @bp.route('/')
# def index():
#     user = None
#     # Check if user is logged in and get MFA status
#     if 'user_id' in session:
#         user = User.query.get(session['user_id'])
#         if user:
#             session['mfa_enabled'] = user.mfa_enabled
#     return render_template('index.html', user=user)

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
                        session['user'] = user.username
                        session['user_id'] = user.id
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

@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def register():
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
                    # Get IP and location
                    ip_address = get_client_ip()
                    location = get_location_from_ip(ip_address)

                    # Create new user with Argon2id hashed password and MFA enabled
                    new_user = User(
                        username=username,
                        email=email,
                        last_login_ip=ip_address,
                        last_login_location=location
                    )
                    new_user.set_password(password)

                    # Generate MFA secret and enable MFA by default
                    new_user.mfa_secret = pyotp.random_base32()
                    new_user.mfa_enabled = True

                    db.session.add(new_user)
                    db.session.commit()

                    # Log user creation to SIEM
                    siem.user_created(
                        admin_id="self-registration",
                        new_user_id=username,
                        ip=ip_address,
                        user_role="standard"
                    )

                    # Send account creation email
                    send_account_creation_email(email, username, ip_address, location)

                    # Log the user in temporarily to set up MFA
                    session['user'] = new_user.username
                    session['user_id'] = new_user.id
                    session['email'] = new_user.email
                    session['needs_mfa_setup'] = True

                    return redirect(url_for('main.mfa_setup_required'))

    return render_template('register.html', recaptcha_site_key=current_app.config.get('RECAPTCHA_SITE_KEY'))

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
                session['user'] = user.username
                session['user_id'] = user.id
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
                    session['user'] = existing_user.username
                    session['user_id'] = existing_user.id
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

    # Get last login info
    last_ip = user.last_login_ip
    last_location = user.last_login_location

    # Skip if no previous location data
    if not last_location or last_location == 'Location unavailable':
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
    siem.log(
        event_type='impossible_travel_detected',
        severity='critical',
        message=f'Impossible travel detected for {user.username}: {last_location} -> {current_location}',
        user_id=user.username,
        ip=current_ip,
        details={
            'last_location': last_location,
            'current_location': current_location,
            'last_ip': last_ip,
            'current_ip': current_ip
        }
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
    return redirect(url_for('main.login'))

@bp.route('/profile')
def profile():
    """User profile page"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('main.login'))

    return render_template('profile.html', user=user)

@bp.route('/settings', methods=['GET'])
def settings():
    """User settings page"""
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('main.login'))

    return render_template('settings.html', user=user)

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
                session.pop('needs_mfa_setup', None)
                session['mfa_enabled'] = True
                return redirect(url_for('filetransfer.index'))

    # Generate QR code
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='MOVEit Authentication'
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
                session['user'] = user.username
                session['user_id'] = user.id
                session['email'] = user.email
                session['mfa_enabled'] = True

                # Log to SIEM
                siem.login_success(
                    user_id=user.username,
                    ip=get_client_ip(),
                    user_role='admin',
                    mfa_used=True
                )

                flash('MFA enabled successfully! Welcome to the admin dashboard.', 'success')
                return redirect(url_for('main.admin_dashboard'))
            else:
                flash('Invalid verification code. Please try again.', 'error')

    # Generate QR code
    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='MOVEit Admin'
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
                db.session.commit()

                # Clear temporary secret
                session.pop('temp_mfa_secret', None)

                return redirect(url_for('filetransfer.index'))

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
        issuer_name='MOVEit Authentication'
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
                session['user'] = user.username
                session['user_id'] = user.id
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
    if user.oauth_provider:
        # For OAuth users, we can disable without password
        # Or you could require re-authentication with OAuth
        pass
    else:
        # Get password from request
        password = request.form.get('password')

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

    # Store username for logging before deletion
    deleted_username = target_user.username

    # Log to SIEM before deletion
    siem.user_deleted(
        admin_id=current_user.username,
        deleted_user_id=deleted_username,
        ip=get_client_ip()
    )

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
    siem.log(
        event_type='account_locked_by_admin',
        severity='warning',
        message=f'Account {target_user.username} locked by admin {current_user.username}',
        user_id=target_user.username,
        ip=get_client_ip()
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
    siem.log(
        event_type='account_unlocked_by_admin',
        severity='info',
        message=f'Account {target_user.username} unlocked by admin {current_user.username}',
        user_id=target_user.username,
        ip=get_client_ip()
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
                    session['user'] = user.username
                    session['user_id'] = user.id
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
                session['user'] = user.username
                session['user_id'] = user.id
                session['email'] = user.email
                session.pop('mac_verify_user_id', None)
                flash('Login successful! MAC address verified.', 'success')
                return redirect(url_for('main.admin_dashboard'))
            else:
                flash('MAC address does not match. Access denied.', 'error')

    return render_template('admin_mac_verify.html',
                         user=user,
                         detected_mac=detected_mac)
