from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_mail import Message
from app import oauth, mail
from app.models import db, User
import geoip2.database
import geoip2.errors
import os
import re
import html
import requests
import secrets
import pyotp
from datetime import datetime, timedelta

bp = Blueprint('main', __name__)

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

def send_account_creation_email(email, username, ip_address, location):
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
                        <p style="margin: 5px 0;"><strong>Sign-up Method:</strong> Google OAuth</p>
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
        - Sign-up Method: Google OAuth
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

@bp.route('/')
def index():
    return render_template('index.html')

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
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')  # Don't sanitize passwords

        if not username or not password:
            flash('Please enter both username and password', 'error')
        else:
            # Find user by username
            user = User.query.filter_by(username=username).first()

            if user and user.verify_password(password):
                # Password verified with Argon2id
                session['user'] = user.username
                session['user_id'] = user.id
                flash('Login successful!', 'success')
                return redirect(url_for('main.index'))
            else:
                flash('Invalid username or password', 'error')

    return render_template('login.html')

@bp.route('/register', methods=['GET', 'POST'])
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
                    flash('Username or email already exists', 'error')
                else:
                    # Create new user with Argon2id hashed password
                    new_user = User(username=username, email=email)
                    new_user.set_password(password)

                    db.session.add(new_user)
                    db.session.commit()

                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('main.login'))

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

                    # Create new OAuth user
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

                    db.session.add(new_user)
                    db.session.commit()

                    # Send security notification email to their Google email
                    send_account_creation_email(email, username, ip_address, location)

                    # Clear OAuth session data
                    session.pop('oauth_email', None)
                    session.pop('oauth_name', None)
                    session.pop('oauth_id', None)
                    session.pop('oauth_picture', None)

                    # Log the user in
                    session['user'] = new_user.username
                    session['user_id'] = new_user.id
                    session['email'] = new_user.email
                    session['picture'] = new_user.profile_picture_url

                    flash('Account created successfully! A confirmation email has been sent to your Google email.', 'success')
                    return redirect(url_for('main.index'))

    return render_template('oauth_signup.html', recaptcha_site_key=current_app.config.get('RECAPTCHA_SITE_KEY'))

@bp.route('/google-login')
def google_login():
    # Use the /auth/google/authorized endpoint as the callback URL
    redirect_uri = url_for('main.google_callback', _external=True, _scheme='https')
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
                # User exists, log them in
                session['user'] = existing_user.username
                session['user_id'] = existing_user.id
                session['email'] = existing_user.email
                session['picture'] = existing_user.profile_picture_url or oauth_picture

                # Update last login info
                existing_user.last_login_ip = get_client_ip()
                existing_user.last_login_location = get_location_from_ip(existing_user.last_login_ip)
                db.session.commit()

                flash(f'Welcome back, {existing_user.username}!', 'success')
                return redirect(url_for('main.index'))
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

                # Clear session
                session.pop('otp_verified', None)
                session.pop('reset_user_id', None)
                session.pop('reset_email', None)

                flash('Password reset successful! You can now login with your new password.', 'success')
                return redirect(url_for('main.login'))

    return render_template('reset_password_confirm.html')

@bp.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('main.login'))
