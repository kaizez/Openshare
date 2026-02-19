from flask import Flask, request, session, redirect, url_for, flash
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from app.models import db
from app.security_middleware import SecurityMiddleware, setup_security_logging

# Load environment variables from .env file (use explicit path)
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))

oauth = OAuth()
mail = Mail()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
csrf = CSRFProtect()
security_middleware = SecurityMiddleware()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

    # Database Configuration - Use MySQL in Docker, SQLite locally
    if os.environ.get('DOCKER_ENV') == 'true':
        from urllib.parse import quote_plus
        mysql_host = os.environ.get('MYSQL_HOST', 'db')
        mysql_port = os.environ.get('MYSQL_PORT', '3306')
        mysql_user = os.environ.get('MYSQL_USER', 'root')
        mysql_password = quote_plus(os.environ.get('MYSQL_PASSWORD', 'your_secure_password'))
        mysql_database = os.environ.get('MYSQL_DATABASE', 'auth_db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}'
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Email Configuration
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'OpenShare <noreply@openshare.com>')

    # reCAPTCHA Configuration
    app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', '')
    app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', '')

    # Server configuration for OAuth callbacks
    # Only set SERVER_NAME if not in Docker (it can cause issues with URL generation in Docker)
    if os.environ.get('DOCKER_ENV') != 'true':
        app.config['SERVER_NAME'] = '127.0.0.1:5000'
    # Force HTTPS URL scheme for OAuth redirects (when not in Docker)
    app.config['PREFERRED_URL_SCHEME'] = os.environ.get('URL_SCHEME', 'https')

    # Google OAuth Configuration
    app.config['GOOGLE_CLIENT_ID'] = '1030772732738-7e4iq8jseiea8n418m2blvm22dqt0lrf.apps.googleusercontent.com'
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')  # Set this in .env file

    # Initialize database
    db.init_app(app)

    # Initialize email
    mail.init_app(app)

    # Initialize rate limiter
    limiter.init_app(app)

    # Initialize CSRF protection
    csrf.init_app(app)

    # Initialize security middleware (WAF)
    security_middleware.init_app(app)

    # Setup security logging
    setup_security_logging()

    oauth.init_app(app)

    # Register Google OAuth
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Create database tables and ensure admin exists
    with app.app_context():
        db.create_all()
        _ensure_admin_exists()

    from app import routes
    app.register_blueprint(routes.bp)

    # Session management middleware
    @app.before_request
    def session_management():
        # Skip for static files and auth routes
        exempt_routes = ['main.login', 'main.register', 'main.logout', 'main.forgot_password',
                        'main.reset_password', 'main.reset_password_confirm', 'main.verify_mfa',
                        'main.google_login', 'main.google_callback', 'main.oauth_confirm',
                        'main.oauth_signup', 'main.change_password', 'static', 'filetransfer.static']

        if request.endpoint in exempt_routes or request.endpoint is None:
            return

        if request.path.startswith('/static'):
            return

        # Check if user is logged in
        if 'user_id' not in session:
            return

        from app.models import User

        # 1. Session timeout check (10 minutes)
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            if datetime.utcnow() - last_activity_time > timedelta(minutes=10):
                # Session expired
                user_id = session.get('user_id')
                session.clear()
                flash('Session expired due to inactivity. Please login again.', 'warning')
                return redirect(url_for('main.login'))

        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()

        # 2. Concurrent session check
        user = User.query.get(session.get('user_id'))
        if user and user.current_session_id:
            if session.get('session_id') != user.current_session_id:
                # Another session is active, kick this one
                session.clear()
                flash('You have been logged out because your account was accessed from another location.', 'warning')
                return redirect(url_for('main.login'))

        # 3. Password expiry check (skip for OAuth users)
        if user and not user.is_oauth_user() and user.is_password_expired():
            if request.endpoint != 'main.change_password':
                flash('Your password has expired. Please change it now.', 'warning')
                return redirect(url_for('main.change_password'))

    return app


def _ensure_admin_exists():
    """
    Check if a super admin account exists in the database.
    If not, create the default admin account.
    This runs on every app startup to ensure admin access is always available.
    """
    from app.models import User
    from argon2 import PasswordHasher
    from datetime import datetime
    import time

    # Retry logic for database connection (handles race condition with MySQL startup)
    max_retries = 30
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            # Check if ANY super admin exists (not by username, but by role)
            super_admin = User.query.filter_by(is_super_admin=True).first()
            break  # Connection successful, exit retry loop
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"[Init] Database not ready (attempt {attempt + 1}/{max_retries}), retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                print(f"[Init] Failed to connect to database after {max_retries} attempts: {e}")
                raise

    if super_admin:
        print(f"[Init] Super admin exists: {super_admin.username}")
        return

    # No super admin found - create default admin account
    print("[Init] No super admin found. Creating default admin account...")

    # Get admin credentials from environment variables (with defaults)
    admin_username = os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin')
    admin_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin')
    admin_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@openshare.local')

    # Check if the username already exists (edge case: user exists but not super admin)
    existing_user = User.query.filter_by(username=admin_username).first()

    if existing_user:
        # Promote existing user to super admin
        existing_user.is_admin = True
        existing_user.is_super_admin = True
        db.session.commit()
        print(f"[Init] Promoted existing user '{admin_username}' to super admin")
        return

    # Create new admin user
    ph = PasswordHasher()
    admin = User(
        username=admin_username,
        email=admin_email,
        password_hash=ph.hash(admin_password),
        is_admin=True,
        is_super_admin=True,
        mfa_enabled=False,
        created_at=datetime.utcnow()
    )

    db.session.add(admin)
    db.session.commit()

    print("=" * 50)
    print("[Init] Default Admin Account Created!")
    print("=" * 50)
    print(f"  Username: {admin_username}")
    print(f"  Password: {admin_password}")
    print(f"  Email:    {admin_email}")
    print("=" * 50)
    print("  WARNING: Change password after first login!")
    print("=" * 50)
