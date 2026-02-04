from flask import Flask, request
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
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
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'MoveIT <noreply@moveit.com>')

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
    admin_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@moveit.local')

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
