from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
import os
from dotenv import load_dotenv
from app.models import db

# Load environment variables from .env file
load_dotenv()

oauth = OAuth()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-here'

    # Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Email Configuration
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@moveit.com')

    # reCAPTCHA Configuration
    app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', '')
    app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', '')

    # Server configuration for OAuth callbacks
    app.config['SERVER_NAME'] = '127.0.0.1:5000'
    # Force HTTPS URL scheme for OAuth redirects
    app.config['PREFERRED_URL_SCHEME'] = 'https'

    # Google OAuth Configuration
    app.config['GOOGLE_CLIENT_ID'] = '1030772732738-7e4iq8jseiea8n418m2blvm22dqt0lrf.apps.googleusercontent.com'
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', '')  # Set this in .env file

    # Initialize database
    db.init_app(app)

    # Initialize email
    mail.init_app(app)

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

    # Create database tables
    with app.app_context():
        db.create_all()

    from app import routes
    app.register_blueprint(routes.bp)

    return app
