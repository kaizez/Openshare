import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration class"""

    # Secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Upload configuration
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 500 * 1024 * 1024))  # 500MB default

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz',
        'mp3', 'mp4', 'avi', 'mkv', 'mov', 'csv', 'json', 'xml'
    }

    # Server configuration
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

    # File metadata storage (deprecated - now using MySQL)
    FILE_METADATA_PATH = os.environ.get('FILE_METADATA_PATH', 'file_metadata.json')

    # ============================================
    # DUAL DATABASE CONFIGURATION
    # ============================================

    # Working Database (DB1) - Primary database for all app operations
    # This database handles all real-time transactions and is directly accessible by the app
    WORKING_DB_HOST = os.environ.get('WORKING_DB_HOST', os.environ.get('DB_HOST', 'localhost'))
    WORKING_DB_USER = os.environ.get('WORKING_DB_USER', os.environ.get('DB_USER', 'root'))
    WORKING_DB_PASSWORD = os.environ.get('WORKING_DB_PASSWORD', os.environ.get('DB_PASSWORD', ''))
    WORKING_DB_NAME = os.environ.get('WORKING_DB_NAME', os.environ.get('DB_NAME', 'workingdb'))
    WORKING_DB_PORT = int(os.environ.get('WORKING_DB_PORT', os.environ.get('DB_PORT', 3306)))

    # Storage Database (DB2) - Isolated database for long-term storage
    # This database is only accessible by the Working DB for data archival
    STORAGE_DB_HOST = os.environ.get('STORAGE_DB_HOST', 'storage-db')
    STORAGE_DB_USER = os.environ.get('STORAGE_DB_USER', 'storage_user')
    STORAGE_DB_PASSWORD = os.environ.get('STORAGE_DB_PASSWORD', 'storage_secure_password')
    STORAGE_DB_NAME = os.environ.get('STORAGE_DB_NAME', 'storagedb')
    STORAGE_DB_PORT = int(os.environ.get('STORAGE_DB_PORT', 3307))

    # Sync Configuration
    # Interval in seconds for syncing data from Working DB to Storage DB
    SYNC_INTERVAL_SECONDS = int(os.environ.get('SYNC_INTERVAL_SECONDS', 3600))  # Default: 1 hour

    # Data retention in Working DB (in hours) - data older than this is archived to Storage DB
    WORKING_DB_RETENTION_HOURS = int(os.environ.get('WORKING_DB_RETENTION_HOURS', 24))  # Default: 24 hours

    # Enable/disable dual DB mode (for backward compatibility)
    DUAL_DB_ENABLED = os.environ.get('DUAL_DB_ENABLED', 'True').lower() == 'true'

    # Enable automatic sync service
    SYNC_SERVICE_ENABLED = os.environ.get('SYNC_SERVICE_ENABLED', 'True').lower() == 'true'

    # Legacy single DB configuration (for backward compatibility)
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'storagedb')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    # Override with stronger settings for production


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
