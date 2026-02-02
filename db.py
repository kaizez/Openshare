import mysql.connector
from mysql.connector import Error
from datetime import datetime
import os

# Check if dual DB mode is enabled
DUAL_DB_ENABLED = os.environ.get('DUAL_DB_ENABLED', 'false').lower() == 'true'


class Database:
    """Database handler for MySQL operations - Working DB only"""

    def __init__(self):
        """Initialize database connection"""
        self.connection = None
        self.host = os.environ.get('WORKING_DB_HOST', 'working-db')
        self.user = os.environ.get('WORKING_DB_USER', 'working_user')
        self.password = os.environ.get('WORKING_DB_PASSWORD', 'working_pass_2024')
        self.database = os.environ.get('WORKING_DB_NAME', 'workingdb')
        self.port = int(os.environ.get('WORKING_DB_PORT', 3306))
        self.connect()
        self.create_tables()

    def connect(self):
        """Establish connection to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database,
                port=self.port
            )
            if self.connection.is_connected():
                print(f"Connected to MySQL database at {self.host}:{self.port}")
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            raise

    def ensure_connection(self):
        """Ensure database connection is active"""
        try:
            if self.connection is None or not self.connection.is_connected():
                self.connect()
        except Error:
            self.connect()

    def create_tables(self):
        """Create tables if they don't exist"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_metadata (
                    file_id VARCHAR(255) PRIMARY KEY,
                    original_filename VARCHAR(500) NOT NULL,
                    stored_filename VARCHAR(500) NOT NULL,
                    file_size BIGINT NOT NULL,
                    file_hash VARCHAR(64) NOT NULL,
                    upload_time DATETIME NOT NULL,
                    download_count INT DEFAULT 0,
                    classification VARCHAR(50) NOT NULL,
                    detected_mime VARCHAR(100),
                    current_otp_code VARCHAR(16),
                    otp_generated_at DATETIME,
                    otp_expires_at DATETIME,
                    otp_used BOOLEAN DEFAULT FALSE,
                    is_archived BOOLEAN DEFAULT FALSE,
                    file_content LONGBLOB,
                    INDEX idx_otp_code (current_otp_code),
                    INDEX idx_upload_time (upload_time),
                    INDEX idx_archived (is_archived)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_id VARCHAR(255) NOT NULL,
                    timestamp DATETIME NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(45),
                    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
                    INDEX idx_file_id (file_id),
                    INDEX idx_timestamp (timestamp)
                )
            """)

            self.connection.commit()
            print("Database tables created successfully")
        except Error as e:
            print(f"Error creating tables: {e}")
            raise
        finally:
            cursor.close()

    def get_all_metadata(self):
        """Get all file metadata as a dictionary"""
        cursor = None
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("SELECT * FROM file_metadata")
            rows = cursor.fetchall()
            cursor.close()
            cursor = None

            result = {}
            for row in rows:
                file_id = row['file_id']
                access_logs = self.get_access_logs(file_id)

                result[file_id] = {
                    'original_filename': row['original_filename'],
                    'stored_filename': row['stored_filename'],
                    'file_size': row['file_size'],
                    'file_hash': row['file_hash'],
                    'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                    'download_count': row['download_count'],
                    'classification': row['classification'],
                    'detected_mime': row['detected_mime'],
                    'current_otp_code': row['current_otp_code'],
                    'otp_generated_at': row['otp_generated_at'].isoformat() if row['otp_generated_at'] else None,
                    'otp_expires_at': row['otp_expires_at'].isoformat() if row['otp_expires_at'] else None,
                    'otp_used': bool(row['otp_used']),
                    'is_archived': bool(row.get('is_archived', False)),
                    'access_logs': access_logs
                }
            return result
        except Error as e:
            print(f"Error fetching all metadata: {e}")
            return {}
        finally:
            if cursor is not None:
                cursor.close()

    def get_file_metadata(self, file_id, include_content=False):
        """Get metadata for a specific file"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)

            if include_content:
                cursor.execute("SELECT * FROM file_metadata WHERE file_id = %s", (file_id,))
            else:
                cursor.execute("""
                    SELECT file_id, original_filename, stored_filename, file_size,
                           file_hash, upload_time, download_count, classification,
                           detected_mime, current_otp_code, otp_generated_at,
                           otp_expires_at, otp_used, is_archived
                    FROM file_metadata WHERE file_id = %s
                """, (file_id,))

            row = cursor.fetchone()

            if not row:
                return None

            access_logs = self.get_access_logs(file_id)

            result = {
                'original_filename': row['original_filename'],
                'stored_filename': row['stored_filename'],
                'file_size': row['file_size'],
                'file_hash': row['file_hash'],
                'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                'download_count': row['download_count'],
                'classification': row['classification'],
                'detected_mime': row['detected_mime'],
                'current_otp_code': row['current_otp_code'],
                'otp_generated_at': row['otp_generated_at'].isoformat() if row['otp_generated_at'] else None,
                'otp_expires_at': row['otp_expires_at'].isoformat() if row['otp_expires_at'] else None,
                'otp_used': bool(row['otp_used']),
                'is_archived': bool(row.get('is_archived', False)),
                'access_logs': access_logs
            }

            if include_content and 'file_content' in row:
                result['file_content'] = row['file_content']

            return result
        except Error as e:
            print(f"Error fetching file metadata: {e}")
            return None
        finally:
            cursor.close()

    def save_file_metadata(self, file_id, metadata, file_content=None):
        """Save or update file metadata"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            upload_time = datetime.fromisoformat(metadata['upload_time']) if isinstance(metadata['upload_time'], str) else metadata['upload_time']
            otp_generated_at = datetime.fromisoformat(metadata['otp_generated_at']) if isinstance(metadata.get('otp_generated_at'), str) else metadata.get('otp_generated_at')
            otp_expires_at = datetime.fromisoformat(metadata['otp_expires_at']) if isinstance(metadata.get('otp_expires_at'), str) else metadata.get('otp_expires_at')

            if file_content is not None:
                cursor.execute("""
                    INSERT INTO file_metadata
                    (file_id, original_filename, stored_filename, file_size, file_hash,
                     upload_time, download_count, classification, detected_mime,
                     current_otp_code, otp_generated_at, otp_expires_at, otp_used, file_content)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    original_filename = VALUES(original_filename),
                    stored_filename = VALUES(stored_filename),
                    file_size = VALUES(file_size),
                    file_hash = VALUES(file_hash),
                    upload_time = VALUES(upload_time),
                    download_count = VALUES(download_count),
                    classification = VALUES(classification),
                    detected_mime = VALUES(detected_mime),
                    current_otp_code = VALUES(current_otp_code),
                    otp_generated_at = VALUES(otp_generated_at),
                    otp_expires_at = VALUES(otp_expires_at),
                    otp_used = VALUES(otp_used),
                    file_content = VALUES(file_content)
                """, (
                    file_id,
                    metadata['original_filename'],
                    metadata['stored_filename'],
                    metadata['file_size'],
                    metadata['file_hash'],
                    upload_time,
                    metadata.get('download_count', 0),
                    metadata['classification'],
                    metadata.get('detected_mime'),
                    metadata.get('current_otp_code'),
                    otp_generated_at,
                    otp_expires_at,
                    metadata.get('otp_used', False),
                    file_content
                ))
            else:
                cursor.execute("""
                    UPDATE file_metadata SET
                    original_filename = %s,
                    stored_filename = %s,
                    file_size = %s,
                    file_hash = %s,
                    upload_time = %s,
                    download_count = %s,
                    classification = %s,
                    detected_mime = %s,
                    current_otp_code = %s,
                    otp_generated_at = %s,
                    otp_expires_at = %s,
                    otp_used = %s
                    WHERE file_id = %s
                """, (
                    metadata['original_filename'],
                    metadata['stored_filename'],
                    metadata['file_size'],
                    metadata['file_hash'],
                    upload_time,
                    metadata.get('download_count', 0),
                    metadata['classification'],
                    metadata.get('detected_mime'),
                    metadata.get('current_otp_code'),
                    otp_generated_at,
                    otp_expires_at,
                    metadata.get('otp_used', False),
                    file_id
                ))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error saving file metadata: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def delete_file_metadata(self, file_id):
        """Delete file metadata and associated access logs"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM file_metadata WHERE file_id = %s", (file_id,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error deleting file metadata: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def get_access_logs(self, file_id):
        """Get access logs for a specific file"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT timestamp, status, details, ip_address
                FROM access_logs
                WHERE file_id = %s
                ORDER BY timestamp DESC
            """, (file_id,))

            logs = cursor.fetchall()

            return [
                {
                    'timestamp': log['timestamp'].isoformat() if log['timestamp'] else None,
                    'status': log['status'],
                    'details': log['details'],
                    'ip_address': log['ip_address']
                }
                for log in logs
            ]
        except Error as e:
            print(f"Error fetching access logs: {e}")
            return []
        finally:
            cursor.close()

    def add_access_log(self, file_id, status, details, ip_address):
        """Add an access log entry"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO access_logs (file_id, timestamp, status, details, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """, (file_id, datetime.now(), status, details, ip_address))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error adding access log: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def find_file_by_otp(self, otp_code):
        """Find file by OTP code"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT file_id FROM file_metadata
                WHERE current_otp_code = %s
            """, (otp_code,))

            row = cursor.fetchone()
            return row['file_id'] if row else None
        except Error as e:
            print(f"Error finding file by OTP: {e}")
            return None
        finally:
            cursor.close()

    def update_download_count(self, file_id):
        """Increment download count for a file"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE file_metadata
                SET download_count = download_count + 1
                WHERE file_id = %s
            """, (file_id,))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error updating download count: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def update_otp(self, file_id, otp_code, generated_at, expires_at, otp_used=False):
        """Update OTP information for a file"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE file_metadata
                SET current_otp_code = %s,
                    otp_generated_at = %s,
                    otp_expires_at = %s,
                    otp_used = %s
                WHERE file_id = %s
            """, (otp_code, generated_at, expires_at, otp_used, file_id))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error updating OTP: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection closed")


# Global database instance
db = None


def get_db():
    """Get or create database instance"""
    global db
    if db is None:
        db = Database()
    return db
