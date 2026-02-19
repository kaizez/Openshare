import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
import os

# Import encryption utilities
from encryption import encrypt_file, decrypt_file, encrypt_otp, decrypt_otp

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
                port=self.port,
                autocommit=True  # Ensure we always see latest committed data
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
                    current_otp_code TEXT,
                    otp_generated_at DATETIME,
                    otp_expires_at DATETIME,
                    otp_used BOOLEAN DEFAULT FALSE,
                    is_archived BOOLEAN DEFAULT FALSE,
                    scan_status VARCHAR(20),
                    vt_analysis_id VARCHAR(255),
                    vt_scan_method VARCHAR(50),
                    vt_malicious_count INT DEFAULT 0,
                    vt_suspicious_count INT DEFAULT 0,
                    vt_total_engines INT DEFAULT 0,
                    vt_scan_completed_at DATETIME,
                    vt_scan_error TEXT,
                    upload_ip VARCHAR(45),
                    uploaded_by INT,
                    file_content LONGBLOB,
                    INDEX idx_otp_code (current_otp_code(255)),
                    INDEX idx_upload_time (upload_time),
                    INDEX idx_archived (is_archived),
                    INDEX idx_scan_status (scan_status),
                    INDEX idx_uploaded_by (uploaded_by)
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS failed_upload_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    original_filename VARCHAR(500) NOT NULL,
                    file_size BIGINT,
                    file_hash VARCHAR(64),
                    detected_mime VARCHAR(100),
                    failure_reason VARCHAR(100) NOT NULL,
                    failure_details TEXT,
                    ip_address VARCHAR(45),
                    classification VARCHAR(50),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_failure_reason (failure_reason)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS virus_scan_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    file_id VARCHAR(255),
                    original_filename VARCHAR(500) NOT NULL,
                    file_size BIGINT,
                    file_hash VARCHAR(64),
                    scan_status VARCHAR(20) NOT NULL,
                    malicious_count INT DEFAULT 0,
                    suspicious_count INT DEFAULT 0,
                    scan_details TEXT,
                    ip_address VARCHAR(45),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_scan_status (scan_status),
                    INDEX idx_file_id (file_id)
                )
            """)

            # Approval requests for Classified files (two-person rule)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    request_id VARCHAR(32) UNIQUE NOT NULL,
                    file_id VARCHAR(255) NOT NULL,
                    requester_user_id INT NOT NULL,
                    owner_user_id INT NOT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    responded_at DATETIME,
                    requester_ip VARCHAR(45),
                    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
                    INDEX idx_request_id (request_id),
                    INDEX idx_owner_status (owner_user_id, status),
                    INDEX idx_expires_at (expires_at)
                )
            """)

            # Forensic download watermarks – admin-only decrypt
            # watermarked_hash : SHA-256 of the file WITH the watermark embedded
            #                    (unique per download — identifies exactly one user)
            # original_file_hash: SHA-256 of the original file (links to file_metadata)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS download_watermarks (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    watermark_id VARCHAR(64) UNIQUE NOT NULL,
                    file_id VARCHAR(255) NOT NULL,
                    original_file_hash VARCHAR(64) NOT NULL,
                    watermarked_hash VARCHAR(64) NOT NULL,
                    download_timestamp DATETIME NOT NULL,
                    encrypted_payload LONGTEXT NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
                    INDEX idx_wm_file_id (file_id),
                    INDEX idx_wm_original_hash (original_file_hash),
                    INDEX idx_wm_watermarked_hash (watermarked_hash),
                    INDEX idx_wm_timestamp (download_timestamp),
                    INDEX idx_wm_watermark_id (watermark_id)
                )
            """)
            # Migrate: add columns if table already existed without them
            try:
                cursor.execute("ALTER TABLE download_watermarks ADD COLUMN watermarked_hash VARCHAR(64) NOT NULL DEFAULT '' AFTER file_id")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE download_watermarks ADD COLUMN original_file_hash VARCHAR(64) NOT NULL DEFAULT '' AFTER file_id")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE download_watermarks ADD INDEX idx_wm_watermarked_hash (watermarked_hash)")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE download_watermarks ADD INDEX idx_wm_original_hash (original_file_hash)")
            except Exception:
                pass

            # ML trust-score analysis results
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_ml_analysis (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    file_id VARCHAR(255) UNIQUE NOT NULL,
                    trust_score INT NOT NULL DEFAULT 50,
                    risk_level VARCHAR(20) NOT NULL DEFAULT 'unknown',
                    risk_signals JSON,
                    features JSON,
                    anomaly_score FLOAT,
                    analyzed_at DATETIME NOT NULL,
                    model_version VARCHAR(20) DEFAULT '1.0',
                    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id) ON DELETE CASCADE,
                    INDEX idx_ml_trust_score (trust_score),
                    INDEX idx_ml_risk_level (risk_level)
                )
            """)

            self.connection.commit()
            print("Database tables created successfully")
        except Error as e:
            print(f"Error creating tables: {e}")
            raise
        finally:
            cursor.close()

    def get_all_metadata(self, user_id=None):
        """Get all file metadata as a dictionary, optionally filtered by user"""
        cursor = None
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            if user_id is not None:
                cursor.execute("SELECT * FROM file_metadata WHERE uploaded_by = %s", (user_id,))
            else:
                cursor.execute("SELECT * FROM file_metadata")
            rows = cursor.fetchall()
            cursor.close()
            cursor = None

            result = {}
            for row in rows:
                file_id = row['file_id']
                access_logs = self.get_access_logs(file_id)

                # Decrypt OTP code for display
                encrypted_otp = row['current_otp_code']
                decrypted_otp = decrypt_otp(encrypted_otp) if encrypted_otp else None

                result[file_id] = {
                    'original_filename': row['original_filename'],
                    'stored_filename': row['stored_filename'],
                    'file_size': row['file_size'],
                    'file_hash': row['file_hash'],
                    'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                    'download_count': row['download_count'],
                    'classification': row['classification'],
                    'detected_mime': row['detected_mime'],
                    'current_otp_code': decrypted_otp,
                    'otp_generated_at': row['otp_generated_at'].isoformat() if row['otp_generated_at'] else None,
                    'otp_expires_at': row['otp_expires_at'].isoformat() if row['otp_expires_at'] else None,
                    'otp_used': bool(row['otp_used']),
                    'is_archived': bool(row.get('is_archived', False)),
                    'scan_status': row.get('scan_status'),
                    'uploaded_by': row.get('uploaded_by'),
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
                           otp_expires_at, otp_used, is_archived, scan_status,
                           vt_analysis_id, uploaded_by
                    FROM file_metadata WHERE file_id = %s
                """, (file_id,))

            row = cursor.fetchone()

            if not row:
                return None

            access_logs = self.get_access_logs(file_id)

            # Decrypt OTP code
            encrypted_otp = row['current_otp_code']
            decrypted_otp = decrypt_otp(encrypted_otp) if encrypted_otp else None

            result = {
                'original_filename': row['original_filename'],
                'stored_filename': row['stored_filename'],
                'file_size': row['file_size'],
                'file_hash': row['file_hash'],
                'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                'download_count': row['download_count'],
                'classification': row['classification'],
                'detected_mime': row['detected_mime'],
                'current_otp_code': decrypted_otp,  # Return decrypted OTP
                'otp_generated_at': row['otp_generated_at'].isoformat() if row['otp_generated_at'] else None,
                'otp_expires_at': row['otp_expires_at'].isoformat() if row['otp_expires_at'] else None,
                'otp_used': bool(row['otp_used']),
                'is_archived': bool(row.get('is_archived', False)),
                'scan_status': row.get('scan_status'),
                'vt_analysis_id': row.get('vt_analysis_id'),
                'uploaded_by': row.get('uploaded_by'),
                'access_logs': access_logs
            }

            if include_content and 'file_content' in row:
                # Decrypt file content
                encrypted_content = row['file_content']
                result['file_content'] = decrypt_file(encrypted_content) if encrypted_content else None

            return result
        except Error as e:
            print(f"Error fetching file metadata: {e}")
            return None
        finally:
            cursor.close()

    def save_file_metadata(self, file_id, metadata, file_content=None):
        """Save or update file metadata with encryption"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            upload_time = datetime.fromisoformat(metadata['upload_time']) if isinstance(metadata['upload_time'], str) else metadata['upload_time']
            otp_generated_at = datetime.fromisoformat(metadata['otp_generated_at']) if isinstance(metadata.get('otp_generated_at'), str) else metadata.get('otp_generated_at')
            otp_expires_at = datetime.fromisoformat(metadata['otp_expires_at']) if isinstance(metadata.get('otp_expires_at'), str) else metadata.get('otp_expires_at')

            # Encrypt OTP code before storing
            otp_code = metadata.get('current_otp_code')
            encrypted_otp = encrypt_otp(otp_code) if otp_code else None

            # Encrypt file content before storing
            encrypted_content = encrypt_file(file_content) if file_content is not None else None

            if file_content is not None:
                cursor.execute("""
                    INSERT INTO file_metadata
                    (file_id, original_filename, stored_filename, file_size, file_hash,
                     upload_time, download_count, classification, detected_mime,
                     current_otp_code, otp_generated_at, otp_expires_at, otp_used,
                     scan_status, vt_analysis_id, vt_scan_method, upload_ip, uploaded_by, file_content)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    scan_status = VALUES(scan_status),
                    vt_analysis_id = VALUES(vt_analysis_id),
                    vt_scan_method = VALUES(vt_scan_method),
                    upload_ip = VALUES(upload_ip),
                    uploaded_by = VALUES(uploaded_by),
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
                    encrypted_otp,  # Store encrypted OTP
                    otp_generated_at,
                    otp_expires_at,
                    metadata.get('otp_used', False),
                    metadata.get('scan_status'),
                    metadata.get('vt_analysis_id'),
                    metadata.get('vt_scan_method'),
                    metadata.get('upload_ip'),
                    metadata.get('uploaded_by'),
                    encrypted_content  # Store encrypted file content
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
                    otp_used = %s,
                    scan_status = %s,
                    vt_analysis_id = %s,
                    vt_scan_method = %s,
                    upload_ip = %s
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
                    encrypted_otp,  # Store encrypted OTP
                    otp_generated_at,
                    otp_expires_at,
                    metadata.get('otp_used', False),
                    metadata.get('scan_status'),
                    metadata.get('vt_analysis_id'),
                    metadata.get('vt_scan_method'),
                    metadata.get('upload_ip'),
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
        """Find file by OTP code (decrypts stored OTPs for comparison)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)

            # Get all files with OTP codes and decrypt to compare
            # (Fernet encryption is non-deterministic, so we can't compare encrypted values)
            cursor.execute("""
                SELECT file_id, current_otp_code FROM file_metadata
                WHERE current_otp_code IS NOT NULL
            """)

            rows = cursor.fetchall()
            for row in rows:
                encrypted_otp = row['current_otp_code']
                if encrypted_otp:
                    decrypted_otp = decrypt_otp(encrypted_otp)
                    if decrypted_otp == otp_code:
                        return row['file_id']

            return None
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
        """Update OTP information for a file (encrypts OTP before storing)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            # Encrypt OTP before storing
            encrypted_otp = encrypt_otp(otp_code) if otp_code else None

            cursor.execute("""
                UPDATE file_metadata
                SET current_otp_code = %s,
                    otp_generated_at = %s,
                    otp_expires_at = %s,
                    otp_used = %s
                WHERE file_id = %s
            """, (encrypted_otp, generated_at, expires_at, otp_used, file_id))

            self.connection.commit()
            return True
        except Error as e:
            print(f"Error updating OTP: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def log_virus_scan(self, file_id, filename, file_size, file_hash, scan_status,
                       malicious_count=0, suspicious_count=0, scan_details=None, ip_address=None):
        """Log a virus scan result (both successful and failed)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO virus_scan_logs
                (timestamp, file_id, original_filename, file_size, file_hash,
                 scan_status, malicious_count, suspicious_count, scan_details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datetime.now(),
                file_id,
                filename,
                file_size,
                file_hash,
                scan_status,
                malicious_count,
                suspicious_count,
                scan_details,
                ip_address
            ))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error logging virus scan: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def get_virus_scan_logs(self, limit=100):
        """Get recent virus scan logs"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT * FROM virus_scan_logs
                ORDER BY timestamp DESC
                LIMIT %s
            """, (limit,))
            logs = cursor.fetchall()
            return [
                {
                    'id': log['id'],
                    'timestamp': log['timestamp'].isoformat() if log['timestamp'] else None,
                    'file_id': log['file_id'],
                    'original_filename': log['original_filename'],
                    'file_size': log['file_size'],
                    'file_hash': log['file_hash'],
                    'scan_status': log['scan_status'],
                    'malicious_count': log['malicious_count'],
                    'suspicious_count': log['suspicious_count'],
                    'scan_details': log['scan_details'],
                    'ip_address': log['ip_address']
                }
                for log in logs
            ]
        except Error as e:
            print(f"Error fetching virus scan logs: {e}")
            return []
        finally:
            cursor.close()

    def log_failed_upload(self, filename, file_size, file_hash, detected_mime,
                          failure_reason, failure_details, ip_address, classification=None):
        """Log a failed upload attempt (without storing file content)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO failed_upload_logs
                (timestamp, original_filename, file_size, file_hash, detected_mime,
                 failure_reason, failure_details, ip_address, classification)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datetime.now(),
                filename,
                file_size,
                file_hash,
                detected_mime,
                failure_reason,
                failure_details,
                ip_address,
                classification
            ))
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error logging failed upload: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def get_failed_upload_logs(self, limit=100):
        """Get recent failed upload logs"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT * FROM failed_upload_logs
                ORDER BY timestamp DESC
                LIMIT %s
            """, (limit,))
            logs = cursor.fetchall()
            return [
                {
                    'id': log['id'],
                    'timestamp': log['timestamp'].isoformat() if log['timestamp'] else None,
                    'original_filename': log['original_filename'],
                    'file_size': log['file_size'],
                    'file_hash': log['file_hash'],
                    'detected_mime': log['detected_mime'],
                    'failure_reason': log['failure_reason'],
                    'failure_details': log['failure_details'],
                    'ip_address': log['ip_address'],
                    'classification': log['classification']
                }
                for log in logs
            ]
        except Error as e:
            print(f"Error fetching failed upload logs: {e}")
            return []
        finally:
            cursor.close()

    def update_scan_status(self, file_id, scan_status, **kwargs):
        """
        Update virus scan status for a file
        
        Args:
            file_id: File ID
            scan_status: 'clean', 'pending', 'malicious', 'error'
            **kwargs: Additional fields to update (vt_analysis_id, malicious_count, etc.)
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            
            # Build UPDATE query dynamically based on kwargs
            updates = ['scan_status = %s']
            params = [scan_status]
            
            if 'vt_analysis_id' in kwargs:
                updates.append('vt_analysis_id = %s')
                params.append(kwargs['vt_analysis_id'])
            
            if 'vt_scan_method' in kwargs:
                updates.append('vt_scan_method = %s')
                params.append(kwargs['vt_scan_method'])
            
            if 'malicious_count' in kwargs:
                updates.append('vt_malicious_count = %s')
                params.append(kwargs['malicious_count'])
            
            if 'suspicious_count' in kwargs:
                updates.append('vt_suspicious_count = %s')
                params.append(kwargs['suspicious_count'])
            
            if 'total_engines' in kwargs:
                updates.append('vt_total_engines = %s')
                params.append(kwargs['total_engines'])
            
            if 'scan_completed_at' in kwargs:
                completed_at = kwargs['scan_completed_at']
                if isinstance(completed_at, str):
                    completed_at = datetime.fromisoformat(completed_at)
                updates.append('vt_scan_completed_at = %s')
                params.append(completed_at)
            
            if 'scan_error' in kwargs:
                updates.append('vt_scan_error = %s')
                params.append(kwargs['scan_error'])
            
            params.append(file_id)
            
            query = f"UPDATE file_metadata SET {', '.join(updates)} WHERE file_id = %s"
            cursor.execute(query, params)
            
            self.connection.commit()
            return True
        except Error as e:
            print(f"Error updating scan status: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()
    
    def get_files_by_scan_status(self, status):
        """
        Get all files with given scan_status
        
        Args:
            status: 'pending', 'clean', 'malicious', 'error'
            
        Returns:
            dict: {file_id: metadata} for matching files
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT file_id, original_filename, file_size, file_hash,
                       vt_analysis_id, vt_scan_method, upload_ip,
                       upload_time, scan_status
                FROM file_metadata
                WHERE scan_status = %s
            """, (status,))
            
            rows = cursor.fetchall()
            
            result = {}
            for row in rows:
                result[row['file_id']] = {
                    'original_filename': row['original_filename'],
                    'file_size': row['file_size'],
                    'file_hash': row['file_hash'],
                    'vt_analysis_id': row['vt_analysis_id'],
                    'vt_scan_method': row['vt_scan_method'],
                    'upload_ip': row['upload_ip'],
                    'upload_time': row['upload_time'].isoformat() if row['upload_time'] else None,
                    'scan_status': row['scan_status']
                }
            
            return result
        except Error as e:
            print(f"Error fetching files by scan status: {e}")
            return {}
        finally:
            cursor.close()
    
    def delete_file(self, file_id):
        """
        Completely delete a file (for malicious files)
        This removes all metadata and file content
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            
            # Foreign key constraints will cascade delete access_logs
            cursor.execute("DELETE FROM file_metadata WHERE file_id = %s", (file_id,))
            
            self.connection.commit()
            print(f"[DB] Deleted file {file_id}")
            return True
        except Error as e:
            print(f"Error deleting file: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    # ============================================
    # Approval Request Methods (Classified Files)
    # ============================================

    def create_approval_request(self, file_id, requester_id, owner_id, requester_ip):
        """
        Create a new approval request for Classified file access
        Returns request_id on success, None on failure
        """
        import secrets
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            request_id = secrets.token_urlsafe(16)
            created_at = datetime.now()
            expires_at = created_at + timedelta(minutes=5)

            cursor.execute("""
                INSERT INTO approval_requests
                (request_id, file_id, requester_user_id, owner_user_id, status,
                 created_at, expires_at, requester_ip)
                VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s)
            """, (request_id, file_id, requester_id, owner_id, created_at, expires_at, requester_ip))

            self.connection.commit()
            print(f"[DB] Created approval request {request_id} for file {file_id}", flush=True)
            return request_id
        except Error as e:
            print(f"[DB] Error creating approval request: {e}", flush=True)
            import traceback
            traceback.print_exc()
            self.connection.rollback()
            return None
        finally:
            cursor.close()

    def get_approval_request(self, request_id):
        """Get an approval request by request_id"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            print(f"[DB] get_approval_request: request_id={request_id}", flush=True)

            cursor.execute("""
                SELECT * FROM approval_requests WHERE request_id = %s
            """, (request_id,))

            row = cursor.fetchone()
            print(f"[DB] get_approval_request: row={row}", flush=True)
            if not row:
                return None

            return {
                'id': row['id'],
                'request_id': row['request_id'],
                'file_id': row['file_id'],
                'requester_user_id': row['requester_user_id'],
                'owner_user_id': row['owner_user_id'],
                'status': row['status'],
                'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                'expires_at': row['expires_at'].isoformat() if row['expires_at'] else None,
                'responded_at': row['responded_at'].isoformat() if row['responded_at'] else None,
                'requester_ip': row['requester_ip']
            }
        except Error as e:
            print(f"[DB] Error fetching approval request: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return None
        finally:
            if cursor:
                cursor.close()

    def get_pending_approvals_for_owner(self, owner_user_id):
        """Get all pending approval requests for a file owner"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)

            # First, expire old requests
            self.expire_old_requests()

            cursor.execute("""
                SELECT ar.*, fm.original_filename, fm.file_size, fm.classification
                FROM approval_requests ar
                JOIN file_metadata fm ON ar.file_id = fm.file_id
                WHERE ar.owner_user_id = %s AND ar.status = 'pending'
                ORDER BY ar.created_at DESC
            """, (owner_user_id,))

            rows = cursor.fetchall()
            results = []

            for row in rows:
                expires_at = row['expires_at']
                time_remaining = ''
                if expires_at:
                    remaining = (expires_at - datetime.now()).total_seconds()
                    if remaining > 0:
                        minutes = int(remaining // 60)
                        seconds = int(remaining % 60)
                        time_remaining = f"{minutes}:{seconds:02d}"
                    else:
                        time_remaining = "Expired"

                results.append({
                    'request_id': row['request_id'],
                    'file_id': row['file_id'],
                    'filename': row['original_filename'],
                    'file_size': row['file_size'],
                    'classification': row['classification'],
                    'requester_user_id': row['requester_user_id'],
                    'requester_ip': row['requester_ip'],
                    'created_at': row['created_at'].strftime('%Y-%m-%d %H:%M:%S') if row['created_at'] else None,
                    'time_remaining': time_remaining
                })

            return results
        except Error as e:
            print(f"Error fetching pending approvals: {e}")
            return []
        finally:
            cursor.close()

    def get_approval_history_for_owner(self, owner_user_id, limit=50):
        """Get past (non-pending) approval requests for a file owner"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)

            cursor.execute("""
                SELECT ar.*, fm.original_filename, fm.file_size, fm.classification
                FROM approval_requests ar
                JOIN file_metadata fm ON ar.file_id = fm.file_id
                WHERE ar.owner_user_id = %s AND ar.status != 'pending'
                ORDER BY ar.responded_at DESC, ar.created_at DESC
                LIMIT %s
            """, (owner_user_id, limit))

            rows = cursor.fetchall()
            results = []

            for row in rows:
                results.append({
                    'request_id': row['request_id'],
                    'file_id': row['file_id'],
                    'filename': row['original_filename'],
                    'file_size': row['file_size'],
                    'classification': row['classification'],
                    'requester_user_id': row['requester_user_id'],
                    'requester_ip': row['requester_ip'],
                    'status': row['status'],
                    'created_at': row['created_at'].strftime('%Y-%m-%d %H:%M:%S') if row['created_at'] else None,
                    'responded_at': row['responded_at'].strftime('%Y-%m-%d %H:%M:%S') if row['responded_at'] else None
                })

            return results
        except Error as e:
            print(f"Error fetching approval history: {e}")
            return []
        finally:
            cursor.close()

    def get_approval_history_for_requester(self, requester_user_id, limit=50):
        """Get past approval requests made by a user"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)

            cursor.execute("""
                SELECT ar.*, fm.original_filename, fm.file_size, fm.classification
                FROM approval_requests ar
                JOIN file_metadata fm ON ar.file_id = fm.file_id
                WHERE ar.requester_user_id = %s
                ORDER BY ar.created_at DESC
                LIMIT %s
            """, (requester_user_id, limit))

            rows = cursor.fetchall()
            results = []

            for row in rows:
                results.append({
                    'request_id': row['request_id'],
                    'file_id': row['file_id'],
                    'filename': row['original_filename'],
                    'file_size': row['file_size'],
                    'classification': row['classification'],
                    'owner_user_id': row['owner_user_id'],
                    'status': row['status'],
                    'created_at': row['created_at'].strftime('%Y-%m-%d %H:%M:%S') if row['created_at'] else None,
                    'responded_at': row['responded_at'].strftime('%Y-%m-%d %H:%M:%S') if row['responded_at'] else None
                })

            return results
        except Error as e:
            print(f"Error fetching requester history: {e}")
            return []
        finally:
            cursor.close()

    def update_approval_status(self, request_id, status):
        """Update the status of an approval request (approve/deny)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            cursor.execute("""
                UPDATE approval_requests
                SET status = %s, responded_at = %s
                WHERE request_id = %s AND status = 'pending'
            """, (status, datetime.now(), request_id))

            self.connection.commit()
            updated = cursor.rowcount > 0
            if updated:
                print(f"[DB] Updated approval request {request_id} to {status}")
            return updated
        except Error as e:
            print(f"Error updating approval status: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def expire_old_requests(self):
        """Mark expired approval requests (older than 5 minutes)"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            cursor.execute("""
                UPDATE approval_requests
                SET status = 'expired'
                WHERE status = 'pending' AND expires_at < %s
            """, (datetime.now(),))

            self.connection.commit()
            expired_count = cursor.rowcount
            if expired_count > 0:
                print(f"[DB] Expired {expired_count} old approval requests")
            return expired_count
        except Error as e:
            print(f"Error expiring old requests: {e}")
            self.connection.rollback()
            return 0
        finally:
            cursor.close()

    def get_pending_approval_count(self, owner_user_id):
        """Get count of pending approval requests for badge display"""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()

            # Expire old requests first
            self.expire_old_requests()

            cursor.execute("""
                SELECT COUNT(*) FROM approval_requests
                WHERE owner_user_id = %s AND status = 'pending'
            """, (owner_user_id,))

            count = cursor.fetchone()[0]
            return count
        except Error as e:
            print(f"Error counting pending approvals: {e}")
            return 0
        finally:
            cursor.close()

    # ============================================
    # Forensic Watermark Methods
    # ============================================

    def store_watermark(self, watermark_id: str, file_id: str,
                        original_file_hash: str, watermarked_hash: str,
                        download_timestamp, encrypted_payload: bytes) -> bool:
        """
        Persist an encrypted forensic watermark for a download event.

        watermarked_hash  — SHA-256 of the file WITH the watermark embedded.
                            Unique per download; used for exact forensic lookup.
        original_file_hash — SHA-256 of the raw original file (links to file_metadata).
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            if isinstance(encrypted_payload, bytes):
                encrypted_payload = encrypted_payload.decode('utf-8')
            if isinstance(download_timestamp, str):
                download_timestamp = datetime.fromisoformat(download_timestamp)
            cursor.execute("""
                INSERT INTO download_watermarks
                    (watermark_id, file_id, original_file_hash, watermarked_hash,
                     download_timestamp, encrypted_payload)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (watermark_id, file_id, original_file_hash, watermarked_hash,
                  download_timestamp, encrypted_payload))
            self.connection.commit()
            return True
        except Error as e:
            print(f"[DB] Error storing watermark: {e}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()

    def get_watermark_by_watermarked_hash(self, watermarked_hash: str) -> dict | None:
        """
        Look up the single watermark whose watermarked_hash matches exactly.
        Each watermarked_hash is unique to one download event / one user.
        Returns None if not found.
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT watermark_id, file_id, original_file_hash, watermarked_hash,
                       download_timestamp, encrypted_payload
                FROM download_watermarks
                WHERE watermarked_hash = %s
                LIMIT 1
            """, (watermarked_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'watermark_id':       row['watermark_id'],
                'file_id':            row['file_id'],
                'original_file_hash': row['original_file_hash'],
                'watermarked_hash':   row['watermarked_hash'],
                'download_timestamp': row['download_timestamp'].isoformat() if row['download_timestamp'] else None,
                'encrypted_payload':  row['encrypted_payload'],
            }
        except Error as e:
            print(f"[DB] Error fetching watermark by watermarked hash: {e}")
            return None
        finally:
            cursor.close()

    def get_watermarks_for_file(self, file_id: str) -> list:
        """Return all watermark rows for a given file_id (admin view)."""
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT watermark_id, file_id, original_file_hash, watermarked_hash,
                       download_timestamp, encrypted_payload
                FROM download_watermarks
                WHERE file_id = %s
                ORDER BY download_timestamp DESC
            """, (file_id,))
            rows = cursor.fetchall()
            return [
                {
                    'watermark_id':       r['watermark_id'],
                    'file_id':            r['file_id'],
                    'original_file_hash': r['original_file_hash'],
                    'watermarked_hash':   r['watermarked_hash'],
                    'download_timestamp': r['download_timestamp'].isoformat() if r['download_timestamp'] else None,
                    'encrypted_payload':  r['encrypted_payload'],
                }
                for r in rows
            ]
        except Error as e:
            print(f"[DB] Error fetching watermarks for file: {e}")
            return []
        finally:
            cursor.close()

    def lookup_file_by_hash(self, file_hash: str) -> dict | None:
        """
        Check if a file with the given SHA-256 hash exists in file_metadata.
        Returns basic file info dict or None.
        """
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute("""
                SELECT file_id, original_filename, file_size, file_hash,
                       upload_time, classification, scan_status, is_archived,
                       uploaded_by, download_count
                FROM file_metadata
                WHERE file_hash = %s
                LIMIT 1
            """, (file_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
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
        except Error as e:
            print(f"[DB] Error looking up file by hash: {e}")
            return None
        finally:
            cursor.close()

    def store_ml_analysis(self, file_id, trust_score, risk_level, risk_signals,
                          features, anomaly_score):
        """Store ML trust-score analysis results for a file."""
        import json as _json
        cursor = None
        try:
            self.ensure_connection()
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO file_ml_analysis
                    (file_id, trust_score, risk_level, risk_signals, features,
                     anomaly_score, analyzed_at, model_version)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    trust_score   = VALUES(trust_score),
                    risk_level    = VALUES(risk_level),
                    risk_signals  = VALUES(risk_signals),
                    features      = VALUES(features),
                    anomaly_score = VALUES(anomaly_score),
                    analyzed_at   = VALUES(analyzed_at)
            """, (
                file_id,
                int(trust_score),
                risk_level,
                _json.dumps(risk_signals),
                _json.dumps(features),
                float(anomaly_score) if anomaly_score is not None else None,
                datetime.now(),
                '1.0',
            ))
            self.connection.commit()
        except Error as e:
            print(f"Error storing ML analysis: {e}")
            raise
        finally:
            if cursor:
                cursor.close()

    def get_ml_analysis(self, file_id) -> dict | None:
        """Return the ML analysis record for a file, or None if not found."""
        import json as _json
        cursor = None
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(
                "SELECT * FROM file_ml_analysis WHERE file_id = %s", (file_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'file_id': row['file_id'],
                'trust_score': row['trust_score'],
                'risk_level': row['risk_level'],
                'risk_signals': _json.loads(row['risk_signals']) if row['risk_signals'] else [],
                'features': _json.loads(row['features']) if row['features'] else {},
                'anomaly_score': row['anomaly_score'],
                'analyzed_at': row['analyzed_at'].isoformat() if row['analyzed_at'] else None,
                'model_version': row['model_version'],
            }
        except Error as e:
            print(f"Error fetching ML analysis: {e}")
            return None
        finally:
            if cursor:
                cursor.close()

    def get_all_ml_features(self) -> list:
        """Return all {file_id, features, trust_score} rows for IsolationForest training."""
        import json as _json
        cursor = None
        try:
            self.ensure_connection()
            cursor = self.connection.cursor(dictionary=True, buffered=True)
            cursor.execute(
                "SELECT file_id, features, trust_score FROM file_ml_analysis"
            )
            rows = cursor.fetchall()
            result = []
            for row in rows:
                try:
                    features = _json.loads(row['features']) if row['features'] else {}
                except Exception:
                    features = {}
                result.append({
                    'file_id': row['file_id'],
                    'features': features,
                    'trust_score': row['trust_score'],
                })
            return result
        except Error as e:
            print(f"Error fetching ML features: {e}")
            return []
        finally:
            if cursor:
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
