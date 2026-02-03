import os
import secrets
import string
import time
import requests as http_requests  # Renamed to avoid conflict with flask.request
from datetime import datetime, timedelta
from flask import Blueprint, Flask, render_template, request, send_file, redirect, url_for, flash, jsonify, session, current_app
from werkzeug.utils import secure_filename
import hashlib
import json
import magic
import pyotp
from functools import wraps

# ============================================
# User Model Import (for MFA verification)
# ============================================
def get_user_model():
    """Lazy import of User model from auth app"""
    from app.models import User
    return User

# Create Blueprint
bp = Blueprint('filetransfer', __name__,
               template_folder='templates',
               static_folder='styles',
               static_url_path='/filetransfer/styles')

def csrf_exempt_view(f):
    """Mark a view as exempt from CSRF protection"""
    f.csrf_exempt = True
    return f

# ============================================
# Login Required Decorator
# ============================================
def login_required(f):
    """Decorator to require login for FileTransfer routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"[login_required] Checking session for {f.__name__}", flush=True)
        print(f"[login_required] Session keys: {list(session.keys())}", flush=True)
        print(f"[login_required] user_id in session: {'user_id' in session}", flush=True)
        if 'user_id' not in session:
            print(f"[login_required] No user_id, redirecting to login", flush=True)
            flash('Please login to access the file transfer system', 'error')
            return redirect(url_for('main.login'))
        print(f"[login_required] User authenticated, proceeding", flush=True)
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# Lazy Initialization
# ============================================
_db = None
_vt_service = None

def get_db():
    """Get database connection (lazy initialization)"""
    global _db
    if _db is None:
        from db import get_db as _get_db
        _db = _get_db()
    return _db

def get_vt_service():
    """Get VirusTotal service (lazy initialization)"""
    global _vt_service
    if _vt_service is None:
        from virustotal_service import VirusTotalService
        _vt_service = VirusTotalService(
            api_key=os.environ.get('VIRUSTOTAL_API_KEY', ''),
            timeout=int(os.environ.get('VIRUSTOTAL_TIMEOUT', 60)),
            enabled=os.environ.get('VIRUSTOTAL_ENABLED', 'true').lower() == 'true'
        )
    return _vt_service

# ============================================
# Configuration
# ============================================
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
    'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz',
    'mp3', 'mp4', 'avi', 'mkv', 'mov', 'csv', 'json', 'xml'
}

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_expected_mime_types(extension):
    """
    Map file extensions to their expected MIME types
    Returns a list of acceptable MIME types for the given extension
    """
    mime_type_map = {
        'txt': ['text/plain', 'text/x-c', 'text/x-c++', 'text/x-python', 'application/octet-stream'],
        'pdf': ['application/pdf'],
        'png': ['image/png'],
        'jpg': ['image/jpeg'],
        'jpeg': ['image/jpeg'],
        'gif': ['image/gif'],
        'doc': ['application/msword', 'application/x-ole-storage'],
        'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
        'xls': ['application/vnd.ms-excel', 'application/x-ole-storage'],
        'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        'ppt': ['application/vnd.ms-powerpoint', 'application/x-ole-storage'],
        'pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
        'zip': ['application/zip', 'application/x-zip-compressed'],
        'rar': ['application/x-rar', 'application/x-rar-compressed'],
        '7z': ['application/x-7z-compressed'],
        'tar': ['application/x-tar'],
        'gz': ['application/gzip', 'application/x-gzip'],
        'mp3': ['audio/mpeg', 'audio/mp3'],
        'mp4': ['video/mp4'],
        'avi': ['video/x-msvideo', 'video/avi'],
        'mkv': ['video/x-matroska', 'application/octet-stream'],
        'mov': ['video/quicktime'],
        'csv': ['text/csv', 'text/plain', 'application/csv'],
        'json': ['application/json', 'text/plain'],
        'xml': ['application/xml', 'text/xml', 'text/plain']
    }
    return mime_type_map.get(extension.lower(), [])

def validate_file_magic_bytes(file_path, claimed_extension):
    """
    Validate file using magic bytes to prevent file type spoofing

    Args:
        file_path: Path to the uploaded file
        claimed_extension: The file extension from the filename

    Returns:
        tuple: (is_valid: bool, error_message: str, detected_mime: str)
    """
    try:
        # Detect actual MIME type using magic bytes
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_file(file_path)

        # Get expected MIME types for the claimed extension
        expected_mimes = get_expected_mime_types(claimed_extension)

        if not expected_mimes:
            return False, f'Unknown file extension: {claimed_extension}', detected_mime

        # Check for dangerous executable types that should never be allowed
        dangerous_mimes = [
            'application/x-executable',
            'application/x-dosexec',
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-mach-binary',
            'application/x-elf',
            'application/x-sharedlib',
            'application/vnd.microsoft.portable-executable'
        ]

        if detected_mime in dangerous_mimes:
            return False, f'Executable files are not allowed (detected: {detected_mime})', detected_mime

        # Check if detected MIME type matches the claimed extension
        if detected_mime not in expected_mimes:
            return False, f'File type mismatch: file appears to be {detected_mime} but has .{claimed_extension} extension', detected_mime

        return True, None, detected_mime

    except Exception as e:
        return False, f'Error validating file type: {str(e)}', 'unknown'

def generate_unique_id():
    """Generate a unique file identifier"""
    return secrets.token_urlsafe(16)

def get_file_hash(filepath):
    """Generate SHA256 hash of file for integrity verification"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

def generate_otp_code():
    """
    Generate a secure 16-character OTP code with mixed case alphanumeric characters
    Format: aB3x9K2pQ7mN4sT1 (no dashes for security)
    """
    characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    return ''.join(secrets.choice(characters) for _ in range(16))

def validate_otp(file_id, provided_code):
    """
    Validate OTP code for a file
    Checks: code correctness, expiration (24 hours), and usage status
    Returns: (bool, str, dict) - (valid, error_message, file_info)
    """
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return False, 'File not found', None

    # Check if OTP exists
    if 'current_otp_code' not in file_info or not file_info.get('current_otp_code'):
        return False, 'No access code available for this file', None

    # Check if code matches (case-sensitive)
    if file_info['current_otp_code'] != provided_code:
        # Log failed attempt
        log_access_attempt(file_id, 'failed', 'Invalid code entered')
        return False, 'Invalid access code', None

    # Check if code has expired (24 hours)
    expires_at = datetime.fromisoformat(file_info['otp_expires_at'])
    if datetime.now() > expires_at:
        return False, 'Access code has expired', None

    # Check if code has already been used
    if file_info.get('otp_used', False):
        return False, 'Access code has already been used', None

    return True, None, file_info

def log_access_attempt(file_id, status, details='', ip_address=None):
    """
    Log an access attempt to a file
    status: 'success', 'failed', 'claimed'
    """
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return

    db.add_access_log(
        file_id,
        status,
        details,
        ip_address or request.remote_addr
    )

def regenerate_otp(file_id):
    """
    Generate a new OTP code for a file
    Used after download or manual regeneration by owner
    """
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return None

    new_code = generate_otp_code()
    generated_at = datetime.now()
    expires_at = generated_at + timedelta(hours=24)

    db.update_otp(file_id, new_code, generated_at, expires_at, otp_used=False)
    return new_code

def authenticate_public_access(file_id):
    """
    Placeholder: Authentication for Public classified files
    Public files require no authentication
    Returns: (bool, str) - (success, error_message)
    """
    # TODO: Implement actual public access logic
    return True, None

def authenticate_internal_access(file_id):
    """
    Placeholder: Authentication for Internal Use classified files
    Internal files require basic authentication (e.g., login required)
    Returns: (bool, str) - (success, error_message)
    """
    # TODO: Implement actual internal access authentication
    # Example: Check if user is logged in, verify session, etc.
    return True, None

def authenticate_classified_access(file_id):
    """
    Placeholder: Authentication for Classified files
    Classified files require high-level authentication (e.g., 2FA, special permissions)
    Returns: (bool, str) - (success, error_message)
    """
    # TODO: Implement actual classified access authentication
    # Example: Check user role, verify 2FA, check special permissions, audit log, etc.
    return True, None

def verify_access_by_classification(file_id, classification):
    """
    Verify access based on file classification level
    Routes to appropriate authentication function
    Returns: (bool, str) - (success, error_message)
    """
    if classification == 'Public':
        return authenticate_public_access(file_id)
    elif classification == 'Internal Use':
        return authenticate_internal_access(file_id)
    elif classification == 'Classified':
        return authenticate_classified_access(file_id)
    else:
        return False, 'Invalid classification level'

# ============================================
# Routes
# ============================================

@bp.route('/')
@login_required
def index():
    """Main page - upload interface"""
    return render_template('filetransfer/index.html')

@bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file upload"""
    print(f"[Upload] Request received", flush=True)
    print(f"[Upload] Request files: {request.files}", flush=True)
    print(f"[Upload] Request form: {request.form}", flush=True)

    db = get_db()
    vt_service = get_vt_service()

    if 'file' not in request.files:
        print(f"[Upload] ERROR: No file in request.files", flush=True)
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    # Get data classification from request
    classification = request.form.get('classification', 'Public')

    # Validate classification
    valid_classifications = ['Public', 'Internal Use', 'Classified']
    if classification not in valid_classifications:
        classification = 'Public'

    try:
        # Generate unique ID and secure filename
        file_id = generate_unique_id()
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f"{file_id}.{file_extension}"

        # Read file content into memory
        file_content = file.read()
        file_size = len(file_content)

        # Create temporary file for magic byte validation
        import tempfile
        temp_fd, temp_path = tempfile.mkstemp(suffix=f'.{file_extension}')
        try:
            os.write(temp_fd, file_content)
            os.close(temp_fd)

            # Validate file using magic bytes
            is_valid, error_msg, detected_mime = validate_file_magic_bytes(temp_path, file_extension)

            # Calculate hash early for logging purposes
            file_hash = hashlib.sha256(file_content).hexdigest()

            if not is_valid:
                # Log the failed upload (magic byte validation failed)
                db.log_failed_upload(
                    filename=original_filename,
                    file_size=file_size,
                    file_hash=file_hash,
                    detected_mime=detected_mime,
                    failure_reason='magic_byte_validation',
                    failure_details=error_msg,
                    ip_address=request.remote_addr,
                    classification=classification
                )
                return jsonify({'error': error_msg}), 400

            # VirusTotal hybrid scan (hash lookup + async)
            print(f"[Upload] Starting VT hybrid scan for {original_filename}", flush=True)
            scan_result = vt_service.scan_file_async_start(
                file_content,
                original_filename,
                file_hash
            )

            # Handle immediate results (hash lookup success or error)
            if scan_result['immediate_result']:
                if not scan_result['passed']:
                    # File is malicious or scan error - reject immediately
                    print(f"[Upload] File rejected: {scan_result.get('error', 'malicious')}", flush=True)

                    # Log the failed upload
                    db.log_failed_upload(
                        filename=original_filename,
                        file_size=file_size,
                        file_hash=file_hash,
                        detected_mime=detected_mime,
                        failure_reason='virustotal_malicious',
                        failure_details=f"Flagged by {scan_result['malicious_count']} vendors ({scan_result['scan_method']})",
                        ip_address=request.remote_addr,
                        classification=classification
                    )

                    # Log to virus scan logs
                    db.log_virus_scan(
                        file_id=None,
                        filename=original_filename,
                        file_size=file_size,
                        file_hash=file_hash,
                        scan_status='failed',
                        malicious_count=scan_result['malicious_count'],
                        suspicious_count=scan_result['suspicious_count'],
                        scan_details=f"Hash lookup - Flagged by {scan_result['malicious_count']} vendors",
                        ip_address=request.remote_addr
                    )

                    return jsonify({
                        'error': 'File upload failed: File is suspected to be malicious',
                        'error_type': 'malicious_file'
                    }), 400
                else:
                    # File is clean (from hash lookup)
                    print(f"[Upload] File clean via hash lookup ({scan_result['scan_method']})", flush=True)
                    scan_status = 'clean'
                    vt_scan_method = scan_result['scan_method']
                    vt_analysis_id = None
                    vt_malicious = scan_result['malicious_count']
                    vt_suspicious = scan_result['suspicious_count']
                    vt_total = scan_result['total_engines']
            else:
                # File needs async scan - upload and queue for background processing
                print(f"[Upload] File needs async scan - queuing (ID: {scan_result['analysis_id']})", flush=True)
                scan_status = 'pending'
                vt_scan_method = 'full_scan'
                vt_analysis_id = scan_result['analysis_id']
                vt_malicious = 0
                vt_suspicious = 0
                vt_total = 0

            upload_time = datetime.now().isoformat()

            # Generate OTP code
            otp_code = generate_otp_code()
            otp_generated = datetime.now()
            otp_expires = otp_generated + timedelta(hours=24)

            # Store metadata and file content in database
            metadata = {
                'original_filename': original_filename,
                'stored_filename': stored_filename,
                'file_size': file_size,
                'file_hash': file_hash,
                'upload_time': upload_time,
                'download_count': 0,
                'classification': classification,
                'detected_mime': detected_mime,
                'current_otp_code': otp_code,
                'otp_generated_at': otp_generated.isoformat(),
                'otp_expires_at': otp_expires.isoformat(),
                'otp_used': False,
                'scan_status': scan_status,
                'vt_analysis_id': vt_analysis_id,
                'vt_scan_method': vt_scan_method,
                'upload_ip': request.remote_addr
            }

            db.save_file_metadata(file_id, metadata, file_content)

            # Log successful virus scan (only for clean files from hash lookup)
            if scan_status == 'clean':
                db.log_virus_scan(
                    file_id=file_id,
                    filename=original_filename,
                    file_size=file_size,
                    file_hash=file_hash,
                    scan_status='clean',
                    malicious_count=vt_malicious,
                    suspicious_count=vt_suspicious,
                    scan_details=f"Hash lookup - Scanned by {vt_total} engines - No threats detected",
                    ip_address=request.remote_addr
                )

            # Build response with scan info
            response_data = {
                'success': True,
                'file_id': file_id,
                'filename': original_filename,
                'file_size': format_file_size(file_size),
                'expires_at': otp_expires.strftime('%Y-%m-%d %H:%M:%S'),
                'virus_scan': {
                    'status': scan_status,  # 'clean' or 'pending'
                    'method': vt_scan_method,  # 'hash_lookup' or 'full_scan'
                    'total_engines': vt_total,
                    'malicious_count': vt_malicious,
                    'suspicious_count': vt_suspicious
                }
            }

            # Only include OTP code if file is clean (not pending scan)
            if scan_status == 'clean':
                response_data['otp_code'] = otp_code

            return jsonify(response_data)

        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@bp.route('/download')
@login_required
def download_page():
    """Display the download page where users enter OTP code"""
    return render_template('filetransfer/download.html')

@bp.route('/verify-code', methods=['POST'])
@login_required
def verify_code():
    """Verify OTP code and create session for file access"""
    db = get_db()
    data = request.get_json()
    provided_code = data.get('code', '').strip()

    if not provided_code:
        return jsonify({'success': False, 'error': 'Please enter an access code'}), 400

    # Search for file with matching OTP code
    file_id = db.find_file_by_otp(provided_code)

    if not file_id:
        return jsonify({'success': False, 'error': 'Invalid access code'}), 400

    # Validate the OTP
    is_valid, error_msg, file_info = validate_otp(file_id, provided_code)

    if not is_valid:
        return jsonify({'success': False, 'error': error_msg}), 400

    classification = file_info.get('classification', 'Public')

    # Mark code as used and log successful verification
    db.update_otp(
        file_id,
        file_info['current_otp_code'],
        datetime.fromisoformat(file_info['otp_generated_at']),
        datetime.fromisoformat(file_info['otp_expires_at']),
        otp_used=True
    )
    log_access_attempt(file_id, 'verified', f'Access code verified successfully (Classification: {classification})')

    # Check classification - Internal Use requires TOTP verification
    if classification == 'Internal Use':
        # Store partial verification in session (OTP passed, TOTP pending)
        session[f'otp_verified_{file_id}'] = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'totp_verified': False
        }
        return jsonify({
            'success': True,
            'file_id': file_id,
            'filename': file_info['original_filename'],
            'file_size': format_file_size(file_info['file_size']),
            'classification': classification,
            'requires_totp': True  # Signal that TOTP is needed
        })

    # For Public files, grant full access
    session[f'verified_{file_id}'] = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr
    }

    return jsonify({
        'success': True,
        'file_id': file_id,
        'filename': file_info['original_filename'],
        'file_size': format_file_size(file_info['file_size']),
        'classification': classification,
        'requires_totp': False
    })


@bp.route('/verify-totp', methods=['POST'])
@login_required
def verify_totp():
    """Verify TOTP for Internal Use classified files"""
    data = request.get_json()
    file_id = data.get('file_id', '').strip()
    totp_code = data.get('totp_code', '').strip()

    if not file_id or not totp_code:
        return jsonify({'success': False, 'error': 'File ID and TOTP code are required'}), 400

    # Check if OTP was already verified for this file
    otp_session = session.get(f'otp_verified_{file_id}')
    if not otp_session:
        return jsonify({'success': False, 'error': 'Please verify the access code first'}), 400

    # Get the user's MFA secret
    User = get_user_model()
    user = User.query.get(session['user_id'])

    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 400

    if not user.mfa_enabled or not user.mfa_secret:
        return jsonify({'success': False, 'error': 'MFA is not enabled for your account. Please enable MFA in settings.'}), 400

    # Verify TOTP code
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(totp_code, valid_window=1):
        log_access_attempt(file_id, 'failed', 'Invalid TOTP code entered')
        return jsonify({'success': False, 'error': 'Invalid authenticator code'}), 400

    # TOTP verified - grant full access
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'success': False, 'error': 'File not found'}), 404

    # Remove partial session and create full access session
    session.pop(f'otp_verified_{file_id}', None)
    session[f'verified_{file_id}'] = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'totp_verified': True
    }

    log_access_attempt(file_id, 'verified', 'TOTP verification successful for Internal Use file')

    return jsonify({
        'success': True,
        'file_id': file_id,
        'filename': file_info['original_filename'],
        'file_size': format_file_size(file_info['file_size']),
        'classification': file_info.get('classification', 'Internal Use')
    })

@bp.route('/file/<file_id>')
@login_required
def file_details(file_id):
    """Display file details page (requires valid session from code verification)"""
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return render_template('filetransfer/error.html',
                             error_message='File not found or link expired'), 404

    # Check if user has verified this file
    if f'verified_{file_id}' not in session:
        # Redirect to download page to enter code
        return redirect(url_for('filetransfer.download_page'))

    file_info['formatted_size'] = format_file_size(file_info['file_size'])
    file_info['file_id'] = file_id

    return render_template('filetransfer/file_details.html', file_info=file_info)

@bp.route('/get-file/<file_id>')
@login_required
def get_file(file_id):
    """Download the actual file (requires valid verification session)"""
    db = get_db()

    # Verify user has verified this file
    if f'verified_{file_id}' not in session:
        return jsonify({'error': 'Access denied. Please enter your access code first.'}), 403

    # Get file metadata from database
    file_info = db.get_file_metadata(file_id, include_content=False)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    # Check scan status - block pending or malicious files
    scan_status = file_info.get('scan_status')

    if scan_status == 'pending':
        return jsonify({
            'error': 'File is still being scanned for viruses. Please try again in a moment.',
            'status': 'pending'
        }), 425  # 425 Too Early

    if scan_status == 'malicious':
        return jsonify({'error': 'File failed security scan'}), 403

    if scan_status == 'error':
        return jsonify({'error': 'File scan encountered an error. Contact support.'}), 500

    # Check if file is archived (content moved to Storage DB)
    file_content = None

    if file_info.get('is_archived', False):
        # File is archived - retrieve from sync service
        print(f"[App] File {file_id} is archived, retrieving from Storage DB via sync service...")

        try:
            response = http_requests.get(f'http://sync-service:8080/retrieve/{file_id}', timeout=30)

            if response.status_code == 200:
                file_content = response.content
                print(f"[App] Successfully retrieved archived file {file_id} ({len(file_content)} bytes)")
            else:
                print(f"[App] Failed to retrieve archived file: {response.status_code}")
                return jsonify({'error': 'Failed to retrieve archived file from storage'}), 500

        except Exception as e:
            print(f"[App] Error retrieving archived file: {e}")
            return jsonify({'error': 'Could not connect to storage service'}), 500
    else:
        # File is in Working DB - get content directly
        file_info_with_content = db.get_file_metadata(file_id, include_content=True)

        if not file_info_with_content or 'file_content' not in file_info_with_content:
            return jsonify({'error': 'File content not found in database'}), 404

        file_content = file_info_with_content['file_content']

    if not file_content:
        return jsonify({'error': 'File content not available'}), 404

    # Log successful download
    log_access_attempt(file_id, 'success', 'File downloaded successfully')

    # Increment download counter
    db.update_download_count(file_id)

    # Clear the session for this file
    session.pop(f'verified_{file_id}', None)

    # Send file from memory
    from io import BytesIO
    return send_file(
        BytesIO(file_content),
        as_attachment=True,
        download_name=file_info['original_filename'],
        mimetype=file_info.get('detected_mime', 'application/octet-stream')
    )

@bp.route('/files')
@login_required
def list_files():
    """List all uploaded files (admin view with OTP codes and access logs)"""
    db = get_db()
    all_metadata = db.get_all_metadata()
    files_list = []

    for file_id, info in all_metadata.items():
        # Calculate time remaining for OTP
        time_remaining = 'Expired'
        if info.get('otp_expires_at'):
            expires_at = datetime.fromisoformat(info['otp_expires_at'])
            if datetime.now() < expires_at:
                delta = expires_at - datetime.now()
                hours = int(delta.total_seconds() // 3600)
                minutes = int((delta.total_seconds() % 3600) // 60)
                time_remaining = f"{hours}h {minutes}m"

        files_list.append({
            'file_id': file_id,
            'filename': info['original_filename'],
            'size': format_file_size(info['file_size']),
            'upload_time': info['upload_time'],
            'downloads': info['download_count'],
            'current_otp': info.get('current_otp_code', 'N/A'),
            'otp_used': info.get('otp_used', False),
            'otp_expires': time_remaining,
            'access_logs': info.get('access_logs', []),
            'classification': info.get('classification', 'Public'),
            'scan_status': info.get('scan_status', 'clean')  # Add scan status
        })


    files_list.sort(key=lambda x: x['upload_time'], reverse=True)
    return render_template('filetransfer/files.html', files=files_list)

@bp.route('/regenerate-otp/<file_id>', methods=['POST'])
@login_required
def regenerate_otp_endpoint(file_id):
    """Manually regenerate OTP code for a file"""
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    # Security check: Don't allow operations on pending or malicious files
    scan_status = file_info.get('scan_status')
    if scan_status == 'pending':
        return jsonify({'error': 'File is currently being scanned for security. Please wait.'}), 425
    if scan_status == 'malicious':
        return jsonify({'error': 'File is flagged as malicious.'}), 403


    new_code = regenerate_otp(file_id)

    if new_code:
        # Get updated file info
        file_info = db.get_file_metadata(file_id)

        # Calculate new expiration time
        expires_at = datetime.fromisoformat(file_info['otp_expires_at'])
        delta = expires_at - datetime.now()
        hours = int(delta.total_seconds() // 3600)
        minutes = int((delta.total_seconds() % 3600) // 60)

        return jsonify({
            'success': True,
            'new_code': new_code,
            'expires_in': f"{hours}h {minutes}m"
        })
    else:
        return jsonify({'error': 'Failed to regenerate code'}), 500

@bp.route('/access-logs/<file_id>')
@login_required
def get_access_logs(file_id):
    """Get access logs for a specific file"""
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    logs = file_info.get('access_logs', [])
    return jsonify({
        'file_id': file_id,
        'filename': file_info['original_filename'],
        'logs': logs
    })

@bp.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file from both Working DB and Storage DB (if archived)"""
    db = get_db()
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    try:
        # Check if file is archived (content moved to Storage DB)
        is_archived = file_info.get('is_archived', False)

        if is_archived:
            # File is archived - delete from Storage DB via sync service
            print(f"[App] File {file_id} is archived, deleting from Storage DB...")

            try:
                response = http_requests.delete(
                    f'http://sync-service:8080/delete/{file_id}',
                    timeout=10
                )

                if response.status_code == 200:
                    print(f"[App] Successfully deleted file {file_id} from Storage DB")
                elif response.status_code == 404:
                    # File not found in Storage DB - log but continue with Working DB deletion
                    print(f"[App] File {file_id} not found in Storage DB (may have already been deleted)")
                else:
                    # Failed to delete from Storage DB
                    print(f"[App] Failed to delete from Storage DB: {response.status_code}")
                    return jsonify({
                        'error': 'Failed to delete archived file from storage',
                        'details': response.json().get('error', 'Unknown error')
                    }), 500

            except http_requests.exceptions.Timeout:
                return jsonify({'error': 'Storage service timeout - file may not have been deleted from storage'}), 504
            except http_requests.exceptions.ConnectionError:
                return jsonify({'error': 'Could not connect to storage service'}), 503
            except Exception as e:
                print(f"[App] Error deleting from Storage DB: {e}")
                return jsonify({'error': f'Storage deletion error: {str(e)}'}), 500

        # Delete from Working DB (metadata and content if not archived)
        db.delete_file_metadata(file_id)

        print(f"[App] Successfully deleted file {file_id} from Working DB")

        return jsonify({
            'success': True,
            'message': 'File deleted successfully',
            'deleted_from_storage': is_archived
        })

    except Exception as e:
        return jsonify({'error': f'Deletion failed: {str(e)}'}), 500

@bp.route('/failed-uploads')
@login_required
def get_failed_uploads():
    """Get failed upload logs (admin view)"""
    db = get_db()
    limit = request.args.get('limit', 100, type=int)
    logs = db.get_failed_upload_logs(limit=limit)

    # Format file sizes for display
    for log in logs:
        if log.get('file_size'):
            log['formatted_size'] = format_file_size(log['file_size'])
        else:
            log['formatted_size'] = 'Unknown'

    return jsonify({
        'count': len(logs),
        'logs': logs
    })

@bp.route('/virus-scan-logs')
@login_required
def get_virus_scan_logs():
    """Get virus scan logs (admin view)"""
    db = get_db()
    limit = request.args.get('limit', 100, type=int)
    logs = db.get_virus_scan_logs(limit=limit)

    # Format file sizes for display
    for log in logs:
        if log.get('file_size'):
            log['formatted_size'] = format_file_size(log['file_size'])
        else:
            log['formatted_size'] = 'Unknown'

    return jsonify({
        'count': len(logs),
        'logs': logs
    })

# ============================================
# Standalone App Support (for testing/development)
# ============================================
if __name__ == '__main__':
    # Create standalone Flask app for testing
    app = Flask(__name__,
                template_folder='templates',
                static_folder='styles',
                static_url_path='/styles')

    app.config['SECRET_KEY'] = secrets.token_hex(32)
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

    # Register blueprint at root for standalone mode
    app.register_blueprint(bp, url_prefix='')

    # Error handlers for standalone mode
    @app.errorhandler(413)
    def too_large(e):
        return render_template('filetransfer/error.html',
                             error_message='File too large. Maximum size is 500MB'), 413

    @app.errorhandler(404)
    def not_found(e):
        return render_template('filetransfer/error.html',
                             error_message='Page not found'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('filetransfer/error.html',
                             error_message='Internal server error'), 500

    app.run(debug=True, host='0.0.0.0', port=5000)
