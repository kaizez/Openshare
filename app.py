import os
import secrets
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename
import hashlib
import json
import magic
from db import get_db

app = Flask(__name__,
            template_folder='templates',
            static_folder='styles',
            static_url_path='/styles')

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['ALLOWED_EXTENSIONS'] = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
    'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', '7z', 'tar', 'gz',
    'mp3', 'mp4', 'avi', 'mkv', 'mov', 'csv', 'json', 'xml'
}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database connection
db = get_db()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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

@app.route('/')
def index():
    """Main page - upload interface"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
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

            if not is_valid:
                return jsonify({'error': error_msg}), 400

            # Calculate hash from content
            file_hash = hashlib.sha256(file_content).hexdigest()
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
                'otp_used': False
            }

            db.save_file_metadata(file_id, metadata, file_content)

            return jsonify({
                'success': True,
                'file_id': file_id,
                'otp_code': otp_code,
                'filename': original_filename,
                'file_size': format_file_size(file_size),
                'expires_at': otp_expires.strftime('%Y-%m-%d %H:%M:%S')
            })

        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/download')
def download_page():
    """Display the download page where users enter OTP code"""
    return render_template('download.html')

@app.route('/verify-code', methods=['POST'])
def verify_code():
    """Verify OTP code and create session for file access"""
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

    # Mark code as used and log successful verification
    db.update_otp(
        file_id,
        file_info['current_otp_code'],
        datetime.fromisoformat(file_info['otp_generated_at']),
        datetime.fromisoformat(file_info['otp_expires_at']),
        otp_used=True
    )
    log_access_attempt(file_id, 'verified', 'Access code verified successfully')

    # Create session for this file
    session[f'verified_{file_id}'] = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr
    }

    return jsonify({
        'success': True,
        'file_id': file_id,
        'filename': file_info['original_filename'],
        'file_size': format_file_size(file_info['file_size']),
        'classification': file_info.get('classification', 'Public')
    })

@app.route('/file/<file_id>')
def file_details(file_id):
    """Display file details page (requires valid session from code verification)"""
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return render_template('error.html',
                             error_message='File not found or link expired'), 404

    # Check if user has verified this file
    if f'verified_{file_id}' not in session:
        # Redirect to download page to enter code
        return redirect(url_for('download_page'))

    file_info['formatted_size'] = format_file_size(file_info['file_size'])
    file_info['file_id'] = file_id

    return render_template('file_details.html', file_info=file_info)

@app.route('/get-file/<file_id>')
def get_file(file_id):
    """Download the actual file (requires valid verification session)"""
    # Verify user has verified this file
    if f'verified_{file_id}' not in session:
        return jsonify({'error': 'Access denied. Please enter your access code first.'}), 403

    # Get file metadata and content from database
    file_info = db.get_file_metadata(file_id, include_content=True)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    if 'file_content' not in file_info:
        return jsonify({'error': 'File content not found in database'}), 404

    # Log successful download
    log_access_attempt(file_id, 'success', 'File downloaded successfully')

    # Increment download counter
    db.update_download_count(file_id)

    # Clear the session for this file
    session.pop(f'verified_{file_id}', None)

    # Send file from memory
    from io import BytesIO
    return send_file(
        BytesIO(file_info['file_content']),
        as_attachment=True,
        download_name=file_info['original_filename'],
        mimetype=file_info.get('detected_mime', 'application/octet-stream')
    )

@app.route('/files')
def list_files():
    """List all uploaded files (admin view with OTP codes and access logs)"""
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
            'classification': info.get('classification', 'Public')
        })

    files_list.sort(key=lambda x: x['upload_time'], reverse=True)
    return render_template('files.html', files=files_list)

@app.route('/regenerate-otp/<file_id>', methods=['POST'])
def regenerate_otp_endpoint(file_id):
    """Manually regenerate OTP code for a file"""
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

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

@app.route('/access-logs/<file_id>')
def get_access_logs(file_id):
    """Get access logs for a specific file"""
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    logs = file_info.get('access_logs', [])
    return jsonify({
        'file_id': file_id,
        'filename': file_info['original_filename'],
        'logs': logs
    })

@app.route('/delete/<file_id>', methods=['POST'])
def delete_file(file_id):
    """Delete a file"""
    file_info = db.get_file_metadata(file_id)

    if not file_info:
        return jsonify({'error': 'File not found'}), 404

    try:
        # Remove from database (file content is also deleted)
        db.delete_file_metadata(file_id)

        return jsonify({'success': True, 'message': 'File deleted successfully'})

    except Exception as e:
        return jsonify({'error': f'Deletion failed: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    return render_template('error.html',
                         error_message='File too large. Maximum size is 500MB'), 413

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('error.html',
                         error_message='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return render_template('error.html',
                         error_message='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
