#!/usr/bin/env python3
"""
MoveIT FileTransfer Security Module

Comprehensive security implementation for the file transfer system including:
- Rate limiting per endpoint
- XSS protection and input sanitization
- Input validation
- Security headers
- Request validation
- Audit logging
"""

import os
import re
import html
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session, g
from collections import defaultdict
import time
import threading

# ============================================
# Security Configuration
# ============================================

SECURITY_CONFIG = {
    # Rate limiting (requests per window)
    'rate_limits': {
        'upload': {'requests': 10, 'window': 60},      # 10 uploads per minute
        'download': {'requests': 30, 'window': 60},    # 30 downloads per minute
        'verify': {'requests': 20, 'window': 60},      # 20 verifications per minute
        'otp_regenerate': {'requests': 5, 'window': 60},  # 5 OTP regenerations per minute
        'delete': {'requests': 10, 'window': 60},      # 10 deletions per minute
        'default': {'requests': 100, 'window': 60},    # 100 requests per minute default
    },
    # Max request sizes
    'max_request_sizes': {
        'upload': 500 * 1024 * 1024,  # 500MB for uploads
        'default': 1 * 1024 * 1024,    # 1MB for other requests
    },
    # Blocked patterns
    'blocked_extensions': [
        'exe', 'dll', 'bat', 'cmd', 'sh', 'bash', 'ps1', 'vbs', 'js',
        'msi', 'scr', 'com', 'pif', 'app', 'gadget', 'msp', 'hta',
        'cpl', 'msc', 'jar', 'vb', 'vbe', 'ws', 'wsf', 'wsc', 'wsh'
    ],
    # Session timeout
    'session_timeout_minutes': 30,
}

# ============================================
# Logging Setup
# ============================================

def setup_security_logger():
    """Setup security-specific logger for FileTransfer"""
    logger = logging.getLogger('filetransfer_security')
    logger.setLevel(logging.INFO)

    # Create logs directory if it doesn't exist
    log_dir = '/app/logs'
    os.makedirs(log_dir, exist_ok=True)

    # File handler
    handler = logging.FileHandler(f'{log_dir}/filetransfer_security.log')
    handler.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(remote_addr)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger

security_logger = setup_security_logger()


class SecurityLogAdapter(logging.LoggerAdapter):
    """Custom log adapter to include request info"""
    def process(self, msg, kwargs):
        try:
            remote_addr = request.remote_addr if request else 'N/A'
        except RuntimeError:
            remote_addr = 'N/A'
        kwargs['extra'] = {'remote_addr': remote_addr}
        return msg, kwargs

sec_log = SecurityLogAdapter(security_logger, {})


# ============================================
# Rate Limiting
# ============================================

class RateLimiter:
    """Thread-safe in-memory rate limiter"""

    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()

    def _clean_old_requests(self, key, window):
        """Remove requests outside the time window"""
        cutoff = time.time() - window
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]

    def is_allowed(self, key, limit, window):
        """Check if request is allowed under rate limit"""
        with self.lock:
            self._clean_old_requests(key, window)

            if len(self.requests[key]) >= limit:
                return False

            self.requests[key].append(time.time())
            return True

    def get_remaining(self, key, limit, window):
        """Get remaining requests in window"""
        with self.lock:
            self._clean_old_requests(key, window)
            return max(0, limit - len(self.requests[key]))

    def get_reset_time(self, key, window):
        """Get seconds until rate limit resets"""
        with self.lock:
            if not self.requests[key]:
                return 0
            oldest = min(self.requests[key])
            return max(0, int(window - (time.time() - oldest)))


rate_limiter = RateLimiter()


def rate_limit(endpoint_type='default'):
    """Rate limiting decorator for FileTransfer endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get rate limit config
            config = SECURITY_CONFIG['rate_limits'].get(
                endpoint_type,
                SECURITY_CONFIG['rate_limits']['default']
            )

            # Create rate limit key (IP + endpoint + user_id if logged in)
            user_id = session.get('user_id', 'anonymous')
            key = f"{request.remote_addr}:{endpoint_type}:{user_id}"

            if not rate_limiter.is_allowed(key, config['requests'], config['window']):
                sec_log.warning(
                    f"Rate limit exceeded for {endpoint_type} - "
                    f"User: {user_id}, IP: {request.remote_addr}"
                )

                reset_time = rate_limiter.get_reset_time(key, config['window'])

                response = jsonify({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': reset_time
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(reset_time)
                response.headers['X-RateLimit-Limit'] = str(config['requests'])
                response.headers['X-RateLimit-Remaining'] = '0'
                response.headers['X-RateLimit-Reset'] = str(reset_time)
                return response

            # Add rate limit headers to response
            g.rate_limit_info = {
                'limit': config['requests'],
                'remaining': rate_limiter.get_remaining(key, config['requests'], config['window']),
                'reset': rate_limiter.get_reset_time(key, config['window'])
            }

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============================================
# Input Sanitization & Validation
# ============================================

def sanitize_input(text, max_length=1000):
    """
    Sanitize user input to prevent XSS and injection attacks

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text
    """
    if text is None:
        return None

    if not isinstance(text, str):
        text = str(text)

    # Truncate to max length
    text = text[:max_length]

    # Strip whitespace
    text = text.strip()

    # HTML escape to prevent XSS
    text = html.escape(text)

    return text


def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and other attacks

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    if not filename:
        return None

    # Remove any path components
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace('\x00', '')

    # Remove path traversal attempts
    filename = filename.replace('..', '')
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')

    # Remove control characters
    filename = ''.join(c for c in filename if ord(c) >= 32)

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext

    return filename


def validate_file_id(file_id):
    """
    Validate file ID format

    Args:
        file_id: File ID to validate

    Returns:
        (is_valid, error_message)
    """
    if not file_id:
        return False, "File ID is required"

    if not isinstance(file_id, str):
        return False, "File ID must be a string"

    # File IDs should be URL-safe base64 (alphanumeric + - _)
    if not re.match(r'^[a-zA-Z0-9_-]+$', file_id):
        return False, "Invalid file ID format"

    if len(file_id) > 100:
        return False, "File ID too long"

    return True, None


def validate_otp_code(code):
    """
    Validate OTP code format

    Args:
        code: OTP code to validate

    Returns:
        (is_valid, error_message)
    """
    if not code:
        return False, "Access code is required"

    if not isinstance(code, str):
        return False, "Access code must be a string"

    # OTP codes should be alphanumeric, typically 16 chars
    if not re.match(r'^[a-zA-Z0-9]+$', code):
        return False, "Invalid access code format"

    if len(code) < 8 or len(code) > 32:
        return False, "Access code has invalid length"

    return True, None


def validate_classification(classification):
    """
    Validate file classification

    Args:
        classification: Classification to validate

    Returns:
        (is_valid, validated_value)
    """
    valid_classifications = ['Public', 'Internal Use', 'Classified']

    if classification in valid_classifications:
        return True, classification

    # Default to Public for invalid values
    return False, 'Public'


def validate_request_size(max_size=None):
    """
    Validate request content length

    Args:
        max_size: Maximum allowed size in bytes

    Returns:
        (is_valid, error_message)
    """
    if max_size is None:
        max_size = SECURITY_CONFIG['max_request_sizes']['default']

    content_length = request.content_length

    if content_length and content_length > max_size:
        return False, f"Request too large. Maximum size is {max_size // (1024*1024)}MB"

    return True, None


# ============================================
# XSS Protection Patterns
# ============================================

XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',
    r'<iframe',
    r'<object',
    r'<embed',
    r'<svg[^>]*onload',
    r'expression\s*\(',
    r'vbscript:',
    r'data:text/html',
    r'<meta[^>]*http-equiv',
]

SQL_INJECTION_PATTERNS = [
    r"('\s*OR\s*'?\d+\s*=\s*'?\d+)",
    r"(--|\#|\/\*)",
    r"(UNION\s+SELECT)",
    r"(INSERT\s+INTO)",
    r"(DELETE\s+FROM)",
    r"(DROP\s+TABLE)",
    r"(UPDATE\s+.*\s+SET)",
    r"(EXEC\s*\()",
]

PATH_TRAVERSAL_PATTERNS = [
    r'\.\.',
    r'%2e%2e',
    r'%252e%252e',
    r'/etc/passwd',
    r'/etc/shadow',
    r'c:\\windows',
    r'c:/windows',
]


def detect_xss(text):
    """
    Detect potential XSS attacks in text

    Args:
        text: Text to check

    Returns:
        (is_safe, detected_pattern)
    """
    if not text:
        return True, None

    text_lower = text.lower()

    for pattern in XSS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return False, pattern

    return True, None


def detect_sql_injection(text):
    """
    Detect potential SQL injection attacks

    Args:
        text: Text to check

    Returns:
        (is_safe, detected_pattern)
    """
    if not text:
        return True, None

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return False, pattern

    return True, None


def detect_path_traversal(text):
    """
    Detect potential path traversal attacks

    Args:
        text: Text to check

    Returns:
        (is_safe, detected_pattern)
    """
    if not text:
        return True, None

    text_lower = text.lower()

    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return False, pattern

    return True, None


def check_all_threats(text):
    """
    Check for all types of threats

    Args:
        text: Text to check

    Returns:
        (is_safe, threat_type, pattern)
    """
    is_safe, pattern = detect_xss(text)
    if not is_safe:
        return False, 'XSS', pattern

    is_safe, pattern = detect_sql_injection(text)
    if not is_safe:
        return False, 'SQL_INJECTION', pattern

    is_safe, pattern = detect_path_traversal(text)
    if not is_safe:
        return False, 'PATH_TRAVERSAL', pattern

    return True, None, None


# ============================================
# Security Middleware
# ============================================

def security_check():
    """
    Decorator to perform comprehensive security checks on requests
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check all request parameters for threats
            threats_found = []

            # Check query parameters
            for key, value in request.args.items():
                is_safe, threat_type, pattern = check_all_threats(value)
                if not is_safe:
                    threats_found.append((key, threat_type, pattern))

            # Check form data
            for key, value in request.form.items():
                if isinstance(value, str):
                    is_safe, threat_type, pattern = check_all_threats(value)
                    if not is_safe:
                        threats_found.append((key, threat_type, pattern))

            # Check JSON data
            if request.is_json:
                try:
                    json_data = request.get_json(silent=True) or {}
                    for key, value in json_data.items():
                        if isinstance(value, str):
                            is_safe, threat_type, pattern = check_all_threats(value)
                            if not is_safe:
                                threats_found.append((key, threat_type, pattern))
                except Exception:
                    pass

            if threats_found:
                # Log the security event
                sec_log.warning(
                    f"Security threat detected - Endpoint: {request.endpoint}, "
                    f"Threats: {threats_found}, User: {session.get('user_id', 'anonymous')}"
                )

                return jsonify({
                    'error': 'Request blocked due to security policy violation'
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def add_security_headers(response):
    """
    Add security headers to response

    Args:
        response: Flask response object

    Returns:
        Response with security headers
    """
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # XSS Protection for legacy browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'

    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "frame-src https://www.google.com; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )

    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    )

    # Cache control for sensitive data
    if request.endpoint and 'download' in request.endpoint:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    # Add rate limit headers if available
    if hasattr(g, 'rate_limit_info'):
        info = g.rate_limit_info
        response.headers['X-RateLimit-Limit'] = str(info['limit'])
        response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
        response.headers['X-RateLimit-Reset'] = str(info['reset'])

    return response


# ============================================
# Session Security
# ============================================

def check_session_security():
    """
    Check session security (timeout, IP binding, etc.)

    Returns:
        (is_valid, error_message)
    """
    if 'user_id' not in session:
        return True, None  # No session to check

    # Check session timeout
    last_activity = session.get('last_activity')
    if last_activity:
        try:
            last_time = datetime.fromisoformat(last_activity)
            timeout = timedelta(minutes=SECURITY_CONFIG['session_timeout_minutes'])

            if datetime.utcnow() - last_time > timeout:
                sec_log.info(
                    f"Session timeout for user {session.get('user_id')} - "
                    f"Last activity: {last_activity}"
                )
                return False, "Session expired. Please login again."
        except (ValueError, TypeError):
            pass

    # Update last activity
    session['last_activity'] = datetime.utcnow().isoformat()

    return True, None


def session_security_required(f):
    """Decorator to enforce session security checks"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_valid, error = check_session_security()

        if not is_valid:
            # Clear session
            session.clear()
            return jsonify({'error': error, 'redirect': '/login'}), 401

        return f(*args, **kwargs)
    return decorated_function


# ============================================
# Audit Logging
# ============================================

def log_file_access(file_id, action, status, details=None):
    """
    Log file access for audit trail

    Args:
        file_id: ID of the file accessed
        action: Action performed (upload, download, delete, etc.)
        status: Result status (success, failed, blocked)
        details: Additional details
    """
    user_id = session.get('user_id', 'anonymous')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')[:200]

    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'file_id': file_id,
        'user_id': user_id,
        'action': action,
        'status': status,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'details': details
    }

    sec_log.info(
        f"FILE_ACCESS - Action: {action}, Status: {status}, "
        f"FileID: {file_id}, User: {user_id}, Details: {details}"
    )

    return log_entry


def log_security_event(event_type, severity, details):
    """
    Log security event

    Args:
        event_type: Type of security event
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        details: Event details
    """
    user_id = session.get('user_id', 'anonymous')
    ip_address = request.remote_addr

    if severity == 'CRITICAL':
        sec_log.critical(
            f"SECURITY_EVENT - Type: {event_type}, Severity: {severity}, "
            f"User: {user_id}, Details: {details}"
        )
    elif severity == 'HIGH':
        sec_log.error(
            f"SECURITY_EVENT - Type: {event_type}, Severity: {severity}, "
            f"User: {user_id}, Details: {details}"
        )
    elif severity == 'MEDIUM':
        sec_log.warning(
            f"SECURITY_EVENT - Type: {event_type}, Severity: {severity}, "
            f"User: {user_id}, Details: {details}"
        )
    else:
        sec_log.info(
            f"SECURITY_EVENT - Type: {event_type}, Severity: {severity}, "
            f"User: {user_id}, Details: {details}"
        )


# ============================================
# Request Fingerprinting
# ============================================

def get_request_fingerprint():
    """
    Generate a fingerprint for the current request

    Returns:
        Request fingerprint hash
    """
    components = [
        request.remote_addr,
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
    ]

    fingerprint_string = '|'.join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]


# ============================================
# IP Blocking (Temporary)
# ============================================

class IPBlocker:
    """Temporary IP blocking for suspicious activity"""

    def __init__(self, block_duration=300):  # 5 minutes default
        self.blocked_ips = {}
        self.violation_counts = defaultdict(int)
        self.block_duration = block_duration
        self.lock = threading.Lock()

    def record_violation(self, ip, violation_type):
        """Record a security violation"""
        with self.lock:
            self.violation_counts[ip] += 1

            # Block after 5 violations
            if self.violation_counts[ip] >= 5:
                self.block_ip(ip, f"Multiple violations: {violation_type}")

    def block_ip(self, ip, reason):
        """Block an IP address"""
        with self.lock:
            self.blocked_ips[ip] = {
                'blocked_at': time.time(),
                'reason': reason
            }
            sec_log.warning(f"IP BLOCKED - IP: {ip}, Reason: {reason}")

    def is_blocked(self, ip):
        """Check if IP is blocked"""
        with self.lock:
            if ip not in self.blocked_ips:
                return False

            block_info = self.blocked_ips[ip]

            # Check if block has expired
            if time.time() - block_info['blocked_at'] > self.block_duration:
                del self.blocked_ips[ip]
                self.violation_counts[ip] = 0
                return False

            return True

    def get_block_remaining(self, ip):
        """Get remaining block time"""
        with self.lock:
            if ip not in self.blocked_ips:
                return 0

            elapsed = time.time() - self.blocked_ips[ip]['blocked_at']
            return max(0, int(self.block_duration - elapsed))


ip_blocker = IPBlocker()


def check_ip_block():
    """Decorator to check if IP is blocked"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr

            if ip_blocker.is_blocked(ip):
                remaining = ip_blocker.get_block_remaining(ip)
                return jsonify({
                    'error': 'Access temporarily blocked due to suspicious activity',
                    'retry_after': remaining
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ============================================
# Combined Security Decorator
# ============================================

def secure_endpoint(endpoint_type='default', require_auth=True):
    """
    Combined security decorator for FileTransfer endpoints

    Args:
        endpoint_type: Type of endpoint for rate limiting
        require_auth: Whether authentication is required
    """
    def decorator(f):
        @wraps(f)
        @check_ip_block()
        @rate_limit(endpoint_type)
        @security_check()
        def decorated_function(*args, **kwargs):
            # Check session security if auth required
            if require_auth:
                is_valid, error = check_session_security()
                if not is_valid:
                    session.clear()
                    return jsonify({'error': error, 'redirect': '/login'}), 401

            return f(*args, **kwargs)
        return decorated_function
    return decorator
