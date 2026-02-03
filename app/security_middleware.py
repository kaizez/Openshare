"""
Security Middleware - Web Application Firewall & Protection
Implements defense against OWASP Top 10 vulnerabilities
"""

from flask import request, abort, current_app
import re
import logging
from datetime import datetime
import json

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)

# Create file handler for security logs
handler = logging.FileHandler('logs/security.log')
handler.setLevel(logging.WARNING)

# Create formatter
formatter = logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)


class SecurityMiddleware:
    """
    Web Application Firewall (WAF) middleware
    Protects against common web attacks
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize security middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)

    def before_request(self):
        """Run security checks before each request"""
        print(f"[SecurityMiddleware] Processing: {request.method} {request.path}", flush=True)
        print(f"[SecurityMiddleware] Content-Type: {request.content_type}", flush=True)

        # SQL Injection Detection
        if self.detect_sql_injection():
            self.log_security_event('SQL_INJECTION_ATTEMPT', severity='CRITICAL')
            abort(403, 'Forbidden: SQL injection attempt detected')

        # XSS Detection
        if self.detect_xss():
            self.log_security_event('XSS_ATTEMPT', severity='HIGH')
            abort(403, 'Forbidden: XSS attempt detected')

        # Path Traversal Detection
        if self.detect_path_traversal():
            self.log_security_event('PATH_TRAVERSAL_ATTEMPT', severity='HIGH')
            abort(403, 'Forbidden: Path traversal attempt detected')

        # Command Injection Detection
        if self.detect_command_injection():
            self.log_security_event('COMMAND_INJECTION_ATTEMPT', severity='CRITICAL')
            abort(403, 'Forbidden: Command injection attempt detected')

        # XXE Detection
        if self.detect_xxe():
            self.log_security_event('XXE_ATTEMPT', severity='HIGH')
            abort(403, 'Forbidden: XXE attempt detected')

        print(f"[SecurityMiddleware] Passed all checks for: {request.path}", flush=True)

    def after_request(self, response):
        """Add security headers to all responses"""
        # Content Security Policy - Prevents XSS
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://www.google.com; "
            "frame-src https://www.google.com https://www.recaptcha.net; "
            "frame-ancestors 'none';"
        )

        # HTTP Strict Transport Security - Force HTTPS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # XSS Protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy (formerly Feature Policy)
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=()'
        )

        return response

    def detect_sql_injection(self):
        """Detect SQL injection attempts in request parameters"""
        # SQL injection patterns
        sql_patterns = [
            r"(\bor\b|\band\b).*?[=<>].*?['\"]",  # OR/AND with quotes
            r"union.*?select",  # UNION SELECT
            r"insert.*?into",  # INSERT INTO
            r"update.*?set",  # UPDATE SET
            r"delete.*?from",  # DELETE FROM
            r"drop.*?(table|database)",  # DROP TABLE/DATABASE
            r"exec.*?\(",  # EXEC(
            r"execute.*?\(",  # EXECUTE(
            r"';.*?--",  # SQL comment
            r"xp_cmdshell",  # SQL Server command execution
            r"benchmark.*?\(",  # MySQL benchmark
            r"sleep.*?\(",  # MySQL sleep
            r"pg_sleep",  # PostgreSQL sleep
            r"waitfor.*?delay",  # SQL Server delay
            r"\|\|.*?chr\(",  # Oracle CHR concatenation
            r"information_schema",  # Schema enumeration
            r"load_file",  # MySQL file read
            r"into.*?outfile",  # MySQL file write
        ]

        return self._check_patterns(sql_patterns)

    def detect_xss(self):
        """Detect Cross-Site Scripting (XSS) attempts"""
        xss_patterns = [
            r"<script[^>]*>.*?</script>",  # Script tags
            r"javascript:",  # Javascript protocol
            r"on\w+\s*=",  # Event handlers (onclick, onload, etc.)
            r"<iframe[^>]*>",  # Iframes
            r"<object[^>]*>",  # Object tags
            r"<embed[^>]*>",  # Embed tags
            r"<applet[^>]*>",  # Applet tags
            r"eval\s*\(",  # Eval function
            r"expression\s*\(",  # CSS expression
            r"vbscript:",  # VBScript protocol
            r"data:text/html",  # Data URI
        ]

        return self._check_patterns(xss_patterns)

    def detect_path_traversal(self):
        """Detect path traversal attempts"""
        path_traversal_patterns = [
            r"\.\./",  # ../ (Unix)
            r"\.\.\\",  # ..\ (Windows)
            r"%2e%2e%2f",  # URL encoded ../
            r"%2e%2e/",  # Partially encoded
            r"\.\.%2f",  # Partially encoded
            r"%252e%252e%252f",  # Double URL encoded
            r"/etc/passwd",  # Linux password file
            r"/etc/shadow",  # Linux shadow file
            r"c:\\windows",  # Windows directory
            r"c:/windows",  # Windows directory (forward slash)
        ]

        return self._check_patterns(path_traversal_patterns)

    def detect_command_injection(self):
        """Detect OS command injection attempts"""
        command_patterns = [
            r";\s*(ls|cat|whoami|id|pwd)",  # Unix commands
            r"\|\s*(ls|cat|whoami|id|pwd)",  # Pipe commands
            r"&&\s*(ls|cat|whoami|id|pwd)",  # Command chaining
            r"`.*?`",  # Backticks
            r"\$\(.*?\)",  # Command substitution
            r">\s*/dev/null",  # Output redirection
            r"2>&1",  # Error redirection
            r"nc\s+-e",  # Netcat reverse shell
            r"bash\s+-i",  # Interactive bash
            r"sh\s+-i",  # Interactive sh
            r"/bin/(bash|sh)",  # Shell execution
            r"cmd\.exe",  # Windows command prompt
            r"powershell",  # PowerShell
        ]

        return self._check_patterns(command_patterns)

    def detect_xxe(self):
        """Detect XML External Entity (XXE) attacks"""
        if request.is_json or request.content_type == 'application/xml':
            try:
                data = request.get_data(as_text=True)
                xxe_patterns = [
                    r"<!ENTITY",  # Entity declaration
                    r"<!DOCTYPE",  # DOCTYPE with SYSTEM
                    r"SYSTEM\s+['\"]",  # SYSTEM identifier
                    r"PUBLIC\s+['\"]",  # PUBLIC identifier
                    r"file:///",  # File protocol
                    r"php://",  # PHP wrapper
                    r"expect://",  # Expect wrapper
                ]

                for pattern in xxe_patterns:
                    if re.search(pattern, data, re.IGNORECASE):
                        return True
            except:
                pass

        return False

    def _check_patterns(self, patterns):
        """Check if any pattern matches request parameters"""
        # Check all request parameters
        check_values = []

        # Query parameters
        check_values.extend(request.args.values())

        # Form data
        if request.form:
            check_values.extend(request.form.values())

        # JSON data
        if request.is_json:
            try:
                json_data = request.get_json()
                if isinstance(json_data, dict):
                    check_values.extend(self._extract_json_values(json_data))
            except:
                pass

        # Cookies
        check_values.extend(request.cookies.values())

        # Headers (check certain headers)
        suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in suspicious_headers:
            if request.headers.get(header):
                check_values.append(request.headers.get(header))

        # Check each value against patterns
        for value in check_values:
            if value:
                value_str = str(value)
                for pattern in patterns:
                    if re.search(pattern, value_str, re.IGNORECASE):
                        return True

        return False

    def _extract_json_values(self, data, values=None):
        """Recursively extract all values from JSON data"""
        if values is None:
            values = []

        if isinstance(data, dict):
            for value in data.values():
                self._extract_json_values(value, values)
        elif isinstance(data, list):
            for item in data:
                self._extract_json_values(item, values)
        else:
            values.append(str(data))

        return values

    def log_security_event(self, event_type, severity='MEDIUM', details=None):
        """Log security event with details"""
        event_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string,
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path,
            'query_string': request.query_string.decode('utf-8'),
            'referrer': request.referrer,
        }

        if details:
            event_data['details'] = details

        # Log to file
        log_message = json.dumps(event_data)

        if severity == 'CRITICAL':
            security_logger.critical(log_message)
        elif severity == 'HIGH':
            security_logger.error(log_message)
        elif severity == 'MEDIUM':
            security_logger.warning(log_message)
        else:
            security_logger.info(log_message)

        # TODO: Send alert email for CRITICAL events
        if severity == 'CRITICAL':
            # Send email to admin
            pass


class IntrusionDetectionSystem:
    """
    Intrusion Detection System (IDS)
    Monitors for suspicious patterns and behavior
    """

    def __init__(self):
        self.suspicious_patterns = []
        self.attack_threshold = 5  # Number of suspicious events before blocking

    def analyze_request(self, user_id=None):
        """Analyze current request for suspicious behavior"""
        risk_score = 0
        flags = []

        # Check for suspicious patterns
        if self._check_scanner_pattern():
            risk_score += 30
            flags.append('Scanner detected')

        if self._check_brute_force_pattern():
            risk_score += 40
            flags.append('Brute force pattern')

        if self._check_suspicious_user_agent():
            risk_score += 20
            flags.append('Suspicious user agent')

        if self._check_tor_exit_node():
            risk_score += 15
            flags.append('Tor exit node')

        if self._check_mass_enumeration():
            risk_score += 25
            flags.append('Mass enumeration')

        return risk_score, flags

    def _check_scanner_pattern(self):
        """Check if request looks like a vulnerability scanner"""
        scanner_signatures = [
            'nikto',
            'sqlmap',
            'nessus',
            'openvas',
            'nmap',
            'masscan',
            'zap',
            'burp',
            'acunetix',
            'qualys',
        ]

        user_agent = request.user_agent.string.lower()
        return any(sig in user_agent for sig in scanner_signatures)

    def _check_brute_force_pattern(self):
        """Check for brute force attack patterns"""
        # This would check failed login attempts from same IP
        # Integration with existing rate limiting
        return False  # Placeholder

    def _check_suspicious_user_agent(self):
        """Check for suspicious or missing user agent"""
        user_agent = request.user_agent.string

        if not user_agent or user_agent == '-':
            return True

        # Very short user agents are suspicious
        if len(user_agent) < 10:
            return True

        return False

    def _check_tor_exit_node(self):
        """Check if request is from Tor exit node"""
        # This would check IP against Tor exit node list
        # Placeholder for demonstration
        return False

    def _check_mass_enumeration(self):
        """Check for mass enumeration attempts"""
        # Check if accessing many different endpoints rapidly
        # Would track in session/cache
        return False


def setup_security_logging():
    """Setup security logging directory and handlers"""
    import os

    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)

    # Configure main app logger
    app_logger = logging.getLogger('app')
    app_logger.setLevel(logging.INFO)

    app_handler = logging.FileHandler('logs/app.log')
    app_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    app_logger.addHandler(app_handler)

    return app_logger, security_logger
