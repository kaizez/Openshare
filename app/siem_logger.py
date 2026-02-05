"""
SIEM Logger - Drop this file into your project to send events to the SIEM.

Usage:
    from siem_logger import SIEMLogger

    logger = SIEMLogger("http://SIEM_IP:5001", api_key="your_api_key")

    # Authentication events
    logger.login_success(user_id="john", ip=request.remote_addr)
    logger.login_failed(username="john", ip=request.remote_addr, reason="wrong password")

    # File events
    logger.file_uploaded(user_id="john", filename="doc.pdf", file_size=1024, ip=request.remote_addr)
    logger.file_downloaded(user_id="john", filename="doc.pdf", file_size=1024, ip=request.remote_addr)
"""

import requests
import hashlib
import threading
from datetime import datetime
from typing import Optional


class SIEMLogger:
    """
    SIEM Logger client for sending security events.

    Drop this file into your Flask project and use it to log security events.
    """

    def __init__(self, siem_url: str, api_key: Optional[str] = None,
                 log_source: str = "moveit_app", timeout: int = 5):
        """
        Initialize SIEM Logger.

        Args:
            siem_url: URL of the SIEM server (e.g., "http://192.168.1.100:5001")
            api_key: API key for authentication (optional for now)
            log_source: Name of your application/subsystem
            timeout: Request timeout in seconds
        """
        self.siem_url = siem_url.rstrip('/')
        self.api_key = api_key
        self.log_source = log_source
        self.timeout = timeout
        self.endpoint = f"{self.siem_url}/api/ingest_log"

    def _send_event(self, event_data: dict) -> bool:
        """
        Send event to SIEM in a background thread (fire-and-forget).
        The caller is never blocked — if the SIEM engine is unreachable
        the thread fails silently (prints to stdout) and the user-facing
        request returns immediately.
        """
        # Add timestamp if not present
        if 'timestamp' not in event_data:
            event_data['timestamp'] = datetime.utcnow().isoformat()

        # Add log source
        event_data['log_source'] = self.log_source

        # Prepare headers
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key

        endpoint = self.endpoint
        timeout = self.timeout

        def _post():
            try:
                requests.post(endpoint, json=event_data, headers=headers, timeout=timeout)
            except requests.RequestException as e:
                print(f"[SIEM Logger] Failed to send event: {e}")

        thread = threading.Thread(target=_post, daemon=True)
        thread.start()
        return True

    # ==================== AUTHENTICATION EVENTS ====================

    def login_success(self, user_id: str, ip: str, user_role: str = "standard",
                      mfa_used: bool = False) -> bool:
        """Log successful login."""
        return self._send_event({
            'event_type': 'login_success',
            'user_id': user_id,
            'ip_address': ip,
            'user_role': user_role,
            'result': 'success',
            'description': f'User {user_id} logged in successfully from {ip}',
            'severity': 'Info',
            'mfa_used': mfa_used
        })

    def login_failed(self, username: str, ip: str, reason: str = "invalid credentials") -> bool:
        """Log failed login attempt."""
        return self._send_event({
            'event_type': 'login_attempt',
            'user_id': username,
            'ip_address': ip,
            'result': 'failure',
            'description': f'Failed login attempt for {username} from {ip}: {reason}',
            'severity': 'Medium'
        })

    def logout(self, user_id: str, ip: str) -> bool:
        """Log user logout."""
        return self._send_event({
            'event_type': 'logout',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} logged out',
            'severity': 'Info'
        })

    def mfa_success(self, user_id: str, ip: str) -> bool:
        """Log successful MFA verification."""
        return self._send_event({
            'event_type': 'mfa_success',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} passed MFA verification',
            'severity': 'Info'
        })

    def mfa_failed(self, user_id: str, ip: str) -> bool:
        """Log failed MFA verification."""
        return self._send_event({
            'event_type': 'mfa_failed',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'failure',
            'description': f'User {user_id} failed MFA verification',
            'severity': 'High'
        })

    def password_changed(self, user_id: str, ip: str, changed_by: Optional[str] = None) -> bool:
        """Log password change."""
        changer = changed_by or user_id
        return self._send_event({
            'event_type': 'password_change',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Password changed for {user_id} by {changer}',
            'severity': 'Medium'
        })

    def session_start(self, user_id: str, ip: str, session_id: str) -> bool:
        """Log session start."""
        return self._send_event({
            'event_type': 'session_start',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Session started for {user_id}',
            'severity': 'Info',
            'session_id': session_id
        })

    def session_end(self, user_id: str, ip: str, session_id: str) -> bool:
        """Log session end."""
        return self._send_event({
            'event_type': 'session_end',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Session ended for {user_id}',
            'severity': 'Info',
            'session_id': session_id
        })

    # ==================== FILE OPERATION EVENTS ====================

    def file_uploaded(self, user_id: str, filename: str, file_size: int, ip: str,
                      file_path: Optional[str] = None, file_hash: Optional[str] = None) -> bool:
        """Log file upload."""
        return self._send_event({
            'event_type': 'file_upload',
            'user_id': user_id,
            'file_name': filename,
            'file_size': file_size,
            'file_path': file_path,
            'file_hash': file_hash,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} uploaded {filename} ({file_size} bytes)',
            'severity': 'Info'
        })

    def file_downloaded(self, user_id: str, filename: str, file_size: int, ip: str,
                        destination_ip: Optional[str] = None) -> bool:
        """Log file download."""
        return self._send_event({
            'event_type': 'file_download',
            'user_id': user_id,
            'file_name': filename,
            'file_size': file_size,
            'ip_address': ip,
            'destination_ip': destination_ip,
            'result': 'success',
            'description': f'User {user_id} downloaded {filename} ({file_size} bytes)',
            'severity': 'Info'
        })

    def file_deleted(self, user_id: str, filename: str, ip: str,
                     file_path: Optional[str] = None) -> bool:
        """Log file deletion."""
        return self._send_event({
            'event_type': 'file_delete',
            'user_id': user_id,
            'file_name': filename,
            'file_path': file_path,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} deleted {filename}',
            'severity': 'Medium'
        })

    def file_moved(self, user_id: str, filename: str, ip: str,
                   source_path: str, dest_path: str) -> bool:
        """Log file move/rename."""
        return self._send_event({
            'event_type': 'file_move',
            'user_id': user_id,
            'file_name': filename,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} moved {filename} from {source_path} to {dest_path}',
            'severity': 'Info',
            'source_path': source_path,
            'dest_path': dest_path
        })

    def file_shared(self, user_id: str, filename: str, ip: str,
                    shared_with: str) -> bool:
        """Log file sharing."""
        return self._send_event({
            'event_type': 'file_share',
            'user_id': user_id,
            'file_name': filename,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} shared {filename} with {shared_with}',
            'severity': 'Medium',
            'shared_with': shared_with
        })

    def file_accessed(self, user_id: str, filename: str, ip: str,
                      user_role: str = "standard", success: bool = True) -> bool:
        """Log file access (view/open)."""
        return self._send_event({
            'event_type': 'file_access',
            'user_id': user_id,
            'file_name': filename,
            'ip_address': ip,
            'user_role': user_role,
            'result': 'success' if success else 'failure',
            'description': f'User {user_id} {"accessed" if success else "failed to access"} {filename}',
            'severity': 'Info' if success else 'Medium'
        })

    def file_access_denied(self, user_id: str, filename: str, ip: str,
                           user_role: str = "standard", reason: str = "unauthorized") -> bool:
        """Log denied file access."""
        return self._send_event({
            'event_type': 'file_access',
            'user_id': user_id,
            'file_name': filename,
            'ip_address': ip,
            'user_role': user_role,
            'result': 'failure',
            'description': f'User {user_id} denied access to {filename}: {reason}',
            'severity': 'High'
        })

    # ==================== ADMIN ACTION EVENTS ====================

    def user_created(self, admin_id: str, new_user_id: str, ip: str,
                     user_role: str = "standard") -> bool:
        """Log user creation."""
        return self._send_event({
            'event_type': 'user_created',
            'user_id': admin_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Admin {admin_id} created user {new_user_id} with role {user_role}',
            'severity': 'Medium',
            'target_user': new_user_id,
            'new_role': user_role
        })

    def user_deleted(self, admin_id: str, deleted_user_id: str, ip: str) -> bool:
        """Log user deletion."""
        return self._send_event({
            'event_type': 'user_deleted',
            'user_id': admin_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Admin {admin_id} deleted user {deleted_user_id}',
            'severity': 'High',
            'target_user': deleted_user_id
        })

    def permission_changed(self, admin_id: str, target_user: str, ip: str,
                           old_role: str, new_role: str) -> bool:
        """Log permission/role change."""
        return self._send_event({
            'event_type': 'permission_changed',
            'user_id': admin_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Admin {admin_id} changed {target_user} role from {old_role} to {new_role}',
            'severity': 'High',
            'target_user': target_user,
            'old_role': old_role,
            'new_role': new_role,
            'changed_by': admin_id
        })

    def config_changed(self, admin_id: str, ip: str, setting: str,
                       old_value: str, new_value: str) -> bool:
        """Log configuration change."""
        return self._send_event({
            'event_type': 'config_changed',
            'user_id': admin_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Admin {admin_id} changed {setting} from {old_value} to {new_value}',
            'severity': 'High',
            'setting': setting,
            'old_value': old_value,
            'new_value': new_value
        })

    def account_locked(self, user_id: str, ip: str, reason: str, locked_by: str) -> bool:
        """Log account lock."""
        return self._send_event({
            'event_type': 'account_locked',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'Account {user_id} locked by {locked_by}: {reason}',
            'severity': 'High',
            'locked_by': locked_by,
            'reason': reason
        })

    # ==================== CHATBOT EVENTS ====================

    def chatbot_query(self, user_id: str, query: str, ip: str) -> bool:
        """Log chatbot query."""
        # Truncate query for logging
        truncated_query = query[:200] + "..." if len(query) > 200 else query
        return self._send_event({
            'event_type': 'chatbot_query',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} asked chatbot: {truncated_query}',
            'severity': 'Info',
            'query': truncated_query
        })

    def chatbot_sensitive_query(self, user_id: str, query: str, ip: str,
                                 sensitivity_type: str) -> bool:
        """Log potentially sensitive chatbot query."""
        truncated_query = query[:200] + "..." if len(query) > 200 else query
        return self._send_event({
            'event_type': 'chatbot_sensitive_query',
            'user_id': user_id,
            'ip_address': ip,
            'result': 'success',
            'description': f'User {user_id} made sensitive chatbot query ({sensitivity_type})',
            'severity': 'High',
            'query': truncated_query,
            'sensitivity_type': sensitivity_type
        })

    # ==================== SYSTEM EVENTS ====================

    def service_start(self, service_name: str) -> bool:
        """Log service start."""
        return self._send_event({
            'event_type': 'service_start',
            'result': 'success',
            'description': f'Service {service_name} started',
            'severity': 'Info',
            'service_name': service_name
        })

    def service_stop(self, service_name: str) -> bool:
        """Log service stop."""
        return self._send_event({
            'event_type': 'service_stop',
            'result': 'success',
            'description': f'Service {service_name} stopped',
            'severity': 'Medium',
            'service_name': service_name
        })

    def service_crash(self, service_name: str, error: str) -> bool:
        """Log service crash."""
        return self._send_event({
            'event_type': 'service_crash',
            'result': 'failure',
            'description': f'Service {service_name} crashed: {error}',
            'severity': 'Critical',
            'service_name': service_name,
            'error': error
        })

    # ==================== UTILITY METHODS ====================

    @staticmethod
    def calculate_file_hash(file_content: bytes) -> str:
        """Calculate SHA-256 hash of file content."""
        return hashlib.sha256(file_content).hexdigest()

    def custom_event(self, event_type: str, description: str, severity: str = "Info",
                     user_id: Optional[str] = None, ip: Optional[str] = None,
                     **extra_fields) -> bool:
        """
        Log a custom event.

        Args:
            event_type: Type of event
            description: Human-readable description
            severity: "Critical", "High", "Medium", "Low", or "Info"
            user_id: Optional user ID
            ip: Optional IP address
            **extra_fields: Any additional fields to include
        """
        event_data = {
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'result': 'success'
        }

        if user_id:
            event_data['user_id'] = user_id
        if ip:
            event_data['ip_address'] = ip

        event_data.update(extra_fields)

        return self._send_event(event_data)


# ==================== FLASK INTEGRATION HELPER ====================

def create_flask_logger(app, siem_url: str, api_key: Optional[str] = None):
    """
    Create a SIEM logger and attach it to a Flask app.

    Usage:
        from siem_logger import create_flask_logger

        app = Flask(__name__)
        siem = create_flask_logger(app, "http://SIEM_IP:5001")

        @app.route('/login', methods=['POST'])
        def login():
            # ... login logic ...
            siem.login_success(user_id=user.id, ip=request.remote_addr)
    """
    logger = SIEMLogger(siem_url, api_key=api_key, log_source=app.name)
    app.siem_logger = logger
    return logger
