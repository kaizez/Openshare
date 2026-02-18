"""
Custom SIEM (Security Information and Event Management) Engine
Implements comprehensive detection rules for file transfer security monitoring.
Uses MySQL database for persistent storage.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
import sys
import os
import hashlib

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
from src.database.models import SecurityLog
from src.ingestion.geo_lookup import get_geo_lookup
from src.ingestion.dlp_scanner import get_dlp_scanner
import mysql.connector


class SIEMEngine:
    """Custom SIEM engine for detecting security anomalies."""

    # Supported event types
    EVENT_TYPES = [
        # Authentication events
        'login_success', 'login_failed', 'logout', 'login_attempt',
        'mfa_prompt', 'mfa_success', 'mfa_failed',
        'session_start', 'session_end',
        'password_change', 'password_reset',

        # File operations
        'file_upload', 'file_download', 'file_delete', 'file_move',
        'file_modify', 'file_share', 'file_access', 'file_copy',

        # Admin actions
        'user_created', 'user_deleted', 'user_modified',
        'permission_changed', 'role_changed', 'config_changed',
        'account_locked', 'account_unlocked',

        # System events
        'service_start', 'service_stop', 'service_crash',
        'audit_log_failure',

        # Chatbot events
        'chatbot_query', 'chatbot_sensitive_query',

        # Generic
        'access_attempt'
    ]

    # Map detection rules to MITRE ATT&CK techniques (demo-friendly tagging)
    MITRE_MAP = {
        'failed_login_attempts': 'T1110',          # Brute Force
        'brute_force_success': 'T1110.004',        # Credential Stuffing
        'impossible_travel': 'T1078',              # Valid Accounts
        'mass_deletion': 'T1485',                  # Data Destruction
        'data_staging': 'T1074',                   # Data Staged
        'large_data_transfer': 'T1048',            # Exfiltration Over Alt Protocol
        'privilege_escalation': 'T1078.003',       # Local Accounts
        'honeytoken_access': 'T1083',              # File & Directory Discovery
        'dlp_sensitive_data': 'T1530',             # Data from Cloud Storage
        'user_creation_spike': 'T1136',            # Create Account
        'user_baseline_anomaly': 'T1087',          # Account Discovery (proxy for UEBA demo)
    }

    def __init__(self):
        """Initialize SIEM engine with in-memory tracking."""
        self._init_tracking()
        self.geo_lookup = get_geo_lookup()
        self.dlp_scanner = get_dlp_scanner()

    def _init_tracking(self):
        """Initialize in-memory tracking for detection rules."""
        # Existing trackers
        self.file_download_tracking = {}  # {user_id: [(timestamp, file_count), ...]}
        self.failed_access_tracking = {}  # {ip_address: [timestamp1, timestamp2, ...]}
        self.failed_login_tracking = {}  # {ip_address: [(timestamp, user_attempted), ...]}
        self.large_transfer_tracking = {}  # {user_id: [(timestamp, file_size), ...]}

        # New trackers
        self.failed_mfa_tracking = {}  # {user_id: [timestamp1, timestamp2, ...]}
        self.file_deletion_tracking = {}  # {user_id: [(timestamp, file_count), ...]}
        self.compression_tracking = {}  # {user_id: [(timestamp, file_name), ...]}
        self.successful_login_after_failures = {}  # {ip_address: last_success_info}

    def process_log(self, log_data: Dict) -> Optional[Dict]:
        """
        Process incoming log data through detection rules.

        Args:
            log_data: Dictionary containing log information

        Returns:
            Alert dictionary if detection rule triggers, None otherwise
        """
        timestamp = self._parse_timestamp(log_data.get('timestamp'))
        event_type = log_data.get('event_type', '')
        user_id = log_data.get('user_id')
        ip_address = log_data.get('ip_address', 'unknown')
        file_name = log_data.get('file_name', '')
        user_role = log_data.get('user_role', 'standard')
        result = log_data.get('result', 'success')
        file_size = log_data.get('file_size', 0)
        file_hash = log_data.get('file_hash')  # SHA-256 hash if provided
        file_content = log_data.get('file_content')  # For DLP scanning
        destination_ip = log_data.get('destination_ip')
        protocol = log_data.get('protocol')

        # Store the log in database first
        self._store_log(log_data, timestamp)

        # Update user baseline for behavior analysis
        if user_id and event_type in ['file_download', 'file_upload']:
            self._update_user_baseline(user_id, event_type, file_size)
            baseline_alert = self._check_user_baseline_anomaly(user_id, timestamp)
            if baseline_alert:
                self._store_alert(baseline_alert)
                return baseline_alert

        # Check file hash for integrity monitoring
        if file_hash and file_name:
            hash_alert = self._check_file_hash_change(file_name, file_hash, user_id, ip_address)
            if hash_alert:
                self._store_alert(hash_alert)
                return hash_alert

        # DLP scanning for sensitive data
        if file_name or file_content:
            dlp_alerts = self.dlp_scanner.scan_and_alert(
                file_content, file_name, user_id, ip_address
            )
            if dlp_alerts:
                highest_severity = self.dlp_scanner.get_severity_for_alerts(dlp_alerts)
                if highest_severity in ['Critical', 'High']:
                    alert = {
                        'alert_type': 'Sensitive Data Detected',
                        'severity': highest_severity,
                        'description': f'DLP scan detected {len(dlp_alerts)} sensitive data pattern(s) in {file_name or "content"}',
                        'user_id': user_id,
                        'ip_address': ip_address,
                        'file_name': file_name,
                        'timestamp': timestamp.isoformat(),
                        'rule': 'dlp_sensitive_data',
                        'patterns_found': [a['pattern_description'] for a in dlp_alerts[:5]]
                    }
                    self._store_alert(alert)
                    return alert

        # Check for honeytoken access
        if event_type in ['file_access', 'file_download', 'file_move', 'file_copy'] and file_name:
            honeytoken_alert = self._check_honeytoken_access(file_name, user_id, ip_address, timestamp)
            if honeytoken_alert:
                self._store_alert(honeytoken_alert)
                return honeytoken_alert

        alert = None

        # === AUTHENTICATION RULES ===

        # Rule: Impossible Travel Detection
        if event_type in ['login_success', 'login_attempt'] and result == 'success' and user_id:
            alert = self.geo_lookup.check_impossible_travel(user_id, ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Brute Force with Successful Login (credential abuse)
        if event_type in ['login_success', 'login_attempt'] and result == 'success' and ip_address:
            alert = self._check_brute_force_success(ip_address, user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Failed Login Attempts (existing, enhanced)
        if event_type in ['login_attempt', 'login_failed'] and result == 'failure' and ip_address:
            alert = self._check_failed_login_attempts(ip_address, user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Failed MFA Attempts
        if event_type == 'mfa_failed' and user_id:
            alert = self._check_failed_mfa_attempts(user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # === FILE OPERATION RULES ===

        # Rule: Suspicious Download Volume
        if event_type == 'file_download' and result == 'success' and user_id:
            alert = self._check_suspicious_volume(user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Large Data Transfer / Exfiltration
        if event_type == 'file_download' and result == 'success' and user_id and file_size:
            alert = self._check_large_data_transfer(user_id, timestamp, file_size, destination_ip)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Mass File Deletion
        if event_type == 'file_delete' and user_id:
            alert = self._check_mass_deletion(user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Data Staging (bulk compression)
        if event_type in ['file_upload', 'file_modify'] and file_name:
            if self._is_archive_file(file_name):
                alert = self._check_data_staging(user_id, file_name, timestamp, file_size)
                if alert:
                    self._store_alert(alert)
                    return alert

        # Rule: Unauthorized File Type Access
        if event_type == 'file_access' and file_name and user_role:
            alert = self._check_unauthorized_file_type(file_name, user_role, ip_address, user_id)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Failed Access Attempts
        if event_type in ['access_attempt', 'file_access'] and result == 'failure' and ip_address:
            alert = self._check_failed_access_attempts(ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # === ADMIN ACTION RULES ===

        # Rule: Privilege Escalation
        if event_type in ['permission_changed', 'role_changed']:
            alert = self._check_privilege_escalation(log_data, user_id, ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        # Rule: Suspicious User Creation Spike
        if event_type == 'user_created':
            alert = self._check_user_creation_spike(ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert

        return None

    def _parse_timestamp(self, timestamp_str) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(timestamp_str, datetime):
            return timestamp_str

        if not timestamp_str:
            return datetime.utcnow()

        try:
            if isinstance(timestamp_str, str):
                clean_timestamp = timestamp_str.replace('Z', '').split('+')[0].split('.')[0]
                return datetime.fromisoformat(clean_timestamp)
        except (ValueError, AttributeError, TypeError):
            pass

        return datetime.utcnow()

    # === DETECTION RULE IMPLEMENTATIONS ===

    def _check_suspicious_volume(self, user_id: str, timestamp: datetime) -> Optional[Dict]:
        """Check for suspicious download volume (10+ downloads in 60 seconds) using DB logs."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM security_logs
                WHERE user_id = %s
                  AND event_type = 'file_download'
                  AND result = 'success'
                  AND timestamp >= %s
                """,
                (user_id, timestamp - timedelta(seconds=60)),
            )
            count = cursor.fetchone()[0] or 0
            if count >= 10:
                return {
                    'alert_type': 'Suspicious Volume',
                    'severity': 'High',
                    'description': f'User {user_id} downloaded {count} files within 60 seconds',
                    'user_id': user_id,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'suspicious_volume'
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking suspicious volume: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_failed_access_attempts(self, ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check for consecutive failed access attempts (5 in 5 minutes)."""
        if ip_address not in self.failed_access_tracking:
            self.failed_access_tracking[ip_address] = []

        self.failed_access_tracking[ip_address].append(timestamp)
        self.failed_access_tracking[ip_address] = self.failed_access_tracking[ip_address][-5:]

        recent_failures = [ts for ts in self.failed_access_tracking[ip_address]
                          if (timestamp - ts).total_seconds() <= 300]

        if len(recent_failures) >= 5:
            self.failed_access_tracking[ip_address] = []
            return {
                'alert_type': 'Failed Access Attempts',
                'severity': 'Medium',
                'description': f'5 consecutive failed access attempts from IP {ip_address}',
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat(),
                'rule': 'failed_access_attempts'
            }
        return None

    def _check_failed_login_attempts(self, ip_address: str, user_id: Optional[str],
                                      timestamp: datetime) -> Optional[Dict]:
        """Check for consecutive failed login attempts (5 in 5 minutes) using DB logs."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM security_logs
                WHERE ip_address = %s
                  AND event_type IN ('login_attempt', 'login_failed')
                  AND result = 'failure'
                  AND timestamp >= %s
                """,
                (ip_address, timestamp - timedelta(minutes=5)),
            )
            count = cursor.fetchone()[0] or 0
            if count >= 5:
                return {
                    'alert_type': 'Failed Login Attempts',
                    'severity': 'High',
                    'description': f'{count} failed login attempts from IP {ip_address} in 5 minutes',
                    'ip_address': ip_address,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'failed_login_attempts'
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking failed login attempts: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_brute_force_success(self, ip_address: str, user_id: str,
                                    timestamp: datetime) -> Optional[Dict]:
        """Check for successful login after multiple failures (credential abuse) using DB logs."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM security_logs
                WHERE ip_address = %s
                  AND event_type IN ('login_attempt', 'login_failed')
                  AND result = 'failure'
                  AND timestamp >= %s
                """,
                (ip_address, timestamp - timedelta(minutes=10)),
            )
            failures = cursor.fetchone()[0] or 0
            if failures >= 3:
                return {
                    'alert_type': 'Brute Force Success',
                    'severity': 'Critical',
                    'description': f'User {user_id} successfully logged in from IP {ip_address} after {failures} failed attempts in 10 minutes. Possible credential compromise.',
                    'user_id': user_id,
                    'ip_address': ip_address,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'brute_force_success'
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking brute force success: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_failed_mfa_attempts(self, user_id: str, timestamp: datetime) -> Optional[Dict]:
        """Check for failed MFA attempts (5 failures triggers auto-disable)."""
        if user_id not in self.failed_mfa_tracking:
            self.failed_mfa_tracking[user_id] = []

        self.failed_mfa_tracking[user_id].append(timestamp)

        recent_failures = [ts for ts in self.failed_mfa_tracking[user_id]
                          if (timestamp - ts).total_seconds() <= 300]

        self.failed_mfa_tracking[user_id] = recent_failures

        if len(recent_failures) >= 5:
            self.failed_mfa_tracking[user_id] = []
            return {
                'alert_type': 'Failed MFA Attempts',
                'severity': 'Critical',
                'description': f'User {user_id} failed MFA verification 5 times. Account should be disabled.',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'rule': 'failed_mfa_attempts',
                'recommended_action': 'auto_disable_account'
            }
        return None

    def _check_unauthorized_file_type(self, file_name: str, user_role: str,
                                       ip_address: str, user_id: Optional[str]) -> Optional[Dict]:
        """Check for unauthorized access to configuration/sensitive files."""
        config_extensions = ['.cfg', '.ini', '.conf', '.config', '.env', '.key', '.pem',
                            '.p12', '.pfx', '.cer', '.crt', '.ssh', '.passwd', '.shadow']
        is_config_file = any(file_name.lower().endswith(ext) for ext in config_extensions)

        authorized_roles = ['admin', 'administrator', 'system', 'root']
        is_authorized = user_role.lower() in [role.lower() for role in authorized_roles]

        if is_config_file and not is_authorized:
            user_identifier = user_id if user_id else f"IP {ip_address}"
            return {
                'alert_type': 'Unauthorized File Access',
                'severity': 'Critical',
                'description': f'Unauthorized access attempt to sensitive file {file_name} by {user_identifier} (role: {user_role})',
                'file_name': file_name,
                'user_id': user_id,
                'ip_address': ip_address,
                'user_role': user_role,
                'timestamp': datetime.utcnow().isoformat(),
                'rule': 'unauthorized_file_type'
            }
        return None

    def _check_large_data_transfer(self, user_id: str, timestamp: datetime,
                                    file_size: int, destination_ip: Optional[str] = None) -> Optional[Dict]:
        """Check for large data transfer (100MB+ in 5 minutes) using DB logs."""
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COALESCE(SUM(file_size), 0)
                FROM security_logs
                WHERE user_id = %s
                  AND event_type = 'file_download'
                  AND result = 'success'
                  AND timestamp >= %s
                """,
                (user_id, timestamp - timedelta(minutes=5)),
            )
            total_size = cursor.fetchone()[0] or 0

            threshold = 104857600  # 100MB
            if total_size >= threshold:
                size_mb = total_size / (1024 * 1024)

                severity = 'Medium'
                alert_type = 'Large Data Transfer'

                if destination_ip and not self._is_internal_ip(destination_ip):
                    severity = 'High'
                    alert_type = 'Potential Data Exfiltration'

                return {
                    'alert_type': alert_type,
                    'severity': severity,
                    'description': f'User {user_id} transferred {size_mb:.2f} MB within 5 minutes' +
                                  (f' to {destination_ip}' if destination_ip else ''),
                    'user_id': user_id,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'large_data_transfer',
                    'transfer_size': total_size,
                    'destination_ip': destination_ip
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking large data transfer: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_mass_deletion(self, user_id: str, timestamp: datetime) -> Optional[Dict]:
        """Check for mass file deletion (10+ files in 2 minutes)."""
        if user_id not in self.file_deletion_tracking:
            self.file_deletion_tracking[user_id] = []

        self.file_deletion_tracking[user_id].append((timestamp, 1))

        cutoff_time = timestamp - timedelta(minutes=2)
        self.file_deletion_tracking[user_id] = [
            (ts, count) for ts, count in self.file_deletion_tracking[user_id]
            if ts > cutoff_time
        ]

        total_deletions = sum(count for _, count in self.file_deletion_tracking[user_id])

        if total_deletions >= 10:
            self.file_deletion_tracking[user_id] = []
            return {
                'alert_type': 'Mass File Deletion',
                'severity': 'Critical',
                'description': f'User {user_id} deleted {total_deletions} files within 2 minutes. Possible insider threat or ransomware.',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'rule': 'mass_deletion'
            }
        return None

    def _check_data_staging(self, user_id: str, file_name: str,
                            timestamp: datetime, file_size: int) -> Optional[Dict]:
        """Check for data staging (bulk archive creation)."""
        if not user_id:
            return None

        if user_id not in self.compression_tracking:
            self.compression_tracking[user_id] = []

        self.compression_tracking[user_id].append((timestamp, file_name, file_size))

        cutoff_time = timestamp - timedelta(minutes=10)
        self.compression_tracking[user_id] = [
            (ts, fn, fs) for ts, fn, fs in self.compression_tracking[user_id]
            if ts > cutoff_time
        ]

        # Alert if 3+ archives created in 10 minutes or total size > 500MB
        total_size = sum(fs for _, _, fs in self.compression_tracking[user_id])
        archive_count = len(self.compression_tracking[user_id])

        if archive_count >= 3 or total_size > 524288000:  # 500MB
            self.compression_tracking[user_id] = []
            return {
                'alert_type': 'Data Staging Detected',
                'severity': 'High',
                'description': f'User {user_id} created {archive_count} archive files ({total_size / (1024*1024):.2f} MB) in 10 minutes. Possible data staging for exfiltration.',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'rule': 'data_staging'
            }
        return None

    def _check_privilege_escalation(self, log_data: Dict, user_id: Optional[str],
                                     ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check for privilege escalation attempts."""
        new_role = log_data.get('new_role', '').lower()
        old_role = log_data.get('old_role', '').lower()
        target_user = log_data.get('target_user', user_id)
        changed_by = log_data.get('changed_by', user_id)

        admin_roles = ['admin', 'administrator', 'root', 'superuser', 'system']

        # Check if escalating to admin
        if new_role in admin_roles and old_role not in admin_roles:
            severity = 'High'

            # Self-escalation is critical
            if target_user == changed_by:
                severity = 'Critical'

            return {
                'alert_type': 'Privilege Escalation',
                'severity': severity,
                'description': f'User {target_user} role changed from "{old_role}" to "{new_role}" by {changed_by}',
                'user_id': target_user,
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat(),
                'rule': 'privilege_escalation'
            }
        return None

    def _check_user_creation_spike(self, ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check for suspicious user creation spike (bot registration)."""
        if not ip_address:
            return None

        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM security_logs
                WHERE event_type = 'user_created'
                  AND ip_address = %s
                  AND timestamp >= %s
                """,
                (ip_address, timestamp - timedelta(minutes=10)),
            )
            count = cursor.fetchone()[0] or 0
            if count >= 3:
                return {
                    'alert_type': 'User Creation Spike',
                    'severity': 'Medium',
                    'description': f'{count} user accounts were created from IP {ip_address} within 10 minutes',
                    'ip_address': ip_address,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'user_creation_spike'
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking user creation spike: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_user_baseline_anomaly(self, user_id: str, timestamp: datetime) -> Optional[Dict]:
        """
        UEBA-lite: compare today's download volume against the user's last-30-day average.
        """
        connection = None
        cursor = None
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT
                    AVG(total_downloads) AS avg_downloads,
                    AVG(total_bytes_transferred) AS avg_bytes
                FROM user_baselines
                WHERE user_id = %s
                  AND date < %s
                  AND date >= %s
                """,
                (user_id, timestamp.date(), timestamp.date() - timedelta(days=30)),
            )
            baseline = cursor.fetchone() or {}
            avg_downloads = float(baseline.get("avg_downloads") or 0)
            avg_bytes = float(baseline.get("avg_bytes") or 0)

            cursor.execute(
                """
                SELECT total_downloads, total_bytes_transferred
                FROM user_baselines
                WHERE user_id = %s AND date = %s
                """,
                (user_id, timestamp.date()),
            )
            today = cursor.fetchone()
            if not today:
                return None

            today_downloads = int(today.get("total_downloads") or 0)
            today_bytes = int(today.get("total_bytes_transferred") or 0)

            spike_downloads = avg_downloads > 0 and today_downloads >= 20 and today_downloads >= 3 * avg_downloads
            spike_bytes = avg_bytes > 0 and today_bytes >= 500 * 1024 * 1024 and today_bytes >= 3 * avg_bytes

            if spike_downloads or spike_bytes:
                size_mb = today_bytes / (1024 * 1024) if today_bytes else 0
                return {
                    'alert_type': 'Behavior Anomaly',
                    'severity': 'High',
                    'description': (
                        f'User {user_id} is downloading far more than usual '
                        f'(today: {today_downloads} files, {size_mb:.2f} MB; baseline: {avg_downloads:.1f} files/day)'
                    ),
                    'user_id': user_id,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'user_baseline_anomaly'
                }
            return None
        except mysql.connector.Error as e:
            print(f"Error checking user baseline anomaly: {e}")
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _check_honeytoken_access(self, file_name: str, user_id: Optional[str],
                                  ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check if accessed file is a honeytoken."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT file_name, description FROM honeytokens
                WHERE file_name = %s AND is_active = TRUE
            ''', (file_name,))

            honeytoken = cursor.fetchone()
            if honeytoken:
                return {
                    'alert_type': 'Honeytoken Access',
                    'severity': 'Critical',
                    'description': f'HONEYTOKEN TRIGGERED: Decoy file "{file_name}" accessed by {user_id or "unknown"} from {ip_address}. Immediate investigation required.',
                    'file_name': file_name,
                    'user_id': user_id,
                    'ip_address': ip_address,
                    'timestamp': timestamp.isoformat(),
                    'rule': 'honeytoken_access',
                    'recommended_action': 'immediate_investigation'
                }
        except mysql.connector.Error as e:
            print(f"Error checking honeytoken: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        return None

    def _check_file_hash_change(self, file_name: str, new_hash: str,
                                 user_id: Optional[str], ip_address: str) -> Optional[Dict]:
        """Check if file hash has changed (integrity monitoring)."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT sha256_hash FROM file_hashes
                WHERE file_name = %s
                ORDER BY last_seen DESC LIMIT 1
            ''', (file_name,))

            existing = cursor.fetchone()

            if existing and existing['sha256_hash'] != new_hash:
                # Hash changed - update and alert
                cursor.execute('''
                    UPDATE file_hashes
                    SET hash_changed = TRUE, previous_hash = sha256_hash,
                        sha256_hash = %s, last_seen = %s
                    WHERE file_name = %s
                ''', (new_hash, datetime.utcnow(), file_name))
                connection.commit()

                return {
                    'alert_type': 'File Integrity Violation',
                    'severity': 'Critical',
                    'description': f'File {file_name} hash changed. Previous: {existing["sha256_hash"][:16]}... New: {new_hash[:16]}...',
                    'file_name': file_name,
                    'user_id': user_id,
                    'ip_address': ip_address,
                    'timestamp': datetime.utcnow().isoformat(),
                    'rule': 'file_integrity_violation'
                }
            elif not existing:
                # First time seeing this file, store hash
                cursor.execute('''
                    INSERT INTO file_hashes (file_name, sha256_hash, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s)
                ''', (file_name, new_hash, datetime.utcnow(), datetime.utcnow()))
                connection.commit()

        except mysql.connector.Error as e:
            print(f"Error checking file hash: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

        return None

    def _update_user_baseline(self, user_id: str, event_type: str, file_size: int):
        """Update user's daily baseline for behavior analysis."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            today = datetime.utcnow().date()

            if event_type == 'file_download':
                cursor.execute('''
                    INSERT INTO user_baselines (user_id, date, total_downloads, total_bytes_transferred)
                    VALUES (%s, %s, 1, %s)
                    ON DUPLICATE KEY UPDATE
                        total_downloads = total_downloads + 1,
                        total_bytes_transferred = total_bytes_transferred + %s
                ''', (user_id, today, file_size, file_size))
            elif event_type == 'file_upload':
                cursor.execute('''
                    INSERT INTO user_baselines (user_id, date, total_uploads, total_bytes_transferred)
                    VALUES (%s, %s, 1, %s)
                    ON DUPLICATE KEY UPDATE
                        total_uploads = total_uploads + 1,
                        total_bytes_transferred = total_bytes_transferred + %s
                ''', (user_id, today, file_size, file_size))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error updating user baseline: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _is_archive_file(self, file_name: str) -> bool:
        """Check if file is an archive/compressed file."""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
                             '.tar.gz', '.tgz', '.tar.bz2']
        return any(file_name.lower().endswith(ext) for ext in archive_extensions)

    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP is internal/private."""
        if not ip_address:
            return True
        private_prefixes = ['10.', '172.16.', '172.17.', '172.18.', '172.19.',
                           '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                           '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                           '172.30.', '172.31.', '192.168.', '127.', 'localhost']
        return any(ip_address.startswith(prefix) for prefix in private_prefixes)

    def _store_log(self, log_data: Dict, timestamp: datetime):
        """Store log entry in MySQL database."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO security_logs
                (timestamp, log_source, event_type, description, severity, user_id, ip_address, file_name, user_role, file_size, result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                timestamp,
                log_data.get('log_source', 'unknown'),
                log_data.get('event_type', 'unknown'),
                log_data.get('description', ''),
                log_data.get('severity', 'Info'),
                log_data.get('user_id'),
                log_data.get('ip_address'),
                log_data.get('file_name'),
                log_data.get('user_role'),
                log_data.get('file_size'),
                log_data.get('result')
            ))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error storing log: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _store_alert(self, alert: Dict):
        """Store alert in MySQL database (MITRE tagging + basic correlation)."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            rule = alert.get('rule', 'unknown')
            mitre_code = self.MITRE_MAP.get(rule)

            user_id = alert.get('user_id')
            ip_address = alert.get('ip_address')
            alert_ts = self._parse_timestamp(alert.get('timestamp'))

            correlation_id = None
            if user_id or ip_address:
                cursor.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE timestamp >= %s
                      AND (
                            (%s IS NOT NULL AND user_id = %s)
                         OR (%s IS NOT NULL AND ip_address = %s)
                      )
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (
                        alert_ts - timedelta(minutes=15),
                        user_id, user_id,
                        ip_address, ip_address,
                    ),
                )
                row = cursor.fetchone()
                if row:
                    correlation_id = row[0]

            cursor.execute('''
                INSERT INTO alerts
                (alert_type, severity, description, user_id, ip_address, file_name, timestamp, rule_triggered, status, mitre_technique, correlation_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'new', %s, %s)
            ''', (
                alert.get('alert_type', 'Unknown'),
                alert.get('severity', 'Info'),
                alert.get('description', ''),
                user_id,
                ip_address,
                alert.get('file_name'),
                alert.get('timestamp', datetime.utcnow().isoformat()),
                rule,
                mitre_code,
                correlation_id
            ))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error storing alert: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()


# Global SIEM engine instance
_siem_engine = None

def get_siem_engine() -> SIEMEngine:
    """Get or create global SIEM engine instance."""
    global _siem_engine
    if _siem_engine is None:
        _siem_engine = SIEMEngine()
    return _siem_engine
