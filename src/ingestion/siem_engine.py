"""
Custom SIEM (Security Information and Event Management) Engine
Implements detection rules for file transfer security monitoring.
Uses MySQL database for persistent storage.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
from src.database.models import SecurityLog
import mysql.connector


class SIEMEngine:
    """Custom SIEM engine for detecting security anomalies."""
    
    def __init__(self):
        """Initialize SIEM engine with in-memory tracking."""
        self._init_tracking()
    
    def _init_tracking(self):
        """Initialize in-memory tracking for detection rules."""
        self.file_download_tracking = {}  # {user_id: [(timestamp, file_count), ...]}
        self.failed_access_tracking = {}  # {ip_address: [timestamp1, timestamp2, ...]}
        self.failed_login_tracking = {}  # {ip_address: [timestamp1, timestamp2, ...]}
        self.large_transfer_tracking = {}  # {user_id: [(timestamp, file_size), ...]}
    
    def process_log(self, log_data: Dict) -> Optional[Dict]:
        """
        Process incoming log data through detection rules.
        
        Args:
            log_data: Dictionary containing log information with fields:
                - timestamp: ISO format timestamp
                - log_source: Source of the log (e.g., "file_transfer_server")
                - event_type: Type of event (e.g., "file_download", "access_attempt", "file_access", "login_attempt")
                - description: Human-readable description
                - user_id: User identifier (optional)
                - ip_address: IP address (optional)
                - file_name: File name for file-related events (optional)
                - user_role: User role/permission level (optional)
                - result: "success" or "failure" (optional)
                - file_size: File size in bytes (optional)
        
        Returns:
            Alert dictionary if detection rule triggers, None otherwise
        """
        timestamp_str = log_data.get('timestamp', datetime.utcnow().isoformat())
        try:
            if isinstance(timestamp_str, str):
                clean_timestamp = timestamp_str.replace('Z', '').split('+')[0].split('.')[0]
                timestamp = datetime.fromisoformat(clean_timestamp)
            else:
                timestamp = datetime.utcnow()
        except (ValueError, AttributeError, TypeError):
            timestamp = datetime.utcnow()
        
        event_type = log_data.get('event_type', '')
        user_id = log_data.get('user_id')
        ip_address = log_data.get('ip_address', 'unknown')
        file_name = log_data.get('file_name', '')
        user_role = log_data.get('user_role', 'standard')
        result = log_data.get('result', 'success')
        file_size = log_data.get('file_size', 0)
        
        # Store the log in database first
        self._store_log(log_data, timestamp)
        
        alert = None
        
        # Rule 1: Suspicious Volume - 10+ files downloaded by single user within 60 seconds
        if event_type == 'file_download' and result == 'success' and user_id:
            alert = self._check_suspicious_volume(user_id, timestamp)
            if alert:
                self._store_alert(alert)
                return alert
        
        # Rule 2: Failed Access Attempts - 5 consecutive failed attempts from same IP
        if event_type in ['access_attempt', 'file_access'] and result == 'failure' and ip_address:
            alert = self._check_failed_access_attempts(ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert
        
        # Rule 3: Failed Login Attempts - 5 consecutive failed logins from same IP
        if event_type == 'login_attempt' and result == 'failure' and ip_address:
            alert = self._check_failed_login_attempts(ip_address, timestamp)
            if alert:
                self._store_alert(alert)
                return alert
        
        # Rule 4: Unauthorized File Type - Attempt to access config files without permission
        if event_type == 'file_access' and file_name and user_role:
            alert = self._check_unauthorized_file_type(file_name, user_role, ip_address, user_id)
            if alert:
                self._store_alert(alert)
                return alert
        
        # Rule 5: Large Data Transfer - 100MB+ transferred by single user within 5 minutes
        if event_type == 'file_download' and result == 'success' and user_id and file_size:
            alert = self._check_large_data_transfer(user_id, timestamp, file_size)
            if alert:
                self._store_alert(alert)
                return alert
        
        return None
    
    def _check_suspicious_volume(self, user_id: str, timestamp: datetime) -> Optional[Dict]:
        """Check for suspicious download volume pattern."""
        if user_id not in self.file_download_tracking:
            self.file_download_tracking[user_id] = []
        
        # Add current download
        self.file_download_tracking[user_id].append((timestamp, 1))
        
        # Clean old entries (older than 60 seconds)
        cutoff_time = timestamp - timedelta(seconds=60)
        self.file_download_tracking[user_id] = [
            (ts, count) for ts, count in self.file_download_tracking[user_id]
            if ts > cutoff_time
        ]
        
        # Count total files in last 60 seconds
        total_files = sum(count for _, count in self.file_download_tracking[user_id])
        
        if total_files >= 10:
            # Reset tracking to prevent duplicate alerts
            self.file_download_tracking[user_id] = []
            
            return {
                'alert_type': 'Suspicious Volume',
                'severity': 'High',
                'description': f'User {user_id} downloaded {total_files} files within 60 seconds',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'rule': 'suspicious_volume'
            }
        
        return None
    
    def _check_failed_access_attempts(self, ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check for consecutive failed access attempts."""
        if ip_address not in self.failed_access_tracking:
            self.failed_access_tracking[ip_address] = []
        
        # Add current failed attempt
        self.failed_access_tracking[ip_address].append(timestamp)
        
        # Clean old entries (only keep last 5)
        self.failed_access_tracking[ip_address] = self.failed_access_tracking[ip_address][-5:]
        
        # Check if we have 5 consecutive failures in recent timeframe
        recent_failures = [ts for ts in self.failed_access_tracking[ip_address]
                          if (timestamp - ts).total_seconds() <= 300]  # 5 minutes window
        
        if len(recent_failures) >= 5:
            # Reset tracking to prevent duplicate alerts
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
    
    def _check_failed_login_attempts(self, ip_address: str, timestamp: datetime) -> Optional[Dict]:
        """Check for consecutive failed login attempts."""
        if ip_address not in self.failed_login_tracking:
            self.failed_login_tracking[ip_address] = []
        
        # Add current failed attempt
        self.failed_login_tracking[ip_address].append(timestamp)
        
        # Clean old entries (only keep last 5)
        self.failed_login_tracking[ip_address] = self.failed_login_tracking[ip_address][-5:]
        
        # Check if we have 5 consecutive failures in recent timeframe
        recent_failures = [ts for ts in self.failed_login_tracking[ip_address]
                          if (timestamp - ts).total_seconds() <= 300]  # 5 minutes window
        
        if len(recent_failures) >= 5:
            # Reset tracking to prevent duplicate alerts
            self.failed_login_tracking[ip_address] = []
            
            return {
                'alert_type': 'Failed Login Attempts',
                'severity': 'High',
                'description': f'5 consecutive failed login attempts from IP {ip_address}',
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat(),
                'rule': 'failed_login_attempts'
            }
        
        return None
    
    def _check_unauthorized_file_type(self, file_name: str, user_role: str, 
                                     ip_address: str, user_id: Optional[str]) -> Optional[Dict]:
        """Check for unauthorized access to configuration files."""
        # Check if file is a configuration file
        config_extensions = ['.cfg', '.ini', '.conf', '.config', '.env', '.key', '.pem']
        is_config_file = any(file_name.lower().endswith(ext) for ext in config_extensions)
        
        # Admin role can access config files, others cannot
        authorized_roles = ['admin', 'administrator', 'system']
        is_authorized = user_role.lower() in [role.lower() for role in authorized_roles]
        
        if is_config_file and not is_authorized:
            user_identifier = user_id if user_id else f"IP {ip_address}"
            return {
                'alert_type': 'Unauthorized File Type',
                'severity': 'Critical',
                'description': f'Unauthorized access attempt to configuration file {file_name} by {user_identifier} (role: {user_role})',
                'file_name': file_name,
                'user_id': user_id,
                'ip_address': ip_address,
                'user_role': user_role,
                'timestamp': datetime.utcnow().isoformat(),
                'rule': 'unauthorized_file_type'
            }
        
        return None
    
    def _check_large_data_transfer(self, user_id: str, timestamp: datetime, file_size: int) -> Optional[Dict]:
        """Check for large data transfer patterns."""
        if user_id not in self.large_transfer_tracking:
            self.large_transfer_tracking[user_id] = []
        
        # Add current transfer
        self.large_transfer_tracking[user_id].append((timestamp, file_size))
        
        # Clean old entries (older than 5 minutes)
        cutoff_time = timestamp - timedelta(minutes=5)
        self.large_transfer_tracking[user_id] = [
            (ts, size) for ts, size in self.large_transfer_tracking[user_id]
            if ts > cutoff_time
        ]
        
        # Calculate total size in last 5 minutes (100MB = 104857600 bytes)
        total_size = sum(size for _, size in self.large_transfer_tracking[user_id])
        threshold = 104857600  # 100MB
        
        if total_size >= threshold:
            # Reset tracking to prevent duplicate alerts
            self.large_transfer_tracking[user_id] = []
            
            size_mb = total_size / (1024 * 1024)
            return {
                'alert_type': 'Large Data Transfer',
                'severity': 'Medium',
                'description': f'User {user_id} transferred {size_mb:.2f} MB within 5 minutes',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'rule': 'large_data_transfer',
                'transfer_size': total_size
            }
        
        return None
    
    def _store_log(self, log_data: Dict, timestamp: datetime):
        """Store log entry in MySQL database."""
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            timestamp_str = log_data.get('timestamp', timestamp.isoformat())
            log_source = log_data.get('log_source', 'unknown')
            event_type = log_data.get('event_type', 'unknown')
            description = log_data.get('description', '')
            severity = log_data.get('severity', 'Info')
            user_id = log_data.get('user_id')
            ip_address = log_data.get('ip_address')
            file_name = log_data.get('file_name')
            user_role = log_data.get('user_role')
            file_size = log_data.get('file_size')
            result = log_data.get('result')
            
            cursor.execute('''
                INSERT INTO security_logs 
                (timestamp, log_source, event_type, description, severity, user_id, ip_address, file_name, user_role, file_size, result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (timestamp_str, log_source, event_type, description, severity, user_id, ip_address, file_name, user_role, file_size, result))
            
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
        """Store alert in MySQL database."""
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            timestamp_str = alert.get('timestamp', datetime.utcnow().isoformat())
            alert_type = alert.get('alert_type', 'Unknown')
            severity = alert.get('severity', 'Info')
            description = alert.get('description', '')
            user_id = alert.get('user_id')
            ip_address = alert.get('ip_address')
            file_name = alert.get('file_name')
            rule_triggered = alert.get('rule', 'unknown')
            
            cursor.execute('''
                INSERT INTO alerts 
                (alert_type, severity, description, user_id, ip_address, file_name, timestamp, rule_triggered, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'new')
            ''', (alert_type, severity, description, user_id, ip_address, file_name, timestamp_str, rule_triggered))
            
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
