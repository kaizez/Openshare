"""
Custom SIEM (Security Information and Event Management) Engine
Implements detection rules for file transfer security monitoring.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional
import sqlite3
import os


class SIEMEngine:
    """Custom SIEM engine for detecting security anomalies."""
    
    def __init__(self, db_path: str = "db/idir.db"):
        """Initialize SIEM engine with database path."""
        self.db_path = db_path
        self.ensure_db_directory()
        self._init_tracking()
    
    def ensure_db_directory(self):
        """Ensure database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def _init_tracking(self):
        """Initialize in-memory tracking for detection rules."""
        self.file_download_tracking = {}  # {user_id: [(timestamp, file_count), ...]}
        self.failed_access_tracking = {}  # {ip_address: [timestamp1, timestamp2, ...]}
        self.user_roles = {}  # {user_id: role} - simplified role tracking
    
    def process_log(self, log_data: Dict) -> Optional[Dict]:
        """
        Process incoming log data through detection rules.
        
        Args:
            log_data: Dictionary containing log information with fields:
                - timestamp: ISO format timestamp
                - log_source: Source of the log (e.g., "file_transfer_server")
                - event_type: Type of event (e.g., "file_download", "access_attempt", "file_access")
                - description: Human-readable description
                - user_id: User identifier (optional)
                - ip_address: IP address (optional)
                - file_name: File name for file-related events (optional)
                - user_role: User role/permission level (optional)
                - result: "success" or "failure" (optional)
        
        Returns:
            Alert dictionary if detection rule triggers, None otherwise
        """
        timestamp_str = log_data.get('timestamp', datetime.utcnow().isoformat())
        try:
            # Parse ISO format timestamp, handling various formats
            if isinstance(timestamp_str, str):
                # Remove timezone info if present for simpler parsing
                clean_timestamp = timestamp_str.replace('Z', '').split('+')[0].split('.')[0]
                timestamp = datetime.fromisoformat(clean_timestamp)
            else:
                timestamp = datetime.utcnow()
        except (ValueError, AttributeError, TypeError):
            # Fallback to current time if parsing fails
            timestamp = datetime.utcnow()
        event_type = log_data.get('event_type', '')
        user_id = log_data.get('user_id')
        ip_address = log_data.get('ip_address', 'unknown')
        file_name = log_data.get('file_name', '')
        user_role = log_data.get('user_role', 'standard')
        result = log_data.get('result', 'success')
        
        # Store the log in database first
        self._store_log(log_data)
        
        # Rule 1: Suspicious Volume - 10+ files downloaded by single user within 60 seconds
        if event_type == 'file_download' and result == 'success' and user_id:
            alert = self._check_suspicious_volume(user_id, timestamp)
            if alert:
                return alert
        
        # Rule 2: Failed Access Attempts - 5 consecutive failed attempts from same IP
        if event_type in ['access_attempt', 'file_access'] and result == 'failure' and ip_address:
            alert = self._check_failed_access_attempts(ip_address, timestamp)
            if alert:
                return alert
        
        # Rule 3: Unauthorized File Type - Attempt to access config files without permission
        if event_type == 'file_access' and file_name and user_role:
            alert = self._check_unauthorized_file_type(file_name, user_role, ip_address, user_id)
            if alert:
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
    
    def _check_unauthorized_file_type(self, file_name: str, user_role: str, 
                                     ip_address: str, user_id: Optional[str]) -> Optional[Dict]:
        """Check for unauthorized access to configuration files."""
        # Check if file is a configuration file
        config_extensions = ['.cfg', '.ini', '.conf', '.config']
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
    
    def _store_log(self, log_data: Dict):
        """Store log entry in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = log_data.get('timestamp', datetime.utcnow().isoformat())
        log_source = log_data.get('log_source', 'unknown')
        event_type = log_data.get('event_type', 'unknown')
        description = log_data.get('description', '')
        severity = log_data.get('severity', 'Info')
        
        cursor.execute('''
            INSERT INTO security_logs (timestamp, log_source, event_type, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, log_source, event_type, description, severity))
        
        conn.commit()
        conn.close()


# Global SIEM engine instance
_siem_engine = None

def get_siem_engine(db_path: str = "db/idir.db") -> SIEMEngine:
    """Get or create global SIEM engine instance."""
    global _siem_engine
    if _siem_engine is None:
        _siem_engine = SIEMEngine(db_path)
    return _siem_engine

