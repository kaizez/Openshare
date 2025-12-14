"""
Custom SOAR (Security Orchestration, Automation, and Response) Engine
Implements automated response playbooks for security incidents.
"""

from datetime import datetime
from typing import Dict, Optional
import sqlite3
import os


class SOAREngine:
    """Custom SOAR engine for automated security response."""
    
    def __init__(self, db_path: str = "db/idir.db"):
        """Initialize SOAR engine with database path."""
        self.db_path = db_path
        self.ensure_db_directory()
        self._init_tables()
    
    def ensure_db_directory(self):
        """Ensure database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def _init_tables(self):
        """Initialize quarantined_ips table if it doesn't exist."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(self.db_path, timeout=5.0)
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantined_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL UNIQUE,
                        quarantined_at TEXT NOT NULL,
                        released_at TEXT,
                        status TEXT NOT NULL DEFAULT 'quarantined',
                        reason TEXT,
                        alerted_by TEXT
                    )
                ''')
                
                conn.commit()
                conn.close()
                break  # Success, exit retry loop
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < max_retries - 1:
                    import time
                    time.sleep(0.1)  # Wait a bit before retry
                    continue
                else:
                    # If it's not a locking issue or we're out of retries, raise
                    raise
    
    def initiate_response(self, alert: Dict) -> Optional[Dict]:
        """
        Initiate automated response based on alert severity.
        
        Args:
            alert: Alert dictionary containing:
                - severity: Alert severity level ('Critical', 'High', 'Medium', 'Low')
                - alert_type: Type of alert
                - description: Alert description
                - ip_address: IP address to quarantine (if applicable)
                - timestamp: Alert timestamp
        
        Returns:
            Response action dictionary if action taken, None otherwise
        """
        severity = alert.get('severity', 'Info')
        ip_address = alert.get('ip_address')
        
        # Critical alerts trigger containment/quarantine
        if severity == 'Critical' and ip_address and ip_address != 'unknown':
            return self._quarantine_ip(ip_address, alert)
        
        # High severity alerts can also trigger quarantine in future expansion
        # For now, we log but don't auto-quarantine
        
        return None
    
    def _quarantine_ip(self, ip_address: str, alert: Dict) -> Dict:
        """
        Quarantine an IP address by logging the action.
        
        Args:
            ip_address: IP address to quarantine
            alert: Alert that triggered the quarantine
        
        Returns:
            Response action dictionary
        """
        timestamp = datetime.utcnow().isoformat()
        reason = f"{alert.get('alert_type', 'Security Alert')}: {alert.get('description', '')}"
        
        # Check if IP is already quarantined
        if self.is_ip_quarantined(ip_address):
            return {
                'action': 'quarantine',
                'status': 'already_quarantined',
                'ip_address': ip_address,
                'message': f'IP {ip_address} is already quarantined'
            }
        
        # Add to quarantined_ips table
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO quarantined_ips (ip_address, quarantined_at, status, reason, alerted_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_address, timestamp, 'quarantined', reason, alert.get('alert_type', 'SOAR')))
            
            # Log the quarantine action as a security log
            cursor.execute('''
                INSERT INTO security_logs (timestamp, log_source, event_type, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, 'SOAR_Engine', 'containment_action', 
                  f'IP {ip_address} QUARANTINED - {reason}', 'Critical'))
            
            conn.commit()
            action_result = {
                'action': 'quarantine',
                'status': 'success',
                'ip_address': ip_address,
                'timestamp': timestamp,
                'message': f'IP {ip_address} has been quarantined'
            }
        except sqlite3.IntegrityError:
            # IP already exists (shouldn't happen due to check, but handle gracefully)
            action_result = {
                'action': 'quarantine',
                'status': 'already_quarantined',
                'ip_address': ip_address,
                'message': f'IP {ip_address} is already quarantined'
            }
        finally:
            conn.close()
        
        return action_result
    
    def release_ip(self, ip_address: str) -> bool:
        """
        Release a quarantined IP address.
        
        Args:
            ip_address: IP address to release
        
        Returns:
            True if successfully released, False otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.utcnow().isoformat()
        
        cursor.execute('''
            UPDATE quarantined_ips
            SET released_at = ?, status = 'released'
            WHERE ip_address = ? AND status = 'quarantined'
        ''', (timestamp, ip_address))
        
        success = cursor.rowcount > 0
        
        if success:
            # Log the release action
            cursor.execute('''
                INSERT INTO security_logs (timestamp, log_source, event_type, description, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, 'SOAR_Engine', 'containment_action', 
                  f'IP {ip_address} RELEASED from quarantine', 'Info'))
        
        conn.commit()
        conn.close()
        
        return success
    
    def is_ip_quarantined(self, ip_address: str) -> bool:
        """Check if an IP address is currently quarantined."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM quarantined_ips
            WHERE ip_address = ? AND status = 'quarantined'
        ''', (ip_address,))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def get_quarantined_ips(self) -> list:
        """Get list of currently quarantined IP addresses."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address, quarantined_at, reason, alerted_by
            FROM quarantined_ips
            WHERE status = 'quarantined'
            ORDER BY quarantined_at DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'ip_address': row[0],
                'quarantined_at': row[1],
                'reason': row[2],
                'alerted_by': row[3]
            }
            for row in results
        ]


# Global SOAR engine instance
_soar_engine = None

def get_soar_engine(db_path: str = "db/idir.db") -> SOAREngine:
    """Get or create global SOAR engine instance."""
    global _soar_engine
    if _soar_engine is None:
        _soar_engine = SOAREngine(db_path)
    return _soar_engine

