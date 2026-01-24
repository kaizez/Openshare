"""
Database model classes for SIEM system.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class SecurityLog:
    """Security log entry model."""
    timestamp: datetime
    log_source: str
    event_type: str
    description: str
    severity: str = 'Info'
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    file_name: Optional[str] = None
    user_role: Optional[str] = None
    file_size: Optional[int] = None
    result: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'timestamp': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            'log_source': self.log_source,
            'event_type': self.event_type,
            'description': self.description,
            'severity': self.severity,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'file_name': self.file_name,
            'user_role': self.user_role,
            'file_size': self.file_size,
            'result': self.result
        }


@dataclass
class QuarantinedIP:
    """Quarantined IP address model."""
    ip_address: str
    quarantined_at: datetime
    reason: str
    alerted_by: Optional[str] = None
    action_taken_by: Optional[str] = None
    released_at: Optional[datetime] = None
    status: str = 'quarantined'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'ip_address': self.ip_address,
            'quarantined_at': self.quarantined_at.isoformat() if isinstance(self.quarantined_at, datetime) else str(self.quarantined_at),
            'reason': self.reason,
            'alerted_by': self.alerted_by,
            'action_taken_by': self.action_taken_by,
            'released_at': self.released_at.isoformat() if isinstance(self.released_at, datetime) else str(self.released_at) if self.released_at else None,
            'status': self.status
        }


@dataclass
class User:
    """User model."""
    id: Optional[int] = None
    username: Optional[str] = None
    password_hash: Optional[str] = None
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


@dataclass
class ActiveSession:
    """Active user session model."""
    id: Optional[int] = None
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    status: str = 'active'
