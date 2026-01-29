"""
Database module for SIEM system.
Handles MySQL database connections and operations.
"""

from .connection import get_db_connection, init_database
from .models import SecurityLog, QuarantinedIP, User, ActiveSession

__all__ = [
    'get_db_connection',
    'init_database',
    'SecurityLog',
    'QuarantinedIP',
    'User',
    'ActiveSession'
]
