"""
SOAR (Security Orchestration, Automation, and Response) Playbook Engine
Implements MANUAL response playbooks - all actions require admin button clicks.
"""

from datetime import datetime
from typing import Dict, Optional, List
import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
import mysql.connector


class PlaybookEngine:
    """SOAR playbook engine for manual security response actions."""
    
    def __init__(self):
        """Initialize playbook engine."""
        pass
    
    def block_attacker_ip(self, ip_address: str, reason: str, action_taken_by: str) -> Dict:
        """
        Manually block/quarantine an attacker IP address.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            action_taken_by: Username of admin who took the action
        
        Returns:
            Response action dictionary
        """
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            # Check if IP is already quarantined
            cursor.execute('''
                SELECT id FROM quarantined_ips 
                WHERE ip_address = %s AND status = 'quarantined'
            ''', (ip_address,))
            
            if cursor.fetchone():
                return {
                    'action': 'block_ip',
                    'status': 'already_quarantined',
                    'ip_address': ip_address,
                    'message': f'IP {ip_address} is already quarantined'
                }
            
            # Add to quarantined_ips table
            timestamp = datetime.utcnow()
            cursor.execute('''
                INSERT INTO quarantined_ips 
                (ip_address, quarantined_at, status, reason, action_taken_by)
                VALUES (%s, %s, 'quarantined', %s, %s)
            ''', (ip_address, timestamp, reason, action_taken_by))
            
            # Log the quarantine action
            cursor.execute('''
                INSERT INTO security_logs 
                (timestamp, log_source, event_type, description, severity)
                VALUES (%s, %s, %s, %s, %s)
            ''', (timestamp, 'SOAR_Playbook', 'containment_action', 
                  f'IP {ip_address} QUARANTINED by {action_taken_by} - {reason}', 'Critical'))
            
            connection.commit()
            
            return {
                'action': 'block_ip',
                'status': 'success',
                'ip_address': ip_address,
                'timestamp': timestamp.isoformat(),
                'message': f'IP {ip_address} has been quarantined'
            }
            
        except mysql.connector.IntegrityError:
            if connection:
                connection.rollback()
            return {
                'action': 'block_ip',
                'status': 'already_quarantined',
                'ip_address': ip_address,
                'message': f'IP {ip_address} is already quarantined'
            }
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'block_ip',
                'status': 'error',
                'ip_address': ip_address,
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def terminate_user_session(self, user_id: int, session_id: Optional[str], 
                               reason: str, action_taken_by: str) -> Dict:
        """
        Manually terminate a user session.
        
        Args:
            user_id: User ID to terminate session for
            session_id: Specific session ID to terminate (optional, if None, terminates all)
            reason: Reason for termination
            action_taken_by: Username of admin who took the action
        
        Returns:
            Response action dictionary
        """
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            timestamp = datetime.utcnow()
            
            if session_id:
                # Terminate specific session
                cursor.execute('''
                    UPDATE active_sessions 
                    SET status = 'terminated'
                    WHERE session_id = %s AND status = 'active'
                ''', (session_id,))
                sessions_terminated = cursor.rowcount
            else:
                # Terminate all sessions for user
                cursor.execute('''
                    UPDATE active_sessions 
                    SET status = 'terminated'
                    WHERE user_id = %s AND status = 'active'
                ''', (user_id,))
                sessions_terminated = cursor.rowcount
            
            if sessions_terminated > 0:
                # Log the termination action
                cursor.execute('''
                    INSERT INTO security_logs 
                    (timestamp, log_source, event_type, description, severity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (timestamp, 'SOAR_Playbook', 'session_termination', 
                      f'User {user_id} session(s) TERMINATED by {action_taken_by} - {reason}', 'High'))
                
                connection.commit()
                
                return {
                    'action': 'terminate_session',
                    'status': 'success',
                    'user_id': user_id,
                    'sessions_terminated': sessions_terminated,
                    'timestamp': timestamp.isoformat(),
                    'message': f'Terminated {sessions_terminated} session(s) for user {user_id}'
                }
            else:
                return {
                    'action': 'terminate_session',
                    'status': 'not_found',
                    'user_id': user_id,
                    'message': f'No active sessions found for user {user_id}'
                }
                
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'terminate_session',
                'status': 'error',
                'user_id': user_id,
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def quarantine_file(self, file_name: str, file_path: Optional[str], 
                       reason: str, user_id: Optional[str], ip_address: Optional[str],
                       action_taken_by: str) -> Dict:
        """
        Manually quarantine a file.
        
        Args:
            file_name: Name of file to quarantine
            file_path: Path to file (optional)
            reason: Reason for quarantining
            user_id: User ID associated with file (optional)
            ip_address: IP address associated with file (optional)
            action_taken_by: Username of admin who took the action
        
        Returns:
            Response action dictionary
        """
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            # Check if file is already quarantined
            cursor.execute('''
                SELECT id FROM quarantined_files 
                WHERE file_name = %s AND status = 'quarantined'
            ''', (file_name,))
            
            if cursor.fetchone():
                return {
                    'action': 'quarantine_file',
                    'status': 'already_quarantined',
                    'file_name': file_name,
                    'message': f'File {file_name} is already quarantined'
                }
            
            # Add to quarantined_files table
            timestamp = datetime.utcnow()
            cursor.execute('''
                INSERT INTO quarantined_files 
                (file_name, file_path, quarantined_at, status, reason, user_id, ip_address, action_taken_by)
                VALUES (%s, %s, %s, 'quarantined', %s, %s, %s, %s)
            ''', (file_name, file_path, timestamp, reason, user_id, ip_address, action_taken_by))
            
            # Log the quarantine action
            cursor.execute('''
                INSERT INTO security_logs 
                (timestamp, log_source, event_type, description, severity)
                VALUES (%s, %s, %s, %s, %s)
            ''', (timestamp, 'SOAR_Playbook', 'file_quarantine', 
                  f'File {file_name} QUARANTINED by {action_taken_by} - {reason}', 'High'))
            
            connection.commit()
            
            return {
                'action': 'quarantine_file',
                'status': 'success',
                'file_name': file_name,
                'timestamp': timestamp.isoformat(),
                'message': f'File {file_name} has been quarantined'
            }
            
        except mysql.connector.IntegrityError:
            if connection:
                connection.rollback()
            return {
                'action': 'quarantine_file',
                'status': 'already_quarantined',
                'file_name': file_name,
                'message': f'File {file_name} is already quarantined'
            }
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'quarantine_file',
                'status': 'error',
                'file_name': file_name,
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def release_ip(self, ip_address: str, action_taken_by: str) -> bool:
        """
        Release a quarantined IP address.
        
        Args:
            ip_address: IP address to release
            action_taken_by: Username of admin who took the action
        
        Returns:
            True if successfully released, False otherwise
        """
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor()
            
            timestamp = datetime.utcnow()
            
            cursor.execute('''
                UPDATE quarantined_ips
                SET released_at = %s, status = 'released'
                WHERE ip_address = %s AND status = 'quarantined'
            ''', (timestamp, ip_address))
            
            success = cursor.rowcount > 0
            
            if success:
                # Log the release action
                cursor.execute('''
                    INSERT INTO security_logs 
                    (timestamp, log_source, event_type, description, severity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (timestamp, 'SOAR_Playbook', 'containment_action', 
                      f'IP {ip_address} RELEASED from quarantine by {action_taken_by}', 'Info'))
            
            connection.commit()
            return success
            
        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            print(f"Error releasing IP: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def get_quarantined_ips(self) -> List[Dict]:
        """Get list of currently quarantined IP addresses."""
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute('''
                SELECT ip_address, quarantined_at, reason, alerted_by, action_taken_by
                FROM quarantined_ips
                WHERE status = 'quarantined'
                ORDER BY quarantined_at DESC
            ''')
            
            results = cursor.fetchall()
            
            # Convert datetime objects to strings
            for result in results:
                if result.get('quarantined_at'):
                    result['quarantined_at'] = result['quarantined_at'].isoformat() if hasattr(result['quarantined_at'], 'isoformat') else str(result['quarantined_at'])
            
            return results
            
        except mysql.connector.Error as e:
            print(f"Error getting quarantined IPs: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def get_quarantined_files(self) -> List[Dict]:
        """Get list of currently quarantined files."""
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute('''
                SELECT file_name, file_path, quarantined_at, reason, user_id, ip_address, action_taken_by
                FROM quarantined_files
                WHERE status = 'quarantined'
                ORDER BY quarantined_at DESC
            ''')
            
            results = cursor.fetchall()
            
            # Convert datetime objects to strings
            for result in results:
                if result.get('quarantined_at'):
                    result['quarantined_at'] = result['quarantined_at'].isoformat() if hasattr(result['quarantined_at'], 'isoformat') else str(result['quarantined_at'])
            
            return results
            
        except mysql.connector.Error as e:
            print(f"Error getting quarantined files: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()
    
    def get_active_sessions(self, user_id: Optional[int] = None) -> List[Dict]:
        """Get list of active user sessions."""
        connection = None
        cursor = None
        
        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            
            if user_id:
                cursor.execute('''
                    SELECT s.id, s.user_id, s.session_id, s.ip_address, s.created_at, s.last_activity, u.username
                    FROM active_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.status = 'active' AND s.user_id = %s
                    ORDER BY s.last_activity DESC
                ''', (user_id,))
            else:
                cursor.execute('''
                    SELECT s.id, s.user_id, s.session_id, s.ip_address, s.created_at, s.last_activity, u.username
                    FROM active_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.status = 'active'
                    ORDER BY s.last_activity DESC
                ''')
            
            results = cursor.fetchall()
            
            # Convert datetime objects to strings
            for result in results:
                if result.get('created_at'):
                    result['created_at'] = result['created_at'].isoformat() if hasattr(result['created_at'], 'isoformat') else str(result['created_at'])
                if result.get('last_activity'):
                    result['last_activity'] = result['last_activity'].isoformat() if hasattr(result['last_activity'], 'isoformat') else str(result['last_activity'])
            
            return results
            
        except mysql.connector.Error as e:
            print(f"Error getting active sessions: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()


# Global playbook engine instance
_playbook_engine = None

def get_playbook_engine() -> PlaybookEngine:
    """Get or create global playbook engine instance."""
    global _playbook_engine
    if _playbook_engine is None:
        _playbook_engine = PlaybookEngine()
    return _playbook_engine
