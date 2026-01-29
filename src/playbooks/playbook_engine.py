"""
SOAR (Security Orchestration, Automation, and Response) Playbook Engine
Implements both MANUAL and AUTOMATED response playbooks.
"""

from datetime import datetime
from typing import Dict, Optional, List
import sys
import os
import secrets

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
import mysql.connector


class PlaybookEngine:
    """SOAR playbook engine for security response actions."""

    # Configuration for automated responses
    AUTO_RESPONSE_CONFIG = {
        'auto_disable_after_mfa_failures': 5,
        'auto_block_after_login_failures': 10,
        'enable_auto_disable': True,
        'enable_auto_block': True,
        'enable_auto_session_kill': True
    }

    def __init__(self):
        """Initialize playbook engine."""
        pass

    # ==================== MANUAL PLAYBOOK ACTIONS ====================

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
                cursor.execute('''
                    UPDATE active_sessions
                    SET status = 'terminated'
                    WHERE session_id = %s AND status = 'active'
                ''', (session_id,))
                sessions_terminated = cursor.rowcount
            else:
                cursor.execute('''
                    UPDATE active_sessions
                    SET status = 'terminated'
                    WHERE user_id = %s AND status = 'active'
                ''', (user_id,))
                sessions_terminated = cursor.rowcount

            if sessions_terminated > 0:
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

            timestamp = datetime.utcnow()
            cursor.execute('''
                INSERT INTO quarantined_files
                (file_name, file_path, quarantined_at, status, reason, user_id, ip_address, action_taken_by)
                VALUES (%s, %s, %s, 'quarantined', %s, %s, %s, %s)
            ''', (file_name, file_path, timestamp, reason, user_id, ip_address, action_taken_by))

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
        """Release a quarantined IP address."""
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

    # ==================== AUTOMATED PLAYBOOK ACTIONS ====================

    def auto_disable_account(self, user_id: str, reason: str) -> Dict:
        """
        Automatically disable a user account.

        Args:
            user_id: User ID to disable
            reason: Reason for disabling

        Returns:
            Response action dictionary
        """
        if not self.AUTO_RESPONSE_CONFIG.get('enable_auto_disable', False):
            return {
                'action': 'auto_disable_account',
                'status': 'disabled',
                'message': 'Automatic account disabling is disabled'
            }

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            timestamp = datetime.utcnow()

            # Check if already disabled
            cursor.execute('''
                SELECT id FROM disabled_accounts
                WHERE user_id = %s AND is_disabled = TRUE
            ''', (user_id,))

            if cursor.fetchone():
                return {
                    'action': 'auto_disable_account',
                    'status': 'already_disabled',
                    'user_id': user_id,
                    'message': f'Account {user_id} is already disabled'
                }

            # Disable the account
            cursor.execute('''
                INSERT INTO disabled_accounts
                (user_id, disabled_at, reason, disabled_by, is_disabled)
                VALUES (%s, %s, %s, %s, TRUE)
            ''', (user_id, timestamp, reason, 'AUTOMATED_RESPONSE'))

            # Terminate all sessions
            cursor.execute('''
                UPDATE active_sessions
                SET status = 'terminated'
                WHERE user_id = %s AND status = 'active'
            ''', (user_id,))

            # Log the action
            cursor.execute('''
                INSERT INTO security_logs
                (timestamp, log_source, event_type, description, severity)
                VALUES (%s, %s, %s, %s, %s)
            ''', (timestamp, 'SOAR_Automated', 'account_disabled',
                  f'Account {user_id} AUTOMATICALLY DISABLED - {reason}', 'Critical'))

            connection.commit()

            return {
                'action': 'auto_disable_account',
                'status': 'success',
                'user_id': user_id,
                'timestamp': timestamp.isoformat(),
                'message': f'Account {user_id} has been automatically disabled'
            }

        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'auto_disable_account',
                'status': 'error',
                'user_id': user_id,
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def auto_block_ip(self, ip_address: str, reason: str) -> Dict:
        """
        Automatically block an IP address.

        Args:
            ip_address: IP address to block
            reason: Reason for blocking

        Returns:
            Response action dictionary
        """
        if not self.AUTO_RESPONSE_CONFIG.get('enable_auto_block', False):
            return {
                'action': 'auto_block_ip',
                'status': 'disabled',
                'message': 'Automatic IP blocking is disabled'
            }

        return self.block_attacker_ip(ip_address, reason, 'AUTOMATED_RESPONSE')

    def auto_kill_sessions_for_ip(self, ip_address: str, reason: str) -> Dict:
        """
        Automatically terminate all sessions from a specific IP.

        Args:
            ip_address: IP address to kill sessions for
            reason: Reason for termination

        Returns:
            Response action dictionary
        """
        if not self.AUTO_RESPONSE_CONFIG.get('enable_auto_session_kill', False):
            return {
                'action': 'auto_kill_sessions',
                'status': 'disabled',
                'message': 'Automatic session termination is disabled'
            }

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            timestamp = datetime.utcnow()

            cursor.execute('''
                UPDATE active_sessions
                SET status = 'terminated'
                WHERE ip_address = %s AND status = 'active'
            ''', (ip_address,))

            sessions_terminated = cursor.rowcount

            if sessions_terminated > 0:
                cursor.execute('''
                    INSERT INTO security_logs
                    (timestamp, log_source, event_type, description, severity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (timestamp, 'SOAR_Automated', 'session_termination',
                      f'{sessions_terminated} session(s) from IP {ip_address} AUTOMATICALLY TERMINATED - {reason}', 'High'))

            connection.commit()

            return {
                'action': 'auto_kill_sessions',
                'status': 'success',
                'ip_address': ip_address,
                'sessions_terminated': sessions_terminated,
                'timestamp': timestamp.isoformat(),
                'message': f'Terminated {sessions_terminated} session(s) from IP {ip_address}'
            }

        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'auto_kill_sessions',
                'status': 'error',
                'ip_address': ip_address,
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def check_blacklisted_network(self, ip_address: str) -> bool:
        """
        Check if an IP is in a blacklisted network.

        Args:
            ip_address: IP address to check

        Returns:
            True if blacklisted, False otherwise
        """
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT network_cidr FROM blacklisted_networks
                WHERE is_active = TRUE
            ''')

            networks = cursor.fetchall()

            for network in networks:
                if self._ip_in_network(ip_address, network['network_cidr']):
                    return True

            return False

        except mysql.connector.Error as e:
            print(f"Error checking blacklist: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def _ip_in_network(self, ip: str, cidr: str) -> bool:
        """Check if IP is in a CIDR network range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, ImportError):
            # Simple prefix matching fallback
            if '/' in cidr:
                network_prefix = cidr.split('/')[0]
                # Very basic check - just see if IP starts with network prefix parts
                prefix_parts = network_prefix.split('.')
                ip_parts = ip.split('.')
                for i, part in enumerate(prefix_parts):
                    if part != '0' and i < len(ip_parts) and ip_parts[i] != part:
                        return False
            return False

    def add_blacklisted_network(self, network_cidr: str, description: str,
                                 added_by: str) -> Dict:
        """Add a network to the blacklist."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO blacklisted_networks
                (network_cidr, description, added_at, added_by, is_active)
                VALUES (%s, %s, %s, %s, TRUE)
            ''', (network_cidr, description, datetime.utcnow(), added_by))

            connection.commit()

            return {
                'action': 'add_blacklist',
                'status': 'success',
                'network': network_cidr,
                'message': f'Network {network_cidr} added to blacklist'
            }

        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'add_blacklist',
                'status': 'error',
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    # ==================== HONEYTOKEN MANAGEMENT ====================

    def create_honeytoken(self, file_name: str, file_path: Optional[str],
                          description: str, created_by: str) -> Dict:
        """
        Create a honeytoken (decoy file) for intrusion detection.

        Args:
            file_name: Name of the decoy file
            file_path: Optional path where the file is located
            description: Description of the honeytoken
            created_by: Username who created it

        Returns:
            Response action dictionary
        """
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO honeytokens
                (file_name, file_path, created_at, created_by, is_active, description)
                VALUES (%s, %s, %s, %s, TRUE, %s)
            ''', (file_name, file_path, datetime.utcnow(), created_by, description))

            connection.commit()

            return {
                'action': 'create_honeytoken',
                'status': 'success',
                'file_name': file_name,
                'message': f'Honeytoken "{file_name}" created successfully'
            }

        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 'create_honeytoken',
                'status': 'error',
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def get_honeytokens(self) -> List[Dict]:
        """Get list of active honeytokens."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT file_name, file_path, created_at, created_by, description
                FROM honeytokens
                WHERE is_active = TRUE
                ORDER BY created_at DESC
            ''')

            results = cursor.fetchall()

            for result in results:
                if result.get('created_at'):
                    result['created_at'] = result['created_at'].isoformat() if hasattr(result['created_at'], 'isoformat') else str(result['created_at'])

            return results

        except mysql.connector.Error as e:
            print(f"Error getting honeytokens: {e}")
            return []
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def re_enable_account(self, user_id: str, re_enabled_by: str) -> Dict:
        """Re-enable a disabled account."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            timestamp = datetime.utcnow()

            cursor.execute('''
                UPDATE disabled_accounts
                SET is_disabled = FALSE, re_enabled_at = %s, re_enabled_by = %s
                WHERE user_id = %s AND is_disabled = TRUE
            ''', (timestamp, re_enabled_by, user_id))

            if cursor.rowcount > 0:
                cursor.execute('''
                    INSERT INTO security_logs
                    (timestamp, log_source, event_type, description, severity)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (timestamp, 'SOAR_Playbook', 'account_enabled',
                      f'Account {user_id} RE-ENABLED by {re_enabled_by}', 'Info'))

                connection.commit()

                return {
                    'action': 're_enable_account',
                    'status': 'success',
                    'user_id': user_id,
                    'message': f'Account {user_id} has been re-enabled'
                }
            else:
                return {
                    'action': 're_enable_account',
                    'status': 'not_found',
                    'user_id': user_id,
                    'message': f'No disabled account found for {user_id}'
                }

        except mysql.connector.Error as e:
            if connection:
                connection.rollback()
            return {
                'action': 're_enable_account',
                'status': 'error',
                'message': f'Error: {str(e)}'
            }
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def is_account_disabled(self, user_id: str) -> bool:
        """Check if an account is disabled."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                SELECT id FROM disabled_accounts
                WHERE user_id = %s AND is_disabled = TRUE
            ''', (user_id,))

            return cursor.fetchone() is not None

        except mysql.connector.Error as e:
            print(f"Error checking account status: {e}")
            return False
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    # ==================== QUERY METHODS ====================

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

    def get_disabled_accounts(self) -> List[Dict]:
        """Get list of disabled accounts."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('''
                SELECT user_id, disabled_at, reason, disabled_by
                FROM disabled_accounts
                WHERE is_disabled = TRUE
                ORDER BY disabled_at DESC
            ''')

            results = cursor.fetchall()

            for result in results:
                if result.get('disabled_at'):
                    result['disabled_at'] = result['disabled_at'].isoformat() if hasattr(result['disabled_at'], 'isoformat') else str(result['disabled_at'])

            return results

        except mysql.connector.Error as e:
            print(f"Error getting disabled accounts: {e}")
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
