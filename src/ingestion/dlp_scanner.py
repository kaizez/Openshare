"""
DLP (Data Loss Prevention) Scanner Module.
Detects sensitive data patterns in file content and names.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import sys
import os

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from src.database.connection import get_db_connection
import mysql.connector


class DLPScanner:
    """Scanner for detecting sensitive data patterns."""

    # Sensitive data patterns with severity levels
    PATTERNS = {
        # Credit Card Numbers
        'credit_card_visa': {
            'pattern': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
            'description': 'Visa Credit Card Number',
            'severity': 'Critical'
        },
        'credit_card_mastercard': {
            'pattern': r'\b5[1-5][0-9]{14}\b',
            'description': 'MasterCard Credit Card Number',
            'severity': 'Critical'
        },
        'credit_card_amex': {
            'pattern': r'\b3[47][0-9]{13}\b',
            'description': 'American Express Card Number',
            'severity': 'Critical'
        },

        # Social Security Numbers
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'Social Security Number (SSN)',
            'severity': 'Critical'
        },
        'ssn_no_dash': {
            'pattern': r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b',
            'description': 'Potential SSN (no dashes)',
            'severity': 'High'
        },

        # API Keys and Secrets
        'aws_access_key': {
            'pattern': r'\bAKIA[0-9A-Z]{16}\b',
            'description': 'AWS Access Key ID',
            'severity': 'Critical'
        },
        'aws_secret_key': {
            'pattern': r'\b[A-Za-z0-9/+=]{40}\b',
            'description': 'Potential AWS Secret Key',
            'severity': 'High'
        },
        'stripe_live_key': {
            'pattern': r'\bsk_live_[0-9a-zA-Z]{24,}\b',
            'description': 'Stripe Live Secret Key',
            'severity': 'Critical'
        },
        'stripe_test_key': {
            'pattern': r'\bsk_test_[0-9a-zA-Z]{24,}\b',
            'description': 'Stripe Test Secret Key',
            'severity': 'Medium'
        },
        'github_token': {
            'pattern': r'\bghp_[0-9a-zA-Z]{36}\b',
            'description': 'GitHub Personal Access Token',
            'severity': 'Critical'
        },
        'github_oauth': {
            'pattern': r'\bgho_[0-9a-zA-Z]{36}\b',
            'description': 'GitHub OAuth Token',
            'severity': 'Critical'
        },
        'generic_api_key': {
            'pattern': r'\b[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?\b',
            'description': 'Generic API Key',
            'severity': 'High'
        },
        'generic_secret': {
            'pattern': r'\b[sS][eE][cC][rR][eE][tT]\s*[:=]\s*["\']?[a-zA-Z0-9]{10,}["\']?\b',
            'description': 'Generic Secret',
            'severity': 'High'
        },

        # Private Keys
        'private_key_rsa': {
            'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
            'description': 'RSA Private Key',
            'severity': 'Critical'
        },
        'private_key_openssh': {
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'description': 'OpenSSH Private Key',
            'severity': 'Critical'
        },
        'private_key_ec': {
            'pattern': r'-----BEGIN EC PRIVATE KEY-----',
            'description': 'EC Private Key',
            'severity': 'Critical'
        },

        # Passwords in plaintext
        'password_assignment': {
            'pattern': r'\b[pP][aA][sS][sS][wW][oO][rR][dD]\s*[:=]\s*["\']?[^\s"\']{6,}["\']?',
            'description': 'Hardcoded Password',
            'severity': 'Critical'
        },

        # Email addresses (bulk - potential data leak)
        'email_bulk': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email Address',
            'severity': 'Low',
            'bulk_threshold': 10  # Only alert if 10+ found
        },

        # Phone numbers
        'phone_us': {
            'pattern': r'\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'description': 'US Phone Number',
            'severity': 'Medium',
            'bulk_threshold': 5
        },

        # IP Addresses (bulk - potential reconnaissance data)
        'ip_address_bulk': {
            'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'description': 'IP Address',
            'severity': 'Low',
            'bulk_threshold': 20
        },

        # Healthcare (HIPAA)
        'medical_record': {
            'pattern': r'\b[mM][rR][nN]\s*[:=]?\s*\d{6,}\b',
            'description': 'Medical Record Number (MRN)',
            'severity': 'Critical'
        },

        # Database connection strings
        'db_connection': {
            'pattern': r'(?:mysql|postgresql|mongodb|redis)://[^\s]+',
            'description': 'Database Connection String',
            'severity': 'Critical'
        },

        # JWT Tokens
        'jwt_token': {
            'pattern': r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*\b',
            'description': 'JWT Token',
            'severity': 'High'
        }
    }

    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [
        '.pem', '.key', '.p12', '.pfx', '.cer',  # Certificates/Keys
        '.env', '.config', '.cfg', '.ini',  # Config files
        '.sql', '.bak', '.dump',  # Database files
        '.csv', '.xlsx', '.xls',  # Data files (potential bulk PII)
        '.kdb', '.kdbx', '.psafe3',  # Password managers
    ]

    def __init__(self):
        """Initialize DLP scanner with compiled patterns."""
        self.compiled_patterns = {}
        for name, config in self.PATTERNS.items():
            try:
                self.compiled_patterns[name] = {
                    'regex': re.compile(config['pattern']),
                    'description': config['description'],
                    'severity': config['severity'],
                    'bulk_threshold': config.get('bulk_threshold', 1)
                }
            except re.error as e:
                print(f"Error compiling pattern {name}: {e}")

    def scan_content(self, content: str, file_name: Optional[str] = None) -> List[Dict]:
        """
        Scan content for sensitive data patterns.

        Args:
            content: Text content to scan
            file_name: Optional file name for context

        Returns:
            List of detected sensitive data alerts
        """
        alerts = []

        for name, config in self.compiled_patterns.items():
            matches = config['regex'].findall(content)
            match_count = len(matches)

            if match_count >= config['bulk_threshold']:
                # Determine severity based on count
                severity = config['severity']
                if match_count > 100:
                    severity = 'Critical'
                elif match_count > 50 and severity in ['Low', 'Medium']:
                    severity = 'High'

                alerts.append({
                    'pattern_name': name,
                    'pattern_description': config['description'],
                    'match_count': match_count,
                    'severity': severity,
                    'file_name': file_name,
                    'sample_matches': matches[:3]  # Only store first 3 for evidence
                })

        return alerts

    def scan_file_name(self, file_name: str) -> List[Dict]:
        """
        Check if file name/extension is suspicious.

        Args:
            file_name: File name to check

        Returns:
            List of alerts for suspicious files
        """
        alerts = []
        lower_name = file_name.lower()

        # Check for suspicious extensions
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if lower_name.endswith(ext):
                severity = 'High'
                if ext in ['.pem', '.key', '.env']:
                    severity = 'Critical'

                alerts.append({
                    'pattern_name': 'suspicious_extension',
                    'pattern_description': f'Suspicious file extension: {ext}',
                    'match_count': 1,
                    'severity': severity,
                    'file_name': file_name
                })

        # Check for sensitive keywords in file name
        sensitive_keywords = [
            ('password', 'Critical'),
            ('secret', 'Critical'),
            ('credential', 'Critical'),
            ('private', 'High'),
            ('backup', 'Medium'),
            ('dump', 'High'),
            ('export', 'Medium'),
            ('customer', 'Medium'),
            ('employee', 'Medium'),
            ('salary', 'High'),
            ('ssn', 'Critical'),
            ('credit', 'High'),
        ]

        for keyword, severity in sensitive_keywords:
            if keyword in lower_name:
                alerts.append({
                    'pattern_name': 'sensitive_filename',
                    'pattern_description': f'Sensitive keyword in filename: {keyword}',
                    'match_count': 1,
                    'severity': severity,
                    'file_name': file_name
                })

        return alerts

    def scan_and_alert(self, content: Optional[str], file_name: Optional[str],
                       user_id: Optional[str], ip_address: Optional[str]) -> List[Dict]:
        """
        Scan content and file name, store alerts in database.

        Args:
            content: Optional content to scan
            file_name: Optional file name to check
            user_id: User who triggered the scan
            ip_address: IP address of the user

        Returns:
            List of all detected alerts
        """
        all_alerts = []

        # Scan file name
        if file_name:
            file_alerts = self.scan_file_name(file_name)
            all_alerts.extend(file_alerts)

        # Scan content if provided
        if content:
            content_alerts = self.scan_content(content, file_name)
            all_alerts.extend(content_alerts)

        # Store alerts in database
        for alert in all_alerts:
            self._store_dlp_alert(alert, user_id, ip_address)

        return all_alerts

    def _store_dlp_alert(self, alert: Dict, user_id: Optional[str],
                         ip_address: Optional[str]):
        """Store DLP alert in database."""
        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute('''
                INSERT INTO dlp_alerts
                (file_name, user_id, ip_address, pattern_matched, matched_count, severity, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                alert.get('file_name'),
                user_id,
                ip_address,
                alert['pattern_description'],
                alert['match_count'],
                alert['severity'],
                datetime.utcnow()
            ))

            connection.commit()
        except mysql.connector.Error as e:
            print(f"Error storing DLP alert: {e}")
            if connection:
                connection.rollback()
        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    def get_severity_for_alerts(self, alerts: List[Dict]) -> str:
        """Get highest severity from list of alerts."""
        if not alerts:
            return 'Low'

        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        max_severity = max(alerts, key=lambda x: severity_order.get(x['severity'], 0))
        return max_severity['severity']


# Global instance
_dlp_scanner = None

def get_dlp_scanner() -> DLPScanner:
    """Get or create global DLP scanner instance."""
    global _dlp_scanner
    if _dlp_scanner is None:
        _dlp_scanner = DLPScanner()
    return _dlp_scanner
