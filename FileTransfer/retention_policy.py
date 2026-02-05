#!/usr/bin/env python3
"""
MoveIT Data Retention Policy Module

This module manages data retention policies for files and logs.
Retention is applied per-file based on upload_time, not as a global DB reset.

Configuration is stored in a JSON file and can be modified programmatically
for future admin page integration.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Any

# Default retention policy configuration file path
RETENTION_CONFIG_PATH = os.environ.get(
    'RETENTION_CONFIG_PATH',
    '/app/config/retention_policy.json'
)

# Default retention periods (in seconds)
# Set to 0 to disable retention (keep forever)
DEFAULT_RETENTION_POLICY = {
    # File retention settings
    'files': {
        'working_db': {
            'enabled': True,
            'retention_seconds': 7 * 24 * 60 * 60,  # 7 days default
            'description': 'Files in Working DB (operational database)'
        },
        'storage_db': {
            'enabled': True,
            'retention_seconds': 30 * 24 * 60 * 60,  # 30 days default
            'description': 'Archived files in Storage DB'
        },
        'filesystem': {
            'enabled': True,
            'retention_seconds': 7 * 24 * 60 * 60,  # 7 days default
            'description': 'Files stored on disk in uploads folder'
        }
    },
    # Log retention settings
    'logs': {
        'access_logs': {
            'enabled': True,
            'retention_seconds': 90 * 24 * 60 * 60,  # 90 days default
            'description': 'File access logs'
        },
        'failed_upload_logs': {
            'enabled': True,
            'retention_seconds': 30 * 24 * 60 * 60,  # 30 days default
            'description': 'Failed upload attempt logs'
        },
        'virus_scan_logs': {
            'enabled': True,
            'retention_seconds': 90 * 24 * 60 * 60,  # 90 days default
            'description': 'Virus scan result logs'
        },
        'approval_requests': {
            'enabled': True,
            'retention_seconds': 30 * 24 * 60 * 60,  # 30 days default
            'description': 'Classified file approval requests'
        }
    },
    # Global settings
    'settings': {
        'cleanup_interval_seconds': 3600,  # Run cleanup every hour
        'dry_run': False,  # If True, log what would be deleted without actually deleting
        'last_updated': None,
        'updated_by': None
    }
}


class RetentionPolicy:
    """
    Manages data retention policies for the MoveIT system.

    Policies are stored in a JSON file and can be modified at runtime.
    Changes take effect immediately on the next cleanup cycle.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the retention policy manager.

        Args:
            config_path: Path to the retention policy JSON file.
                        Defaults to RETENTION_CONFIG_PATH.
        """
        self.config_path = config_path or RETENTION_CONFIG_PATH
        self._policy = None
        self._load_policy()

    def _ensure_config_dir(self):
        """Ensure the configuration directory exists."""
        config_dir = os.path.dirname(self.config_path)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)

    def _load_policy(self):
        """Load policy from file or use defaults."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self._policy = json.load(f)
                print(f"[Retention] Loaded policy from {self.config_path}")
            else:
                self._policy = DEFAULT_RETENTION_POLICY.copy()
                self._save_policy()
                print(f"[Retention] Created default policy at {self.config_path}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"[Retention] Error loading policy: {e}, using defaults")
            self._policy = DEFAULT_RETENTION_POLICY.copy()

    def _save_policy(self):
        """Save current policy to file."""
        try:
            self._ensure_config_dir()
            with open(self.config_path, 'w') as f:
                json.dump(self._policy, f, indent=2, default=str)
            print(f"[Retention] Saved policy to {self.config_path}")
            return True
        except IOError as e:
            print(f"[Retention] Error saving policy: {e}")
            return False

    def reload(self):
        """Reload policy from file."""
        self._load_policy()

    def get_policy(self) -> Dict[str, Any]:
        """
        Get the complete retention policy.

        Returns:
            Dict containing all retention settings.
        """
        return self._policy.copy()

    def get_file_retention(self, storage_type: str) -> Dict[str, Any]:
        """
        Get retention settings for a specific file storage type.

        Args:
            storage_type: 'working_db', 'storage_db', or 'filesystem'

        Returns:
            Dict with 'enabled', 'retention_seconds', and 'description'
        """
        return self._policy.get('files', {}).get(storage_type, {})

    def get_log_retention(self, log_type: str) -> Dict[str, Any]:
        """
        Get retention settings for a specific log type.

        Args:
            log_type: 'access_logs', 'failed_upload_logs', 'virus_scan_logs',
                     or 'approval_requests'

        Returns:
            Dict with 'enabled', 'retention_seconds', and 'description'
        """
        return self._policy.get('logs', {}).get(log_type, {})

    def get_cleanup_interval(self) -> int:
        """
        Get the cleanup interval in seconds.

        Returns:
            Interval in seconds between cleanup runs.
        """
        return self._policy.get('settings', {}).get('cleanup_interval_seconds', 3600)

    def is_dry_run(self) -> bool:
        """
        Check if dry run mode is enabled.

        Returns:
            True if changes should be logged but not executed.
        """
        return self._policy.get('settings', {}).get('dry_run', False)

    # ============================================
    # Functions to modify retention policies
    # (For future admin page integration)
    # ============================================

    def set_file_retention(
        self,
        storage_type: str,
        retention_seconds: int,
        enabled: bool = True,
        updated_by: Optional[str] = None
    ) -> bool:
        """
        Set retention period for a file storage type.

        Args:
            storage_type: 'working_db', 'storage_db', or 'filesystem'
            retention_seconds: How long to keep files (0 = forever)
            enabled: Whether retention is enabled for this type
            updated_by: Identifier of who made the change (for audit)

        Returns:
            True if successful, False otherwise.
        """
        if storage_type not in ['working_db', 'storage_db', 'filesystem']:
            print(f"[Retention] Invalid storage type: {storage_type}")
            return False

        if retention_seconds < 0:
            print(f"[Retention] Invalid retention_seconds: {retention_seconds}")
            return False

        if 'files' not in self._policy:
            self._policy['files'] = {}

        if storage_type not in self._policy['files']:
            self._policy['files'][storage_type] = {}

        self._policy['files'][storage_type]['enabled'] = enabled
        self._policy['files'][storage_type]['retention_seconds'] = retention_seconds
        self._policy['settings']['last_updated'] = datetime.now().isoformat()
        self._policy['settings']['updated_by'] = updated_by

        print(f"[Retention] Set {storage_type} retention to {retention_seconds}s "
              f"(enabled={enabled}) by {updated_by}")

        return self._save_policy()

    def set_log_retention(
        self,
        log_type: str,
        retention_seconds: int,
        enabled: bool = True,
        updated_by: Optional[str] = None
    ) -> bool:
        """
        Set retention period for a log type.

        Args:
            log_type: 'access_logs', 'failed_upload_logs', 'virus_scan_logs',
                     or 'approval_requests'
            retention_seconds: How long to keep logs (0 = forever)
            enabled: Whether retention is enabled for this type
            updated_by: Identifier of who made the change (for audit)

        Returns:
            True if successful, False otherwise.
        """
        valid_types = ['access_logs', 'failed_upload_logs', 'virus_scan_logs', 'approval_requests']
        if log_type not in valid_types:
            print(f"[Retention] Invalid log type: {log_type}")
            return False

        if retention_seconds < 0:
            print(f"[Retention] Invalid retention_seconds: {retention_seconds}")
            return False

        if 'logs' not in self._policy:
            self._policy['logs'] = {}

        if log_type not in self._policy['logs']:
            self._policy['logs'][log_type] = {}

        self._policy['logs'][log_type]['enabled'] = enabled
        self._policy['logs'][log_type]['retention_seconds'] = retention_seconds
        self._policy['settings']['last_updated'] = datetime.now().isoformat()
        self._policy['settings']['updated_by'] = updated_by

        print(f"[Retention] Set {log_type} retention to {retention_seconds}s "
              f"(enabled={enabled}) by {updated_by}")

        return self._save_policy()

    def set_cleanup_interval(
        self,
        interval_seconds: int,
        updated_by: Optional[str] = None
    ) -> bool:
        """
        Set the cleanup interval.

        Args:
            interval_seconds: Time between cleanup runs (minimum 60 seconds)
            updated_by: Identifier of who made the change

        Returns:
            True if successful, False otherwise.
        """
        if interval_seconds < 60:
            print(f"[Retention] Cleanup interval must be at least 60 seconds")
            return False

        self._policy['settings']['cleanup_interval_seconds'] = interval_seconds
        self._policy['settings']['last_updated'] = datetime.now().isoformat()
        self._policy['settings']['updated_by'] = updated_by

        print(f"[Retention] Set cleanup interval to {interval_seconds}s by {updated_by}")

        return self._save_policy()

    def set_dry_run(self, enabled: bool, updated_by: Optional[str] = None) -> bool:
        """
        Enable or disable dry run mode.

        Args:
            enabled: True to enable dry run (log without deleting)
            updated_by: Identifier of who made the change

        Returns:
            True if successful, False otherwise.
        """
        self._policy['settings']['dry_run'] = enabled
        self._policy['settings']['last_updated'] = datetime.now().isoformat()
        self._policy['settings']['updated_by'] = updated_by

        print(f"[Retention] Set dry_run to {enabled} by {updated_by}")

        return self._save_policy()

    def get_cutoff_time(self, retention_seconds: int) -> datetime:
        """
        Calculate the cutoff time for a given retention period.

        Args:
            retention_seconds: The retention period in seconds

        Returns:
            datetime before which items should be deleted
        """
        return datetime.now() - timedelta(seconds=retention_seconds)

    def format_retention_time(self, seconds: int) -> str:
        """
        Format retention time in human-readable format.

        Args:
            seconds: Time in seconds

        Returns:
            Human-readable string (e.g., "7 days", "2 hours", "30 minutes")
        """
        if seconds == 0:
            return "Forever (disabled)"

        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''}"
        else:
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''}"

    def get_policy_summary(self) -> Dict[str, str]:
        """
        Get a human-readable summary of the current policy.

        Returns:
            Dict with formatted retention times for each category.
        """
        summary = {}

        # File retention
        for storage_type, settings in self._policy.get('files', {}).items():
            enabled = settings.get('enabled', False)
            seconds = settings.get('retention_seconds', 0)
            if enabled and seconds > 0:
                summary[f"files.{storage_type}"] = self.format_retention_time(seconds)
            else:
                summary[f"files.{storage_type}"] = "Disabled"

        # Log retention
        for log_type, settings in self._policy.get('logs', {}).items():
            enabled = settings.get('enabled', False)
            seconds = settings.get('retention_seconds', 0)
            if enabled and seconds > 0:
                summary[f"logs.{log_type}"] = self.format_retention_time(seconds)
            else:
                summary[f"logs.{log_type}"] = "Disabled"

        # Cleanup interval
        interval = self._policy.get('settings', {}).get('cleanup_interval_seconds', 3600)
        summary['cleanup_interval'] = self.format_retention_time(interval)

        # Dry run status
        summary['dry_run'] = "Enabled" if self.is_dry_run() else "Disabled"

        return summary


# Global singleton instance
_retention_policy = None


def get_retention_policy() -> RetentionPolicy:
    """
    Get the global RetentionPolicy instance.

    Returns:
        The singleton RetentionPolicy instance.
    """
    global _retention_policy
    if _retention_policy is None:
        _retention_policy = RetentionPolicy()
    return _retention_policy


# ============================================
# Convenience functions for direct access
# ============================================

def set_file_retention_minutes(
    storage_type: str,
    minutes: int,
    enabled: bool = True,
    updated_by: Optional[str] = None
) -> bool:
    """
    Set file retention in minutes.

    Args:
        storage_type: 'working_db', 'storage_db', or 'filesystem'
        minutes: How long to keep files in minutes (0 = forever)
        enabled: Whether retention is enabled
        updated_by: Who made the change

    Returns:
        True if successful
    """
    return get_retention_policy().set_file_retention(
        storage_type,
        minutes * 60,
        enabled,
        updated_by
    )


def set_log_retention_minutes(
    log_type: str,
    minutes: int,
    enabled: bool = True,
    updated_by: Optional[str] = None
) -> bool:
    """
    Set log retention in minutes.

    Args:
        log_type: Log type to configure
        minutes: How long to keep logs in minutes (0 = forever)
        enabled: Whether retention is enabled
        updated_by: Who made the change

    Returns:
        True if successful
    """
    return get_retention_policy().set_log_retention(
        log_type,
        minutes * 60,
        enabled,
        updated_by
    )


def set_all_retention_minutes(
    minutes: int,
    enabled: bool = True,
    updated_by: Optional[str] = None
) -> bool:
    """
    Set the same retention period for all data types.

    Args:
        minutes: How long to keep data in minutes (0 = forever)
        enabled: Whether retention is enabled
        updated_by: Who made the change

    Returns:
        True if all updates successful
    """
    policy = get_retention_policy()
    success = True

    # Set file retention
    for storage_type in ['working_db', 'storage_db', 'filesystem']:
        if not policy.set_file_retention(storage_type, minutes * 60, enabled, updated_by):
            success = False

    # Set log retention
    for log_type in ['access_logs', 'failed_upload_logs', 'virus_scan_logs', 'approval_requests']:
        if not policy.set_log_retention(log_type, minutes * 60, enabled, updated_by):
            success = False

    return success
