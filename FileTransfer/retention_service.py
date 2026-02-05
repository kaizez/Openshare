#!/usr/bin/env python3
"""
MoveIT Data Retention Service

This service runs periodically to clean up files and logs based on the
configured retention policy. It deletes files that are older than their
retention period from:
- Working DB (file metadata and content)
- Storage DB (archived files)
- Filesystem (uploads folder)
- Various log tables

Each file is evaluated individually based on its upload_time.
"""

import os
import sys
import time
import signal
import glob
from datetime import datetime
from typing import Dict, List, Tuple
import mysql.connector
from mysql.connector import Error

from retention_policy import get_retention_policy, RetentionPolicy

# Database configurations
WORKING_DB_CONFIG = {
    'host': os.environ.get('WORKING_DB_HOST', 'working-db'),
    'user': os.environ.get('WORKING_DB_USER', 'working_user'),
    'password': os.environ.get('WORKING_DB_PASSWORD', 'working_pass_2024'),
    'database': os.environ.get('WORKING_DB_NAME', 'workingdb'),
    'port': int(os.environ.get('WORKING_DB_PORT', 3306))
}

STORAGE_DB_CONFIG = {
    'host': os.environ.get('STORAGE_DB_HOST', 'storage-db'),
    'user': os.environ.get('STORAGE_DB_USER', 'storage_user'),
    'password': os.environ.get('STORAGE_DB_PASSWORD', 'storage_pass_2024'),
    'database': os.environ.get('STORAGE_DB_NAME', 'storagedb'),
    'port': int(os.environ.get('STORAGE_DB_PORT', 3306))
}

UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/app/uploads')

running = True


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global running
    print(f"[Retention] Received signal {signum}, shutting down...")
    running = False


def get_connection(config: Dict, name: str):
    """Create a database connection."""
    try:
        conn = mysql.connector.connect(**config)
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"[Retention] Failed to connect to {name}: {e}")
    return None


class RetentionService:
    """
    Service that enforces data retention policies by deleting old files and logs.
    """

    def __init__(self):
        """Initialize the retention service."""
        self.policy = get_retention_policy()
        self.stats = {
            'working_db_files': 0,
            'storage_db_files': 0,
            'filesystem_files': 0,
            'access_logs': 0,
            'failed_upload_logs': 0,
            'virus_scan_logs': 0,
            'approval_requests': 0,
            'errors': 0
        }

    def reset_stats(self):
        """Reset cleanup statistics."""
        for key in self.stats:
            self.stats[key] = 0

    def get_stats(self) -> Dict[str, int]:
        """Get current cleanup statistics."""
        return self.stats.copy()

    def cleanup_working_db_files(self, conn) -> int:
        """
        Delete old files from Working DB based on retention policy.

        Args:
            conn: MySQL connection to Working DB

        Returns:
            Number of files deleted
        """
        settings = self.policy.get_file_retention('working_db')
        if not settings.get('enabled', False):
            print("[Retention] Working DB file retention is disabled")
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            print("[Retention] Working DB retention is set to forever")
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor(dictionary=True)

            # Find files older than retention period
            cursor.execute("""
                SELECT file_id, original_filename, stored_filename, upload_time
                FROM file_metadata
                WHERE upload_time < %s
            """, (cutoff_time,))

            files_to_delete = cursor.fetchall()
            deleted_count = 0

            for file in files_to_delete:
                if dry_run:
                    print(f"[Retention][DRY-RUN] Would delete from Working DB: "
                          f"{file['original_filename']} (uploaded {file['upload_time']})")
                else:
                    try:
                        # Delete from file_metadata (access_logs cascade delete)
                        cursor.execute(
                            "DELETE FROM file_metadata WHERE file_id = %s",
                            (file['file_id'],)
                        )
                        deleted_count += 1
                        print(f"[Retention] Deleted from Working DB: {file['original_filename']} "
                              f"(file_id: {file['file_id']})")
                    except Error as e:
                        print(f"[Retention] Error deleting {file['file_id']}: {e}")
                        self.stats['errors'] += 1

            if not dry_run:
                conn.commit()

            cursor.close()
            self.stats['working_db_files'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning Working DB: {e}")
            self.stats['errors'] += 1
            return 0

    def cleanup_storage_db_files(self, conn) -> int:
        """
        Delete old files from Storage DB based on retention policy.

        Args:
            conn: MySQL connection to Storage DB

        Returns:
            Number of files deleted
        """
        settings = self.policy.get_file_retention('storage_db')
        if not settings.get('enabled', False):
            print("[Retention] Storage DB file retention is disabled")
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            print("[Retention] Storage DB retention is set to forever")
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor(dictionary=True)

            # Find files older than retention period
            cursor.execute("""
                SELECT file_id, original_filename, upload_time
                FROM file_metadata
                WHERE upload_time < %s
            """, (cutoff_time,))

            files_to_delete = cursor.fetchall()
            deleted_count = 0

            for file in files_to_delete:
                if dry_run:
                    print(f"[Retention][DRY-RUN] Would delete from Storage DB: "
                          f"{file['original_filename']} (uploaded {file['upload_time']})")
                else:
                    try:
                        # Delete access logs first
                        cursor.execute(
                            "DELETE FROM access_logs WHERE file_id = %s",
                            (file['file_id'],)
                        )
                        # Delete file metadata
                        cursor.execute(
                            "DELETE FROM file_metadata WHERE file_id = %s",
                            (file['file_id'],)
                        )
                        deleted_count += 1
                        print(f"[Retention] Deleted from Storage DB: {file['original_filename']} "
                              f"(file_id: {file['file_id']})")
                    except Error as e:
                        print(f"[Retention] Error deleting {file['file_id']}: {e}")
                        self.stats['errors'] += 1

            if not dry_run:
                conn.commit()

            cursor.close()
            self.stats['storage_db_files'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning Storage DB: {e}")
            self.stats['errors'] += 1
            return 0

    def cleanup_filesystem(self, working_conn) -> int:
        """
        Delete old files from the filesystem based on retention policy.

        Uses upload_time from the database to determine file age.

        Args:
            working_conn: MySQL connection to Working DB (to get file info)

        Returns:
            Number of files deleted
        """
        settings = self.policy.get_file_retention('filesystem')
        if not settings.get('enabled', False):
            print("[Retention] Filesystem retention is disabled")
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            print("[Retention] Filesystem retention is set to forever")
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = working_conn.cursor(dictionary=True)

            # Get files older than retention period
            cursor.execute("""
                SELECT file_id, stored_filename, upload_time
                FROM file_metadata
                WHERE upload_time < %s
            """, (cutoff_time,))

            files_to_delete = cursor.fetchall()
            deleted_count = 0

            for file in files_to_delete:
                file_path = os.path.join(UPLOAD_FOLDER, file['stored_filename'])

                if os.path.exists(file_path):
                    if dry_run:
                        print(f"[Retention][DRY-RUN] Would delete file: {file_path}")
                    else:
                        try:
                            os.remove(file_path)
                            deleted_count += 1
                            print(f"[Retention] Deleted file: {file_path}")
                        except OSError as e:
                            print(f"[Retention] Error deleting file {file_path}: {e}")
                            self.stats['errors'] += 1

            cursor.close()

            # Also clean up orphaned files (files on disk without DB entry)
            orphan_count = self._cleanup_orphaned_files(working_conn, dry_run)
            deleted_count += orphan_count

            self.stats['filesystem_files'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning filesystem: {e}")
            self.stats['errors'] += 1
            return 0

    def _cleanup_orphaned_files(self, working_conn, dry_run: bool) -> int:
        """
        Clean up files on disk that don't have a corresponding DB entry.

        Args:
            working_conn: MySQL connection to Working DB
            dry_run: If True, only log without deleting

        Returns:
            Number of orphaned files deleted
        """
        if not os.path.exists(UPLOAD_FOLDER):
            return 0

        try:
            cursor = working_conn.cursor()
            deleted_count = 0

            # Get all stored filenames from DB
            cursor.execute("SELECT stored_filename FROM file_metadata")
            db_files = {row[0] for row in cursor.fetchall()}
            cursor.close()

            # Check each file on disk
            for filename in os.listdir(UPLOAD_FOLDER):
                file_path = os.path.join(UPLOAD_FOLDER, filename)

                # Skip directories
                if os.path.isdir(file_path):
                    continue

                # Check if file exists in DB
                if filename not in db_files:
                    # Check if file is older than filesystem retention
                    settings = self.policy.get_file_retention('filesystem')
                    retention_seconds = settings.get('retention_seconds', 0)

                    if retention_seconds > 0:
                        file_mtime = os.path.getmtime(file_path)
                        file_age = time.time() - file_mtime

                        if file_age > retention_seconds:
                            if dry_run:
                                print(f"[Retention][DRY-RUN] Would delete orphaned file: {file_path}")
                            else:
                                try:
                                    os.remove(file_path)
                                    deleted_count += 1
                                    print(f"[Retention] Deleted orphaned file: {file_path}")
                                except OSError as e:
                                    print(f"[Retention] Error deleting orphaned file {file_path}: {e}")
                                    self.stats['errors'] += 1

            return deleted_count

        except Exception as e:
            print(f"[Retention] Error cleaning orphaned files: {e}")
            return 0

    def cleanup_access_logs(self, conn) -> int:
        """
        Delete old access logs from Working DB.

        Args:
            conn: MySQL connection to Working DB

        Returns:
            Number of log entries deleted
        """
        settings = self.policy.get_log_retention('access_logs')
        if not settings.get('enabled', False):
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor()

            if dry_run:
                cursor.execute(
                    "SELECT COUNT(*) FROM access_logs WHERE timestamp < %s",
                    (cutoff_time,)
                )
                count = cursor.fetchone()[0]
                print(f"[Retention][DRY-RUN] Would delete {count} access logs")
                cursor.close()
                return 0

            cursor.execute(
                "DELETE FROM access_logs WHERE timestamp < %s",
                (cutoff_time,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()

            if deleted_count > 0:
                print(f"[Retention] Deleted {deleted_count} access logs")

            self.stats['access_logs'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning access logs: {e}")
            self.stats['errors'] += 1
            return 0

    def cleanup_failed_upload_logs(self, conn) -> int:
        """
        Delete old failed upload logs.

        Args:
            conn: MySQL connection to Working DB

        Returns:
            Number of log entries deleted
        """
        settings = self.policy.get_log_retention('failed_upload_logs')
        if not settings.get('enabled', False):
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor()

            if dry_run:
                cursor.execute(
                    "SELECT COUNT(*) FROM failed_upload_logs WHERE timestamp < %s",
                    (cutoff_time,)
                )
                count = cursor.fetchone()[0]
                print(f"[Retention][DRY-RUN] Would delete {count} failed upload logs")
                cursor.close()
                return 0

            cursor.execute(
                "DELETE FROM failed_upload_logs WHERE timestamp < %s",
                (cutoff_time,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()

            if deleted_count > 0:
                print(f"[Retention] Deleted {deleted_count} failed upload logs")

            self.stats['failed_upload_logs'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning failed upload logs: {e}")
            self.stats['errors'] += 1
            return 0

    def cleanup_virus_scan_logs(self, conn) -> int:
        """
        Delete old virus scan logs.

        Args:
            conn: MySQL connection to Working DB

        Returns:
            Number of log entries deleted
        """
        settings = self.policy.get_log_retention('virus_scan_logs')
        if not settings.get('enabled', False):
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor()

            if dry_run:
                cursor.execute(
                    "SELECT COUNT(*) FROM virus_scan_logs WHERE timestamp < %s",
                    (cutoff_time,)
                )
                count = cursor.fetchone()[0]
                print(f"[Retention][DRY-RUN] Would delete {count} virus scan logs")
                cursor.close()
                return 0

            cursor.execute(
                "DELETE FROM virus_scan_logs WHERE timestamp < %s",
                (cutoff_time,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()

            if deleted_count > 0:
                print(f"[Retention] Deleted {deleted_count} virus scan logs")

            self.stats['virus_scan_logs'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning virus scan logs: {e}")
            self.stats['errors'] += 1
            return 0

    def cleanup_approval_requests(self, conn) -> int:
        """
        Delete old approval requests.

        Args:
            conn: MySQL connection to Working DB

        Returns:
            Number of requests deleted
        """
        settings = self.policy.get_log_retention('approval_requests')
        if not settings.get('enabled', False):
            return 0

        retention_seconds = settings.get('retention_seconds', 0)
        if retention_seconds == 0:
            return 0

        cutoff_time = self.policy.get_cutoff_time(retention_seconds)
        dry_run = self.policy.is_dry_run()

        try:
            cursor = conn.cursor()

            if dry_run:
                cursor.execute(
                    "SELECT COUNT(*) FROM approval_requests WHERE created_at < %s",
                    (cutoff_time,)
                )
                count = cursor.fetchone()[0]
                print(f"[Retention][DRY-RUN] Would delete {count} approval requests")
                cursor.close()
                return 0

            cursor.execute(
                "DELETE FROM approval_requests WHERE created_at < %s",
                (cutoff_time,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()

            if deleted_count > 0:
                print(f"[Retention] Deleted {deleted_count} approval requests")

            self.stats['approval_requests'] = deleted_count
            return deleted_count

        except Error as e:
            print(f"[Retention] Error cleaning approval requests: {e}")
            self.stats['errors'] += 1
            return 0

    def run_cleanup(self) -> Dict[str, int]:
        """
        Run a complete cleanup cycle.

        Returns:
            Statistics dict with counts of deleted items per category
        """
        print(f"[Retention] Starting cleanup at {datetime.now().isoformat()}")
        self.reset_stats()

        # Reload policy to pick up any changes
        self.policy.reload()

        # Print current policy summary
        summary = self.policy.get_policy_summary()
        print("[Retention] Current policy:")
        for key, value in summary.items():
            print(f"  {key}: {value}")

        # Connect to databases
        working_conn = get_connection(WORKING_DB_CONFIG, "Working DB")
        storage_conn = get_connection(STORAGE_DB_CONFIG, "Storage DB")

        if not working_conn:
            print("[Retention] Failed to connect to Working DB, aborting cleanup")
            return self.stats

        try:
            # Clean up files
            if working_conn:
                self.cleanup_working_db_files(working_conn)
                self.cleanup_filesystem(working_conn)

            if storage_conn:
                self.cleanup_storage_db_files(storage_conn)

            # Clean up logs (all in Working DB)
            if working_conn:
                self.cleanup_access_logs(working_conn)
                self.cleanup_failed_upload_logs(working_conn)
                self.cleanup_virus_scan_logs(working_conn)
                self.cleanup_approval_requests(working_conn)

            # Print summary
            print(f"[Retention] Cleanup completed at {datetime.now().isoformat()}")
            print(f"[Retention] Summary:")
            print(f"  Working DB files deleted: {self.stats['working_db_files']}")
            print(f"  Storage DB files deleted: {self.stats['storage_db_files']}")
            print(f"  Filesystem files deleted: {self.stats['filesystem_files']}")
            print(f"  Access logs deleted: {self.stats['access_logs']}")
            print(f"  Failed upload logs deleted: {self.stats['failed_upload_logs']}")
            print(f"  Virus scan logs deleted: {self.stats['virus_scan_logs']}")
            print(f"  Approval requests deleted: {self.stats['approval_requests']}")
            print(f"  Errors: {self.stats['errors']}")

            return self.stats

        finally:
            if working_conn:
                working_conn.close()
            if storage_conn:
                storage_conn.close()


def main():
    """Main entry point for the retention service."""
    global running

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=" * 50)
    print("MoveIT Data Retention Service")
    print("=" * 50)

    service = RetentionService()
    policy = get_retention_policy()

    # Print initial configuration
    print(f"Config file: {policy.config_path}")
    summary = policy.get_policy_summary()
    print("Initial policy:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("=" * 50)

    # Wait for databases to be ready
    print("[Retention] Waiting for databases to be ready...")
    time.sleep(15)

    while running:
        try:
            service.run_cleanup()
        except Exception as e:
            print(f"[Retention] Error during cleanup: {e}")
            import traceback
            traceback.print_exc()

        # Wait for next cleanup cycle
        interval = policy.get_cleanup_interval()
        print(f"[Retention] Next cleanup in {interval} seconds...")

        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    print("[Retention] Service stopped")


if __name__ == '__main__':
    main()
