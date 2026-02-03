#!/usr/bin/env python3
"""
MoveIT Sync Service
Syncs data from Working DB to Storage DB periodically.
Runs as a separate container with access to both databases.
"""

import os
import time
import signal
import sys
import mysql.connector
from mysql.connector import Error
from datetime import datetime

# Configuration from environment
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

SYNC_INTERVAL = int(os.environ.get('SYNC_INTERVAL_SECONDS', 3600))
DELETE_AGE = int(os.environ.get('DELETE_FILES_OLDER_THAN_SECONDS', 0))

running = True


def signal_handler(signum, frame):
    global running
    print(f"[Sync] Received signal {signum}, shutting down...")
    running = False


def get_connection(config, name):
    """Create database connection"""
    try:
        conn = mysql.connector.connect(**config)
        if conn.is_connected():
            print(f"[Sync] Connected to {name}")
            return conn
    except Error as e:
        print(f"[Sync] Failed to connect to {name}: {e}")
    return None


def ensure_tables(conn):
    """Ensure required tables exist in Storage DB"""
    cursor = conn.cursor()

    # Create file_metadata table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_metadata (
            file_id VARCHAR(255) PRIMARY KEY,
            original_filename VARCHAR(500) NOT NULL,
            stored_filename VARCHAR(500) NOT NULL,
            file_size BIGINT NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            upload_time DATETIME NOT NULL,
            download_count INT DEFAULT 0,
            classification VARCHAR(50) NOT NULL,
            detected_mime VARCHAR(100),
            current_otp_code VARCHAR(16),
            otp_generated_at DATETIME,
            otp_expires_at DATETIME,
            otp_used BOOLEAN DEFAULT FALSE,
            file_content LONGBLOB NOT NULL,
            synced_at DATETIME,
            INDEX idx_upload_time (upload_time)
        )
    """)

    # Create access_logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INT PRIMARY KEY,
            file_id VARCHAR(255) NOT NULL,
            timestamp DATETIME NOT NULL,
            status VARCHAR(50) NOT NULL,
            details TEXT,
            ip_address VARCHAR(45),
            INDEX idx_file_id (file_id),
            INDEX idx_timestamp (timestamp)
        )
    """)

    conn.commit()
    cursor.close()


def sync_files(working_conn, storage_conn):
    """
    Sync file_metadata from Working DB to Storage DB and archive old files.
    
    NOTE: This function does NOT delete files from Storage DB. File deletion from 
    Storage DB only happens when explicitly requested via the DELETE /delete/<file_id> 
    API endpoint (called by the main app when a user deletes a file).
    """
    working_cursor = working_conn.cursor(dictionary=True)
    storage_cursor = storage_conn.cursor()

    # Get all files from Working DB that aren't archived yet
    # SECURITY: Only sync files with scan_status='clean' or NULL (old files without VT scan)
    # This prevents 'pending' and 'malicious' files from reaching Storage DB
    working_cursor.execute("""
        SELECT * FROM file_metadata 
        WHERE (is_archived = FALSE OR is_archived IS NULL)
        AND (scan_status = 'clean' OR scan_status IS NULL)
    """)
    files = working_cursor.fetchall()

    synced = 0
    archived = 0
    
    for file in files:
        try:
            # Insert/Update in Storage DB
            storage_cursor.execute("""
                INSERT INTO file_metadata
                (file_id, original_filename, stored_filename, file_size, file_hash,
                 upload_time, download_count, classification, detected_mime,
                 current_otp_code, otp_generated_at, otp_expires_at, otp_used,
                 file_content, synced_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    download_count = VALUES(download_count),
                    current_otp_code = VALUES(current_otp_code),
                    otp_generated_at = VALUES(otp_generated_at),
                    otp_expires_at = VALUES(otp_expires_at),
                    otp_used = VALUES(otp_used),
                    file_content = VALUES(file_content),
                    synced_at = VALUES(synced_at)
            """, (
                file['file_id'],
                file['original_filename'],
                file['stored_filename'],
                file['file_size'],
                file['file_hash'],
                file['upload_time'],
                file['download_count'],
                file['classification'],
                file['detected_mime'],
                file['current_otp_code'],
                file['otp_generated_at'],
                file['otp_expires_at'],
                file['otp_used'],
                file['file_content'],
                datetime.now()
            ))
            synced += 1
            
            # Archive file from Working DB if old enough (delete file_content, keep metadata)
            if DELETE_AGE > 0:
                upload_time = file['upload_time']
                age_seconds = (datetime.now() - upload_time).total_seconds()
                
                if age_seconds >= DELETE_AGE:
                    # Set file_content to NULL and mark as archived
                    archive_cursor = working_conn.cursor()
                    archive_cursor.execute(
                        "UPDATE file_metadata SET file_content = NULL, is_archived = TRUE WHERE file_id = %s",
                        (file['file_id'],)
                    )
                    archive_cursor.close()
                    archived += 1
                    print(f"[Sync] Archived {file['file_id']} (age: {age_seconds:.0f}s, content moved to Storage DB)")
                    
        except Error as e:
            print(f"[Sync] Error syncing file {file['file_id']}: {e}")

    storage_conn.commit()
    working_conn.commit()  # Commit archiving
    working_cursor.close()
    storage_cursor.close()
    
    return synced, archived


def sync_logs(working_conn, storage_conn):
    """Sync access_logs from Working DB to Storage DB"""
    working_cursor = working_conn.cursor(dictionary=True)
    storage_cursor = storage_conn.cursor()

    # Get all logs from Working DB
    working_cursor.execute("SELECT * FROM access_logs")
    logs = working_cursor.fetchall()

    synced = 0
    for log in logs:
        try:
            storage_cursor.execute("""
                INSERT INTO access_logs
                (id, file_id, timestamp, status, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    details = VALUES(details)
            """, (
                log['id'],
                log['file_id'],
                log['timestamp'],
                log['status'],
                log.get('details'),
                log.get('ip_address')
            ))
            synced += 1
        except Error as e:
            print(f"[Sync] Error syncing log {log['id']}: {e}")

    storage_conn.commit()
    working_cursor.close()
    storage_cursor.close()
    return synced


def run_sync():
    """Run one sync cycle"""
    print(f"[Sync] Starting sync at {datetime.now().isoformat()}")

    # Connect to databases
    working_conn = get_connection(WORKING_DB_CONFIG, "Working DB")
    storage_conn = get_connection(STORAGE_DB_CONFIG, "Storage DB")

    if not working_conn or not storage_conn:
        print("[Sync] Failed to connect to databases, skipping sync")
        return False

    try:
        # Ensure tables exist in Storage DB
        ensure_tables(storage_conn)

        # Sync files
        files_synced, files_archived = sync_files(working_conn, storage_conn)
        print(f"[Sync] Synced {files_synced} files, archived {files_archived} old files (content moved to Storage DB)")

        # Sync logs
        logs_synced = sync_logs(working_conn, storage_conn)
        print(f"[Sync] Synced {logs_synced} access logs")

        print(f"[Sync] Sync completed at {datetime.now().isoformat()}")
        return True

    except Error as e:
        print(f"[Sync] Sync error: {e}")
        return False
    finally:
        if working_conn:
            working_conn.close()
        if storage_conn:
            storage_conn.close()


# ============================================
# Flask API for File Retrieval
# ============================================
from flask import Flask, jsonify
import threading

api = Flask(__name__)

@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200


@api.route('/retrieve/<file_id>', methods=['GET'])
def retrieve_file(file_id):
    """Retrieve archived file content from Storage DB"""
    try:
        # Connect to Storage DB
        storage_conn = get_connection(STORAGE_DB_CONFIG, "Storage DB")
        if not storage_conn:
            return jsonify({'error': 'Could not connect to Storage DB'}), 500
        
        try:
            cursor = storage_conn.cursor(dictionary=True, buffered=True)
            cursor.execute(
                "SELECT file_content FROM file_metadata WHERE file_id = %s",
                (file_id,)
            )
            row = cursor.fetchone()
            cursor.close()
            
            if not row or not row['file_content']:
                return jsonify({'error': 'File not found in Storage DB'}), 404
            
            # Return file content as bytes
            return row['file_content'], 200, {'Content-Type': 'application/octet-stream'}
            
        finally:
            storage_conn.close()
            
    except Exception as e:
        print(f"[API] Error retrieving file {file_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api.route('/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete a file from Storage DB (only when explicitly requested by main app)"""
    try:
        print(f"[API] Delete request received for file {file_id}")
        
        # Connect to Storage DB
        storage_conn = get_connection(STORAGE_DB_CONFIG, "Storage DB")
        if not storage_conn:
            return jsonify({'error': 'Could not connect to Storage DB'}), 500
        
        try:
            cursor = storage_conn.cursor()
            
            # Check if file exists first
            cursor.execute("SELECT file_id FROM file_metadata WHERE file_id = %s", (file_id,))
            row = cursor.fetchone()
            
            if not row:
                cursor.close()
                print(f"[API] File {file_id} not found in Storage DB")
                return jsonify({'error': 'File not found in Storage DB'}), 404
            
            # Delete the file (access logs will be cascaded if foreign key exists)
            cursor.execute("DELETE FROM file_metadata WHERE file_id = %s", (file_id,))
            
            # Also delete associated access logs
            cursor.execute("DELETE FROM access_logs WHERE file_id = %s", (file_id,))
            
            storage_conn.commit()
            cursor.close()
            
            print(f"[API] Successfully deleted file {file_id} from Storage DB")
            return jsonify({'success': True, 'message': 'File deleted from Storage DB'}), 200
            
        except Error as e:
            storage_conn.rollback()
            print(f"[API] Database error deleting file {file_id}: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            storage_conn.close()
            
    except Exception as e:
        print(f"[API] Error deleting file {file_id}: {e}")
        return jsonify({'error': str(e)}), 500


def run_api():
    """Run Flask API in a separate thread"""
    api.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)


def main():
    global running

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=" * 50)
    print("MoveIT Sync Service")
    print("=" * 50)
    print(f"Working DB: {WORKING_DB_CONFIG['host']}:{WORKING_DB_CONFIG['port']}")
    print(f"Storage DB: {STORAGE_DB_CONFIG['host']}:{STORAGE_DB_CONFIG['port']}")
    print(f"Sync Interval: {SYNC_INTERVAL} seconds")
    print(f"Delete Age: {DELETE_AGE} seconds ({'disabled' if DELETE_AGE == 0 else 'enabled'})")
    print(f"API Endpoint: http://0.0.0.0:8080")
    print("=" * 50)

    # Start Flask API in background thread
    print("[API] Starting file retrieval API server...")
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()
    print("[API] API server started on port 8080")

    # Wait for databases to be ready
    print("[Sync] Waiting for databases to be ready...")
    time.sleep(10)

    while running:
        run_sync()

        # Wait for next sync
        print(f"[Sync] Next sync in {SYNC_INTERVAL} seconds...")
        for _ in range(SYNC_INTERVAL):
            if not running:
                break
            time.sleep(1)

    print("[Sync] Service stopped")


if __name__ == '__main__':
    main()
