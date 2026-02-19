#!/usr/bin/env python3
"""
Migration script to fix current_otp_code column size
Increases VARCHAR(16) or VARCHAR(255) to VARCHAR(512) to accommodate encrypted OTP codes
"""

import os
import mysql.connector
from mysql.connector import Error

# Working DB Configuration
WORKING_DB_CONFIG = {
    'host': os.environ.get('WORKING_DB_HOST', 'working-db'),
    'user': os.environ.get('WORKING_DB_USER', 'working_user'),
    'password': os.environ.get('WORKING_DB_PASSWORD', 'working_pass_2024'),
    'database': os.environ.get('WORKING_DB_NAME', 'workingdb'),
    'port': int(os.environ.get('WORKING_DB_PORT', 3306))
}

# Storage DB Configuration
STORAGE_DB_CONFIG = {
    'host': os.environ.get('STORAGE_DB_HOST', 'storage-db'),
    'user': os.environ.get('STORAGE_DB_USER', 'storage_user'),
    'password': os.environ.get('STORAGE_DB_PASSWORD', 'storage_pass_2024'),
    'database': os.environ.get('STORAGE_DB_NAME', 'storagedb'),
    'port': int(os.environ.get('STORAGE_DB_PORT', 3306))
}


def migrate_database(config, db_name):
    """Migrate a database to fix the current_otp_code column size"""
    try:
        print(f"\n[Migration] Connecting to {db_name}...")
        conn = mysql.connector.connect(**config)
        
        if not conn.is_connected():
            print(f"[Migration] Failed to connect to {db_name}")
            return False
        
        cursor = conn.cursor()
        
        # Check if the table exists
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.tables 
            WHERE table_schema = %s AND table_name = 'file_metadata'
        """, (config['database'],))
        
        table_exists = cursor.fetchone()[0] > 0
        
        if not table_exists:
            print(f"[Migration] Table file_metadata does not exist in {db_name}, skipping...")
            cursor.close()
            conn.close()
            return True
        
        # Check current column size
        cursor.execute("""
            SELECT CHARACTER_MAXIMUM_LENGTH 
            FROM information_schema.columns 
            WHERE table_schema = %s 
            AND table_name = 'file_metadata' 
            AND column_name = 'current_otp_code'
        """, (config['database'],))
        
        result = cursor.fetchone()
        if result:
            current_size = result[0]
            print(f"[Migration] Current current_otp_code size in {db_name}: VARCHAR({current_size})")
            
            if current_size and current_size >= 512:
                print(f"[Migration] Column already has sufficient size in {db_name}, skipping...")
                cursor.close()
                conn.close()
                return True
        
        # Alter the column
        print(f"[Migration] Altering current_otp_code column in {db_name} to VARCHAR(512)...")
        cursor.execute("""
            ALTER TABLE file_metadata 
            MODIFY COLUMN current_otp_code VARCHAR(512)
        """)
        
        conn.commit()
        print(f"[Migration] ✓ Successfully migrated {db_name}")
        
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        print(f"[Migration] ✗ Error migrating {db_name}: {e}")
        return False


def main():
    print("=" * 60)
    print("OpenShare Database Migration")
    print("Fixing current_otp_code column size for encrypted OTPs")
    print("=" * 60)
    
    # Migrate Working DB
    success_working = migrate_database(WORKING_DB_CONFIG, "Working DB")
    
    # Migrate Storage DB
    success_storage = migrate_database(STORAGE_DB_CONFIG, "Storage DB")
    
    print("\n" + "=" * 60)
    if success_working and success_storage:
        print("✓ Migration completed successfully!")
    else:
        print("✗ Migration completed with errors")
        if not success_working:
            print("  - Working DB migration failed")
        if not success_storage:
            print("  - Storage DB migration failed")
    print("=" * 60)
    
    return 0 if (success_working and success_storage) else 1


if __name__ == '__main__':
    import sys
    import time
    
    # Wait for databases to be ready
    print("[Migration] Waiting 15 seconds for databases to be ready...")
    time.sleep(15)
    
    sys.exit(main())
