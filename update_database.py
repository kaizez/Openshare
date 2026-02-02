"""
Database migration script to add password reset, 2FA OTP, MFA TOTP, admin security, and account lockout columns to User table.
Run this script once to update the existing database schema.
"""

import sqlite3
import os

# Path to the database
db_path = os.path.join(os.path.dirname(__file__), 'instance', 'users.db')

def update_database():
    """Add new columns to the User table if they don't exist"""

    # Check if database exists
    if not os.path.exists(db_path):
        print("Database does not exist yet. It will be created when you run the app.")
        return

    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get current columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]

    print(f"Current columns in 'users' table: {columns}")

    # List of new columns to add
    new_columns = [
        ('reset_token', 'VARCHAR(100)'),
        ('reset_token_expiry', 'DATETIME'),
        ('otp_secret', 'VARCHAR(10)'),
        ('otp_expiry', 'DATETIME'),
        ('mfa_enabled', 'BOOLEAN DEFAULT 0'),
        ('mfa_secret', 'VARCHAR(32)'),
        ('is_admin', 'BOOLEAN DEFAULT 0'),
        ('is_super_admin', 'BOOLEAN DEFAULT 0'),
        ('whitelisted_devices', 'TEXT'),
        ('whitelisted_ips', 'TEXT'),
        ('registered_mac_address', 'VARCHAR(17)'),
        ('mac_address_registered', 'BOOLEAN DEFAULT 0'),
        ('failed_login_attempts', 'INTEGER DEFAULT 0'),
        ('account_locked', 'BOOLEAN DEFAULT 0'),
        ('locked_until', 'DATETIME'),
        ('last_failed_login', 'DATETIME')
    ]

    # Add missing columns
    columns_added = []
    for col_name, col_type in new_columns:
        if col_name not in columns:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                columns_added.append(col_name)
                print(f"[+] Added column: {col_name}")
            except sqlite3.OperationalError as e:
                print(f"[x] Error adding column {col_name}: {e}")
        else:
            print(f"[-] Column {col_name} already exists")

    # Commit changes
    conn.commit()
    conn.close()

    if columns_added:
        print(f"\n[SUCCESS] Database updated successfully! Added {len(columns_added)} new column(s).")
    else:
        print("\n[SUCCESS] Database schema is already up to date.")

if __name__ == '__main__':
    print("=" * 70)
    print("Database Migration Script - Adding Security & Account Lockout Columns")
    print("=" * 70)
    print()
    update_database()
    print()
    print("=" * 60)
