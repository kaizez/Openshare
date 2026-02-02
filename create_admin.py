"""
Create default admin account for the authentication system.
Run this script to set up the super admin account.
"""

import sqlite3
import os
from argon2 import PasswordHasher
from datetime import datetime

# Path to the database
db_path = os.path.join(os.path.dirname(__file__), 'instance', 'users.db')

def create_default_admin():
    """Create the default super admin account"""

    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        print("Please run the app first to create the database.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if admin already exists
    cursor.execute("SELECT id, username, email, is_admin, is_super_admin FROM users WHERE username = ?", ('admin',))
    existing = cursor.fetchone()

    if existing:
        print("Admin account already exists!")
        print(f"  ID: {existing[0]}")
        print(f"  Username: {existing[1]}")
        print(f"  Email: {existing[2]}")
        print(f"  Is Admin: {existing[3]}")
        print(f"  Is Super Admin: {existing[4]}")

        # Update to super admin if not already
        if not existing[4]:
            cursor.execute("UPDATE users SET is_admin = 1, is_super_admin = 1 WHERE username = ?", ('admin',))
            conn.commit()
            print("\n  Updated to Super Admin status!")

        conn.close()
        return

    # Hash the password using Argon2id
    ph = PasswordHasher()
    password_hash = ph.hash('admin')

    # Insert new admin user
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, is_admin, is_super_admin, mfa_enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, ('admin', 'culturequest.mail@gmail.com', password_hash, 1, 1, 0, datetime.utcnow()))

    conn.commit()
    conn.close()

    print("=" * 50)
    print("Default Admin Account Created Successfully!")
    print("=" * 50)
    print(f"  Username: admin")
    print(f"  Password: admin")
    print(f"  Email: culturequest.mail@gmail.com")
    print(f"  Role: Super Admin")
    print("=" * 50)
    print("\nIMPORTANT: Change the password after first login!")
    print("\nSuper Admin Features:")
    print("  - No MAC address verification required")
    print("  - Can promote/demote other users to admin")
    print("  - Full access to admin dashboard")
    print("=" * 50)


if __name__ == '__main__':
    create_default_admin()
