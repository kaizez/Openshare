#!/usr/bin/env python3
"""Test database connection and operations"""

from db import get_db
from datetime import datetime, timedelta

def test_connection():
    """Test basic database connection"""
    print("Testing database connection...")
    try:
        db = get_db()
        print("✓ Database connection successful!")
        return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False

def test_metadata_operations():
    """Test basic CRUD operations"""
    print("\nTesting metadata operations...")
    try:
        db = get_db()

        # Test insert
        test_file_id = "test_file_123"
        test_metadata = {
            'original_filename': 'test.txt',
            'stored_filename': 'test_file_123.txt',
            'file_size': 1024,
            'file_hash': 'abc123def456',
            'upload_time': datetime.now().isoformat(),
            'download_count': 0,
            'classification': 'Public',
            'detected_mime': 'text/plain',
            'current_otp_code': 'TEST1234ABCD5678',
            'otp_generated_at': datetime.now().isoformat(),
            'otp_expires_at': (datetime.now() + timedelta(hours=24)).isoformat(),
            'otp_used': False
        }

        db.save_file_metadata(test_file_id, test_metadata)
        print("✓ Insert test passed")

        # Test retrieve
        retrieved = db.get_file_metadata(test_file_id)
        if retrieved and retrieved['original_filename'] == 'test.txt':
            print("✓ Retrieve test passed")
        else:
            print("✗ Retrieve test failed")
            return False

        # Test update
        test_metadata['download_count'] = 5
        db.save_file_metadata(test_file_id, test_metadata)
        retrieved = db.get_file_metadata(test_file_id)
        if retrieved and retrieved['download_count'] == 5:
            print("✓ Update test passed")
        else:
            print("✗ Update test failed")
            return False

        # Test access log
        db.add_access_log(test_file_id, 'test', 'Test log entry', '127.0.0.1')
        logs = db.get_access_logs(test_file_id)
        if logs and len(logs) > 0:
            print("✓ Access log test passed")
        else:
            print("✗ Access log test failed")
            return False

        # Test delete
        db.delete_file_metadata(test_file_id)
        retrieved = db.get_file_metadata(test_file_id)
        if retrieved is None:
            print("✓ Delete test passed")
        else:
            print("✗ Delete test failed")
            return False

        return True
    except Exception as e:
        print(f"✗ Metadata operations test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("Database Connection Test")
    print("=" * 50)

    if test_connection():
        if test_metadata_operations():
            print("\n" + "=" * 50)
            print("All tests passed! ✓")
            print("=" * 50)
        else:
            print("\n" + "=" * 50)
            print("Some tests failed!")
            print("=" * 50)
    else:
        print("\n" + "=" * 50)
        print("Connection test failed!")
        print("=" * 50)
