#!/usr/bin/env python3
"""Test file storage in database (BLOB)"""

from db import get_db
from datetime import datetime, timedelta

def test_blob_storage():
    """Test storing and retrieving file content in database"""
    print("Testing BLOB storage...")
    try:
        db = get_db()

        # Create test file content
        test_content = b"This is a test file content with binary data: \x00\x01\x02\xff"
        test_file_id = "test_blob_123"

        test_metadata = {
            'original_filename': 'test.bin',
            'stored_filename': 'test_blob_123.bin',
            'file_size': len(test_content),
            'file_hash': 'abc123',
            'upload_time': datetime.now().isoformat(),
            'download_count': 0,
            'classification': 'Public',
            'detected_mime': 'application/octet-stream',
            'current_otp_code': 'TESTCODE12345678',
            'otp_generated_at': datetime.now().isoformat(),
            'otp_expires_at': (datetime.now() + timedelta(hours=24)).isoformat(),
            'otp_used': False
        }

        # Test insert with file content
        print("1. Inserting file with content...")
        success = db.save_file_metadata(test_file_id, test_metadata, test_content)
        if not success:
            print("✗ Insert failed")
            return False
        print("✓ Insert successful")

        # Test retrieve without content (for performance)
        print("2. Retrieving metadata without content...")
        retrieved = db.get_file_metadata(test_file_id, include_content=False)
        if not retrieved:
            print("✗ Retrieve failed")
            return False
        if 'file_content' in retrieved:
            print("✗ Content should not be included")
            return False
        print("✓ Metadata retrieved (content excluded)")

        # Test retrieve with content
        print("3. Retrieving metadata with content...")
        retrieved_with_content = db.get_file_metadata(test_file_id, include_content=True)
        if not retrieved_with_content:
            print("✗ Retrieve with content failed")
            return False
        if 'file_content' not in retrieved_with_content:
            print("✗ Content should be included")
            return False
        if retrieved_with_content['file_content'] != test_content:
            print("✗ Content mismatch")
            print(f"Expected: {test_content}")
            print(f"Got: {retrieved_with_content['file_content']}")
            return False
        print("✓ Content retrieved and matches")

        # Test update without changing content
        print("4. Updating metadata without changing content...")
        test_metadata['download_count'] = 5
        success = db.save_file_metadata(test_file_id, test_metadata)  # No file_content
        if not success:
            print("✗ Update failed")
            return False

        # Verify content is still there
        retrieved = db.get_file_metadata(test_file_id, include_content=True)
        if retrieved['file_content'] != test_content:
            print("✗ Content was lost during update")
            return False
        if retrieved['download_count'] != 5:
            print("✗ Metadata update failed")
            return False
        print("✓ Update successful, content preserved")

        # Clean up
        print("5. Deleting file...")
        db.delete_file_metadata(test_file_id)
        retrieved = db.get_file_metadata(test_file_id)
        if retrieved is not None:
            print("✗ Delete failed")
            return False
        print("✓ Delete successful")

        return True

    except Exception as e:
        print(f"✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 50)
    print("BLOB Storage Test")
    print("=" * 50)

    if test_blob_storage():
        print("\n" + "=" * 50)
        print("All BLOB storage tests passed! ✓")
        print("=" * 50)
    else:
        print("\n" + "=" * 50)
        print("BLOB storage tests failed!")
        print("=" * 50)
