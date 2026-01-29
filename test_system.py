"""
Sample script to test the IDIR Dashboard system.
This script demonstrates how to ingest logs and trigger detection rules.
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"

def test_login():
    """Test login and return session."""
    session = requests.Session()
    response = session.post(f"{BASE_URL}/login", data={
        'username': '240612R',
        'password': 'ispj2025'
    })
    
    if response.status_code == 200 and 'dashboard' in response.url:
        print("✓ Login successful")
        return session
    else:
        print("✗ Login failed")
        return None

def ingest_log(session, log_data):
    """Ingest a log entry via API."""
    response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data)
    return response.json()

def test_suspicious_volume(session):
    """Test Rule 1: Suspicious Volume Detection."""
    print("\n=== Testing Suspicious Volume Detection ===")
    print("Sending 11 file download events within 60 seconds...")
    
    user_id = "test_user_001"
    ip_address = "192.168.1.50"
    
    for i in range(11):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': f'File {i+1} downloaded by user',
            'severity': 'Info',
            'user_id': user_id,
            'ip_address': ip_address,
            'file_name': f'document_{i+1}.pdf',
            'result': 'success'
        }
        
        result = ingest_log(session, log_data)
        if result.get('alert_triggered'):
            print(f"✓ Alert triggered on file {i+1}: {result['alert']['description']}")
            break
        
        time.sleep(0.1)  # Small delay between requests

def test_failed_access_attempts(session):
    """Test Rule 2: Failed Access Attempts."""
    print("\n=== Testing Failed Access Attempts Detection ===")
    print("Sending 5 consecutive failed access attempts...")
    
    ip_address = "10.0.0.100"
    
    for i in range(5):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'log_source': 'file_transfer_server',
            'event_type': 'access_attempt',
            'description': f'Failed login attempt {i+1}',
            'severity': 'Info',
            'ip_address': ip_address,
            'result': 'failure'
        }
        
        result = ingest_log(session, log_data)
        if result.get('alert_triggered'):
            print(f"✓ Alert triggered on attempt {i+1}: {result['alert']['description']}")
            break
        
        time.sleep(0.1)

def test_unauthorized_file_type(session):
    """Test Rule 3: Unauthorized File Type Access."""
    print("\n=== Testing Unauthorized File Type Detection ===")
    print("Attempting to access configuration file with standard role...")
    
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'log_source': 'file_transfer_server',
        'event_type': 'file_access',
        'description': 'Access attempt to configuration file',
        'severity': 'Info',
        'user_id': 'standard_user',
        'ip_address': '172.16.0.50',
        'file_name': 'app.config',
        'user_role': 'standard',
        'result': 'success'
    }
    
    result = ingest_log(session, log_data)
    if result.get('alert_triggered'):
        print(f"✓ Alert triggered: {result['alert']['description']}")
        if result.get('soar_response'):
            print(f"  SOAR Response: {result['soar_response']['message']}")
    else:
        print("✗ Alert not triggered (unexpected)")

def test_normal_activity(session):
    """Test normal activity that should not trigger alerts."""
    print("\n=== Testing Normal Activity ===")
    print("Sending normal file download events...")
    
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'log_source': 'file_transfer_server',
        'event_type': 'file_download',
        'description': 'Normal file download',
        'severity': 'Info',
        'user_id': 'user_normal',
        'ip_address': '192.168.1.200',
        'file_name': 'report.pdf',
        'result': 'success'
    }
    
    result = ingest_log(session, log_data)
    if not result.get('alert_triggered'):
        print("✓ Normal activity processed without alerts (expected)")
    else:
        print("✗ Alert triggered for normal activity (unexpected)")

def main():
    """Run all tests."""
    print("=" * 60)
    print("IDIR Dashboard System Test Script")
    print("=" * 60)
    
    # Test login
    session = test_login()
    if not session:
        print("\n✗ Cannot proceed without login. Please check:")
        print("  1. Flask application is running (python app.py)")
        print("  2. Default credentials are correct")
        return
    
    # Run tests
    test_normal_activity(session)
    test_suspicious_volume(session)
    time.sleep(2)  # Wait between tests
    test_failed_access_attempts(session)
    time.sleep(2)
    test_unauthorized_file_type(session)
    
    print("\n" + "=" * 60)
    print("Test completed! Check the dashboard for results:")
    print(f"  {BASE_URL}/dashboard")
    print("=" * 60)

if __name__ == "__main__":
    main()

