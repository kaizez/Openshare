#!/usr/bin/env python3
"""
Quick log injection script for testing IDIR Dashboard.
Simple interactive script to inject sample logs.
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"

def print_menu():
    """Print menu options."""
    print("\n" + "="*60)
    print("IDIR Dashboard - Quick Log Injection")
    print("="*60)
    print("1. Inject Suspicious Volume (10+ files) - High Severity")
    print("2. Inject Failed Access Attempts (5 failures) - Medium Severity")
    print("3. Inject Unauthorized Config File Access - Critical Severity")
    print("4. Inject Normal Activity (no alert)")
    print("5. Inject Custom Log")
    print("0. Exit")
    print("="*60)

def login():
    """Login and return session."""
    print("\nLogging in...")
    session = requests.Session()
    try:
        response = session.post(f"{BASE_URL}/login", data={
            'username': '240612R',
            'password': 'ispj2025'
        }, timeout=5)
        
        if response.status_code == 200:
            print("✓ Login successful")
            return session
        else:
            print(f"✗ Login failed: Status {response.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print("✗ Cannot connect to server. Is Flask app running?")
        print(f"  Expected URL: {BASE_URL}")
        return None
    except Exception as e:
        print(f"✗ Login error: {e}")
        return None

def inject_log(session, log_data):
    """Inject log and return result."""
    try:
        response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
        return response.json()
    except Exception as e:
        print(f"✗ Error injecting log: {e}")
        return None

def test_suspicious_volume(session):
    """Test Rule 1: Suspicious Volume."""
    print("\n[Testing Suspicious Volume Detection]")
    print("Sending 11 file downloads...")
    
    user_id = input("Enter user ID (or press Enter for 'test_user'): ").strip() or "test_user"
    ip_address = input("Enter IP address (or press Enter for '192.168.1.100'): ").strip() or "192.168.1.100"
    
    for i in range(11):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': f'File {i+1} downloaded by {user_id}',
            'severity': 'Info',
            'user_id': user_id,
            'ip_address': ip_address,
            'file_name': f'document_{i+1}.pdf',
            'result': 'success'
        }
        
        result = inject_log(session, log_data)
        if result and result.get('alert_triggered'):
            print(f"\n✓ ALERT TRIGGERED on file {i+1}!")
            print(f"  Type: {result['alert']['alert_type']}")
            print(f"  Severity: {result['alert']['severity']}")
            print(f"  Description: {result['alert']['description']}")
            return
        
        print(f"  File {i+1} sent...", end='\r')
    
    print("\n  All files sent (no alert yet - may need more time)")

def test_failed_attempts(session):
    """Test Rule 2: Failed Access Attempts."""
    print("\n[Testing Failed Access Attempts Detection]")
    print("Sending 5 failed login attempts...")
    
    ip_address = input("Enter IP address (or press Enter for '10.0.0.50'): ").strip() or "10.0.0.50"
    
    for i in range(5):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'log_source': 'file_transfer_server',
            'event_type': 'access_attempt',
            'description': f'Failed login attempt {i+1} from {ip_address}',
            'severity': 'Info',
            'ip_address': ip_address,
            'result': 'failure'
        }
        
        result = inject_log(session, log_data)
        if result and result.get('alert_triggered'):
            print(f"\n✓ ALERT TRIGGERED on attempt {i+1}!")
            print(f"  Type: {result['alert']['alert_type']}")
            print(f"  Severity: {result['alert']['severity']}")
            print(f"  Description: {result['alert']['description']}")
            return
        
        print(f"  Attempt {i+1} sent...", end='\r')
    
    print("\n  All attempts sent (no alert yet - may need more time)")

def test_unauthorized_file(session):
    """Test Rule 3: Unauthorized File Type."""
    print("\n[Testing Unauthorized File Type Detection - CRITICAL]")
    
    user_id = input("Enter user ID (or press Enter for 'standard_user'): ").strip() or "standard_user"
    ip_address = input("Enter IP address (or press Enter for '172.16.0.50'): ").strip() or "172.16.0.50"
    file_name = input("Enter config file name (or press Enter for 'database.ini'): ").strip() or "database.ini"
    user_role = input("Enter user role (or press Enter for 'standard'): ").strip() or "standard"
    
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'log_source': 'file_transfer_server',
        'event_type': 'file_access',
        'description': f'Access attempt to configuration file {file_name}',
        'severity': 'Info',
        'user_id': user_id,
        'ip_address': ip_address,
        'file_name': file_name,
        'user_role': user_role,
        'result': 'success'
    }
    
    print(f"\nInjecting log: Access to {file_name} by {user_id} ({user_role})...")
    result = inject_log(session, log_data)
    
    if result:
        if result.get('alert_triggered'):
            print(f"\n✓ CRITICAL ALERT TRIGGERED!")
            print(f"  Type: {result['alert']['alert_type']}")
            print(f"  Severity: {result['alert']['severity']}")
            print(f"  Description: {result['alert']['description']}")
            
            if result.get('soar_response'):
                print(f"\n  SOAR ACTION:")
                print(f"    Action: {result['soar_response']['action']}")
                print(f"    Status: {result['soar_response']['status']}")
                print(f"    Message: {result['soar_response']['message']}")
                if result['soar_response'].get('ip_address'):
                    print(f"    IP Quarantined: {result['soar_response']['ip_address']}")
        else:
            print("\n  No alert triggered (user role may be authorized)")
    else:
        print("\n✗ Failed to inject log")

def test_normal_activity(session):
    """Test normal activity (should not trigger alerts)."""
    print("\n[Testing Normal Activity - Should NOT trigger alerts]")
    
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'log_source': 'file_transfer_server',
        'event_type': 'file_download',
        'description': 'Normal file download activity',
        'severity': 'Info',
        'user_id': 'normal_user',
        'ip_address': '192.168.1.200',
        'file_name': 'report.pdf',
        'result': 'success'
    }
    
    print("Injecting normal log entry...")
    result = inject_log(session, log_data)
    
    if result:
        if not result.get('alert_triggered'):
            print("✓ Normal activity processed (no alert - as expected)")
        else:
            print("✗ Unexpected alert triggered!")
            print(f"  Alert: {result.get('alert', {})}")
    else:
        print("✗ Failed to inject log")

def inject_custom(session):
    """Inject custom log entry."""
    print("\n[Custom Log Injection]")
    print("Enter log details (press Enter for defaults):")
    
    log_data = {
        'log_source': input("Log source [file_transfer_server]: ").strip() or "file_transfer_server",
        'event_type': input("Event type [file_download]: ").strip() or "file_download",
        'description': input("Description: ").strip() or "Custom log entry",
        'severity': input("Severity [Info]: ").strip() or "Info",
        'result': input("Result [success]: ").strip() or "success"
    }
    
    # Optional fields
    user_id = input("User ID (optional): ").strip()
    if user_id:
        log_data['user_id'] = user_id
    
    ip_address = input("IP address (optional): ").strip()
    if ip_address:
        log_data['ip_address'] = ip_address
    
    file_name = input("File name (optional): ").strip()
    if file_name:
        log_data['file_name'] = file_name
    
    user_role = input("User role (optional): ").strip()
    if user_role:
        log_data['user_role'] = user_role
    
    print(f"\nInjecting custom log...")
    print(f"Log data: {json.dumps(log_data, indent=2)}")
    
    result = inject_log(session, log_data)
    
    if result:
        print(f"\n✓ Log ingested successfully")
        print(f"  Status: {result.get('status')}")
        print(f"  Alert triggered: {result.get('alert_triggered', False)}")
        if result.get('alert_triggered'):
            print(f"  Alert: {result['alert']['alert_type']} ({result['alert']['severity']})")
    else:
        print("\n✗ Failed to inject log")

def main():
    """Main interactive loop."""
    print("IDIR Dashboard - Quick Log Injection Tool")
    print("Ensure the Flask application is running before proceeding.")
    
    session = login()
    if not session:
        print("\nCannot proceed without login. Exiting.")
        return
    
    while True:
        print_menu()
        choice = input("\nSelect option: ").strip()
        
        if choice == '0':
            print("\nExiting...")
            break
        elif choice == '1':
            test_suspicious_volume(session)
        elif choice == '2':
            test_failed_attempts(session)
        elif choice == '3':
            test_unauthorized_file(session)
        elif choice == '4':
            test_normal_activity(session)
        elif choice == '5':
            inject_custom(session)
        else:
            print("\nInvalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")

