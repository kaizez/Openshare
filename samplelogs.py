#!/usr/bin/env python3
"""
Sample Log Injection Script
Injects sample security logs into the SIEM system to demonstrate detection rules.
"""

import requests
import time
from datetime import datetime

BASE_URL = "http://localhost:5001"  # Change to 5000 if using default port
USERNAME = "admin"
PASSWORD = "admin123"


def login():
    """Login and return session."""
    session = requests.Session()
    try:
        response = session.post(f"{BASE_URL}/login", data={
            'username': USERNAME,
            'password': PASSWORD
        }, timeout=5)
        
        if response.status_code == 200 or response.status_code == 302:
            print("✓ Login successful")
            return session
        else:
            print(f"✗ Login failed: Status {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"✗ Login error: {e}")
        print(f"  Make sure the Flask app is running on {BASE_URL}")
        return None


def inject_normal_logs(session):
    """Inject some normal, non-suspicious logs."""
    print("\n[Injecting Normal Logs]")
    
    normal_logs = [
        {
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': 'Normal file download - document.pdf',
            'user_id': 'user001',
            'ip_address': '192.168.1.10',
            'file_name': 'document.pdf',
            'user_role': 'standard',
            'file_size': 1024000,  # 1MB
            'result': 'success',
            'severity': 'Info'
        },
        {
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': 'Normal file download - image.jpg',
            'user_id': 'user002',
            'ip_address': '192.168.1.11',
            'file_name': 'image.jpg',
            'user_role': 'standard',
            'file_size': 2048000,  # 2MB
            'result': 'success',
            'severity': 'Info'
        },
        {
            'log_source': 'file_transfer_server',
            'event_type': 'login_attempt',
            'description': 'Successful login',
            'user_id': 'user001',
            'ip_address': '192.168.1.10',
            'result': 'success',
            'severity': 'Info'
        }
    ]
    
    for log in normal_logs:
        try:
            response = session.post(f"{BASE_URL}/api/ingest_log", json=log, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered'):
                    print(f"  ⚠️  Alert triggered: {result.get('alert', {}).get('alert_type')}")
                else:
                    print(f"  ✓ Log ingested: {log['description']}")
            else:
                print(f"  ✗ Failed to ingest: {log['description']}")
        except Exception as e:
            print(f"  ✗ Error: {e}")
        time.sleep(0.2)


def trigger_suspicious_volume(session):
    """Trigger Rule 1: Suspicious Volume (10+ files in 60 seconds)."""
    print("\n[Triggering Suspicious Volume Alert]")
    print("  Sending 11 file downloads rapidly...")
    
    user_id = 'user123'
    for i in range(11):
        log_data = {
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': f'File {i+1} downloaded by user',
            'user_id': user_id,
            'ip_address': '192.168.1.100',
            'file_name': f'file_{i+1}.pdf',
            'user_role': 'standard',
            'file_size': 512000,  # 500KB each
            'result': 'success',
            'severity': 'Info'
        }
        
        try:
            response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered'):
                    alert = result.get('alert', {})
                    print(f"  🚨 ALERT TRIGGERED: {alert.get('alert_type')} - {alert.get('description')}")
                    print(f"     Severity: {alert.get('severity')}")
                    break
            time.sleep(0.1)  # Small delay between requests
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print("  ✓ Suspicious volume test completed")


def trigger_failed_login_attempts(session):
    """Trigger Rule 2: Failed Login Attempts (5+ failures from same IP)."""
    print("\n[Triggering Failed Login Attempts Alert]")
    print("  Sending 5 failed login attempts from same IP...")
    
    ip_address = '192.168.1.200'
    for i in range(5):
        log_data = {
            'log_source': 'file_transfer_server',
            'event_type': 'login_attempt',
            'description': f'Failed login attempt {i+1}',
            'ip_address': ip_address,
            'result': 'failure',
            'severity': 'Medium'
        }
        
        try:
            response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered'):
                    alert = result.get('alert', {})
                    print(f"  🚨 ALERT TRIGGERED: {alert.get('alert_type')} - {alert.get('description')}")
                    print(f"     Severity: {alert.get('severity')}")
                    break
            time.sleep(0.2)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print("  ✓ Failed login attempts test completed")


def trigger_unauthorized_file_access(session):
    """Trigger Rule 3: Unauthorized File Type (config file access without admin role)."""
    print("\n[Triggering Unauthorized File Access Alert - CRITICAL]")
    print("  Attempting to access config file without admin role...")
    
    log_data = {
        'log_source': 'file_transfer_server',
        'event_type': 'file_access',
        'description': 'Attempt to access configuration file',
        'file_name': 'config.ini',
        'user_id': 'user456',
        'ip_address': '192.168.1.150',
        'user_role': 'standard',  # Not admin!
        'result': 'success',
        'severity': 'Critical'
    }
    
    try:
        response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            if result.get('alert_triggered'):
                alert = result.get('alert', {})
                print(f"  🚨 ALERT TRIGGERED: {alert.get('alert_type')} - {alert.get('description')}")
                print(f"     Severity: {alert.get('severity')}")
            else:
                print("  ⚠️  No alert triggered (this might be expected)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    print("  ✓ Unauthorized file access test completed")


def trigger_large_data_transfer(session):
    """Trigger Rule 4: Large Data Transfer (100MB+ in 5 minutes)."""
    print("\n[Triggering Large Data Transfer Alert]")
    print("  Sending large file transfers...")
    
    user_id = 'user789'
    # Send multiple large files to exceed 100MB threshold
    file_sizes = [30 * 1024 * 1024, 35 * 1024 * 1024, 40 * 1024 * 1024]  # 30MB, 35MB, 40MB
    
    for i, file_size in enumerate(file_sizes):
        log_data = {
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': f'Large file {i+1} downloaded',
            'user_id': user_id,
            'ip_address': '192.168.1.175',
            'file_name': f'large_file_{i+1}.zip',
            'user_role': 'standard',
            'file_size': file_size,
            'result': 'success',
            'severity': 'Info'
        }
        
        try:
            response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered'):
                    alert = result.get('alert', {})
                    print(f"  🚨 ALERT TRIGGERED: {alert.get('alert_type')} - {alert.get('description')}")
                    print(f"     Severity: {alert.get('severity')}")
                    break
            time.sleep(0.2)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print("  ✓ Large data transfer test completed")


def trigger_failed_access_attempts(session):
    """Trigger Rule 5: Failed Access Attempts (5+ failures from same IP)."""
    print("\n[Triggering Failed Access Attempts Alert]")
    print("  Sending 5 failed file access attempts...")
    
    ip_address = '192.168.1.250'
    for i in range(5):
        log_data = {
            'log_source': 'file_transfer_server',
            'event_type': 'file_access',
            'description': f'Failed file access attempt {i+1}',
            'ip_address': ip_address,
            'file_name': f'protected_file_{i+1}.txt',
            'result': 'failure',
            'severity': 'Medium'
        }
        
        try:
            response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                if result.get('alert_triggered'):
                    alert = result.get('alert', {})
                    print(f"  🚨 ALERT TRIGGERED: {alert.get('alert_type')} - {alert.get('description')}")
                    print(f"     Severity: {alert.get('severity')}")
                    break
            time.sleep(0.2)
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print("  ✓ Failed access attempts test completed")


def main():
    """Main function to run all sample log injections."""
    print("=" * 60)
    print("SIEM Sample Log Injection Script")
    print("=" * 60)
    print(f"\nConnecting to: {BASE_URL}")
    print(f"Username: {USERNAME}")
    
    # Login
    session = login()
    if not session:
        print("\n❌ Cannot proceed without login. Please check:")
        print("   1. Flask app is running")
        print("   2. URL is correct (default: http://localhost:5001)")
        print("   3. Credentials are correct")
        return
    
    print("\n" + "=" * 60)
    print("Starting log injection...")
    print("=" * 60)
    
    # Inject normal logs first
    inject_normal_logs(session)
    time.sleep(1)
    
    # Trigger various alerts
    trigger_suspicious_volume(session)
    time.sleep(1)
    
    trigger_failed_login_attempts(session)
    time.sleep(1)
    
    trigger_unauthorized_file_access(session)
    time.sleep(1)
    
    trigger_large_data_transfer(session)
    time.sleep(1)
    
    trigger_failed_access_attempts(session)
    
    print("\n" + "=" * 60)
    print("✅ Sample log injection completed!")
    print("=" * 60)
    print("\nCheck your dashboard at:")
    print(f"  {BASE_URL}/dashboard")
    print("\nYou should see:")
    print("  - Multiple security logs in the logs table")
    print("  - Several alerts in the alerts section")
    print("  - Playbook action buttons on alerts")
    print("\n" + "=" * 60)


if __name__ == '__main__':
    main()
