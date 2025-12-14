# Sample Log Injection Guide

This guide shows you how to inject sample logs to test the IDIR Dashboard system and trigger all detection rules.

## Quick Start: Automated Test Script

The easiest way to test all detection rules is using the automated test script:

### Prerequisites
```bash
pip install requests
```

### Run the Test Script
1. **Start the Flask application** in one terminal:
   ```bash
   python app.py
   ```

2. **Run the test script** in another terminal:
   ```bash
   python test_system.py
   ```

This will automatically test all three detection rules:
- ✓ Suspicious Volume Detection (High Severity)
- ✓ Failed Access Attempts (Medium Severity)  
- ✓ Unauthorized File Type Access (Critical Severity)

---

## Manual Log Injection Methods

### Method 1: Using Python (Interactive)

#### Step 1: Login and Create Session
```python
import requests
from datetime import datetime

# Create session
session = requests.Session()

# Login
response = session.post('http://localhost:5000/login', data={
    'username': '240612R',
    'password': 'ispj2025'
})

print(f"Login status: {response.status_code}")
```

#### Step 2: Inject Logs

**Example 1: Trigger Suspicious Volume Detection (10+ files in 60 seconds)**
```python
# Send 11 file downloads rapidly
for i in range(11):
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'log_source': 'file_transfer_server',
        'event_type': 'file_download',
        'description': f'File {i+1} downloaded',
        'severity': 'Info',
        'user_id': 'malicious_user',
        'ip_address': '192.168.1.100',
        'file_name': f'document_{i+1}.pdf',
        'result': 'success'
    }
    
    response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
    result = response.json()
    print(f"File {i+1}: Alert={result.get('alert_triggered')}")
    
    if result.get('alert_triggered'):
        print(f"ALERT: {result['alert']['description']}")
        break
```

**Example 2: Trigger Failed Access Attempts Detection (5 consecutive failures)**
```python
# Send 5 failed login attempts from same IP
ip_address = '10.0.0.50'

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
    
    response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
    result = response.json()
    print(f"Attempt {i+1}: Alert={result.get('alert_triggered')}")
    
    if result.get('alert_triggered'):
        print(f"ALERT: {result['alert']['description']}")
        break
```

**Example 3: Trigger Unauthorized File Type Detection (Config file access)**
```python
# Attempt to access configuration file without admin role
log_data = {
    'timestamp': datetime.utcnow().isoformat(),
    'log_source': 'file_transfer_server',
    'event_type': 'file_access',
    'description': 'Access attempt to configuration file',
    'severity': 'Info',
    'user_id': 'standard_user',
    'ip_address': '172.16.0.50',
    'file_name': 'database.config',  # Config file extension
    'user_role': 'standard',  # Not admin/administrator/system
    'result': 'success'
}

response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
result = response.json()

if result.get('alert_triggered'):
    print(f"CRITICAL ALERT: {result['alert']['description']}")
    if result.get('soar_response'):
        print(f"SOAR Action: {result['soar_response']['message']}")
```

**Example 4: Normal Activity (Should NOT trigger alerts)**
```python
# Normal file download - should not trigger any alerts
log_data = {
    'timestamp': datetime.utcnow().isoformat(),
    'log_source': 'file_transfer_server',
    'event_type': 'file_download',
    'description': 'Normal file download',
    'severity': 'Info',
    'user_id': 'user123',
    'ip_address': '192.168.1.200',
    'file_name': 'report.pdf',
    'result': 'success'
}

response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
result = response.json()
print(f"Normal activity - Alert triggered: {result.get('alert_triggered')}")  # Should be False
```

---

### Method 2: Using curl (Command Line)

#### Step 1: Login and Save Session Cookie
```bash
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=240612R&password=ispj2025"
```

#### Step 2: Inject Logs

**Example: Trigger Suspicious Volume**
```bash
# Send multiple file downloads
for i in {1..11}; do
  curl -b cookies.txt -X POST http://localhost:5000/api/ingest_log \
    -H "Content-Type: application/json" \
    -d "{
      \"log_source\": \"file_transfer_server\",
      \"event_type\": \"file_download\",
      \"description\": \"File $i downloaded\",
      \"severity\": \"Info\",
      \"user_id\": \"test_user\",
      \"ip_address\": \"192.168.1.100\",
      \"file_name\": \"file_$i.pdf\",
      \"result\": \"success\"
    }"
  sleep 0.1
done
```

**Example: Trigger Unauthorized File Type (Critical Alert)**
```bash
curl -b cookies.txt -X POST http://localhost:5000/api/ingest_log \
  -H "Content-Type: application/json" \
  -d '{
    "log_source": "file_transfer_server",
    "event_type": "file_access",
    "description": "Config file access attempt",
    "severity": "Info",
    "user_id": "standard_user",
    "ip_address": "10.0.0.100",
    "file_name": "app.cfg",
    "user_role": "standard",
    "result": "success"
  }'
```

**Example: Trigger Failed Access Attempts**
```bash
# Send 5 failed attempts
for i in {1..5}; do
  curl -b cookies.txt -X POST http://localhost:5000/api/ingest_log \
    -H "Content-Type: application/json" \
    -d "{
      \"log_source\": \"file_transfer_server\",
      \"event_type\": \"access_attempt\",
      \"description\": \"Failed attempt $i\",
      \"severity\": \"Info\",
      \"ip_address\": \"10.0.0.50\",
      \"result\": \"failure\"
    }"
done
```

---

### Method 3: Complete Python Script Example

Save this as `inject_samples.py`:

```python
#!/usr/bin/env python3
"""
Sample log injection script for IDIR Dashboard.
Demonstrates all three detection rules.
"""

import requests
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"

def login():
    """Login and return session."""
    session = requests.Session()
    response = session.post(f"{BASE_URL}/login", data={
        'username': '240612R',
        'password': 'ispj2025'
    })
    if response.status_code == 200:
        print("✓ Logged in successfully")
        return session
    else:
        print("✗ Login failed")
        return None

def inject_log(session, log_data):
    """Inject a single log entry."""
    response = session.post(f"{BASE_URL}/api/ingest_log", json=log_data)
    return response.json()

# Main execution
if __name__ == "__main__":
    print("Starting log injection samples...")
    
    session = login()
    if not session:
        exit(1)
    
    # Sample 1: Suspicious Volume
    print("\n[1] Testing Suspicious Volume Detection...")
    for i in range(11):
        log = {
            'log_source': 'file_transfer_server',
            'event_type': 'file_download',
            'description': f'File {i+1} download',
            'severity': 'Info',
            'user_id': 'suspicious_user',
            'ip_address': '192.168.1.50',
            'file_name': f'file_{i+1}.pdf',
            'result': 'success'
        }
        result = inject_log(session, log)
        if result.get('alert_triggered'):
            print(f"  ✓ Alert triggered: {result['alert']['description']}")
            break
    
    time.sleep(1)
    
    # Sample 2: Failed Access Attempts
    print("\n[2] Testing Failed Access Attempts Detection...")
    for i in range(5):
        log = {
            'log_source': 'file_transfer_server',
            'event_type': 'access_attempt',
            'description': f'Failed attempt {i+1}',
            'severity': 'Info',
            'ip_address': '10.0.0.100',
            'result': 'failure'
        }
        result = inject_log(session, log)
        if result.get('alert_triggered'):
            print(f"  ✓ Alert triggered: {result['alert']['description']}")
            break
    
    time.sleep(1)
    
    # Sample 3: Unauthorized File Type (CRITICAL)
    print("\n[3] Testing Unauthorized File Type Detection...")
    log = {
        'log_source': 'file_transfer_server',
        'event_type': 'file_access',
        'description': 'Config file access',
        'severity': 'Info',
        'user_id': 'regular_user',
        'ip_address': '172.16.0.50',
        'file_name': 'settings.ini',  # Config file
        'user_role': 'standard',  # Not authorized
        'result': 'success'
    }
    result = inject_log(session, log)
    if result.get('alert_triggered'):
        print(f"  ✓ CRITICAL Alert: {result['alert']['description']}")
        if result.get('soar_response'):
            print(f"  ✓ SOAR Action: {result['soar_response']['message']}")
    
    print("\n✓ All samples injected! Check the dashboard:")
    print(f"  {BASE_URL}/dashboard")
```

Run it:
```bash
python inject_samples.py
```

---

## Sample JSON Payloads

### Payload Structure

All log payloads should be JSON objects with these fields:

```json
{
  "timestamp": "2025-07-12T16:00:00",      // Optional - auto-generated if missing
  "log_source": "file_transfer_server",    // Required - source of log
  "event_type": "file_download",           // Required - type of event
  "description": "Human readable text",    // Required - description
  "severity": "Info",                      // Required - severity level
  "user_id": "user123",                    // Optional - user identifier
  "ip_address": "192.168.1.100",          // Optional - IP address
  "file_name": "document.pdf",             // Optional - file name
  "user_role": "standard",                 // Optional - user role
  "result": "success"                      // Optional - success/failure
}
```

### Detection Rule 1: Suspicious Volume

**Trigger:** 10+ file downloads by same user within 60 seconds

**Sample Payload:**
```json
{
  "log_source": "file_transfer_server",
  "event_type": "file_download",
  "description": "File downloaded by user",
  "severity": "Info",
  "user_id": "malicious_user",
  "ip_address": "192.168.1.100",
  "file_name": "document.pdf",
  "result": "success"
}
```

**Expected Alert:**
- Severity: **High**
- Alert Type: "Suspicious Volume"
- Description: "User {user_id} downloaded {count} files within 60 seconds"

---

### Detection Rule 2: Failed Access Attempts

**Trigger:** 5 consecutive failed access attempts from same IP

**Sample Payload:**
```json
{
  "log_source": "file_transfer_server",
  "event_type": "access_attempt",
  "description": "Failed login attempt",
  "severity": "Info",
  "ip_address": "10.0.0.50",
  "result": "failure"
}
```

**Expected Alert:**
- Severity: **Medium**
- Alert Type: "Failed Access Attempts"
- Description: "5 consecutive failed access attempts from IP {ip_address}"

---

### Detection Rule 3: Unauthorized File Type (CRITICAL)

**Trigger:** Attempt to access config files (`.cfg`, `.ini`, `.conf`, `.config`) without admin role

**Sample Payload:**
```json
{
  "log_source": "file_transfer_server",
  "event_type": "file_access",
  "description": "Configuration file access attempt",
  "severity": "Info",
  "user_id": "standard_user",
  "ip_address": "172.16.0.50",
  "file_name": "app.config",
  "user_role": "standard",
  "result": "success"
}
```

**Expected Alert:**
- Severity: **Critical**
- Alert Type: "Unauthorized File Type"
- Description: "Unauthorized access attempt to configuration file {file_name}"
- **SOAR Action:** IP address will be automatically quarantined

---

## Viewing Results

After injecting logs:

1. **Check the Dashboard:**
   - Open: `http://localhost:5000/dashboard`
   - View "Recent Security Logs" for all ingested events
   - View "Quarantined IPs" for any IPs automatically quarantined

2. **Check API Response:**
   - Each API call returns a JSON response indicating if an alert was triggered
   - If an alert triggers, the response includes alert details and SOAR actions

3. **Release Quarantined IPs:**
   - Go to dashboard
   - Click "Release IP" button next to any quarantined IP
   - Or use the API response to verify the quarantine action

---

## Troubleshooting

**Problem: Login fails**
- Ensure Flask app is running (`python app.py`)
- Check credentials: `240612R` / `ispj2025`
- Check URL: `http://localhost:5000`

**Problem: No alerts triggered**
- Ensure you're sending the exact required number of events (11 for volume, 5 for failures)
- Check that timestamps are recent (within detection window)
- Verify event types match exactly: `file_download`, `access_attempt`, `file_access`

**Problem: API returns error**
- Ensure you're logged in (session cookie is set)
- Check JSON format is valid
- Verify all required fields are present

---

## Tips

1. **Use the test script first** - It's the easiest way to verify everything works
2. **Check timestamps** - Detection rules use time windows (60 seconds, 5 minutes)
3. **Monitor the dashboard** - Real-time view of all logs and alerts
4. **Test one rule at a time** - Clearer to see individual rule behavior
5. **Use unique IPs/users** - Avoid mixing test data from different scenarios

---

For more information, see the main **README.md** file.

