# Testing Guide - How to Inject Sample Data

This guide shows how to test the SIEM by injecting sample events and triggering alerts.

## Prerequisites

Make sure the SIEM is running:

```bash
docker-compose up --build
```

Dashboard should be at `http://localhost:5001`

---

## Option 1: Use the Sample Log Script

Run the included test script:

```bash
python samplelogs.py
```

This will:
- Login to the SIEM
- Inject normal logs
- Trigger each detection rule
- Show results in terminal

---

## Option 2: Manual Testing with Python

### Setup

```python
import os
import requests
import time

# Login and get session (uses first account from USERS env var)
username, password = os.environ['USERS'].split(',')[0].split(':', 1)
session = requests.Session()
session.post('http://localhost:5001/login', data={
    'username': username.strip(),
    'password': password.strip()
})
```

### Test 1: Trigger Failed Login Alert

```python
# Send 5 failed logins from same IP
for i in range(5):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'login_attempt',
        'user_id': f'user{i}',
        'ip_address': '192.168.1.100',
        'result': 'failure',
        'description': f'Failed login attempt {i+1}'
    })

# Check dashboard - should see "Failed Login Attempts" alert
```

### Test 2: Trigger Brute Force Success Alert

```python
# First, send some failed logins
for i in range(3):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'login_attempt',
        'user_id': 'victim',
        'ip_address': '10.0.0.50',
        'result': 'failure'
    })

# Then a successful login from same IP
session.post('http://localhost:5001/api/ingest_log', json={
    'event_type': 'login_success',
    'user_id': 'victim',
    'ip_address': '10.0.0.50',
    'result': 'success'
})

# Check dashboard - should see "Brute Force Success" alert
```

### Test 3: Trigger Suspicious Download Volume Alert

```python
# Send 11 file downloads rapidly (same user)
for i in range(11):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'file_download',
        'user_id': 'suspicious_user',
        'ip_address': '192.168.1.50',
        'file_name': f'file_{i}.pdf',
        'result': 'success'
    })
    time.sleep(0.1)

# Check dashboard - should see "Suspicious Volume" alert
```

### Test 4: Trigger Unauthorized File Access Alert

```python
# Non-admin trying to access config file
session.post('http://localhost:5001/api/ingest_log', json={
    'event_type': 'file_access',
    'user_id': 'normal_user',
    'ip_address': '192.168.1.100',
    'file_name': 'database.env',  # Sensitive file
    'user_role': 'standard',       # Not admin
    'result': 'success'
})

# Check dashboard - should see "Unauthorized File Access" alert (Critical)
```

### Test 5: Trigger Large Data Transfer Alert

```python
# Send downloads totaling over 100MB
for i in range(5):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'file_download',
        'user_id': 'data_thief',
        'ip_address': '192.168.1.200',
        'file_name': f'big_file_{i}.zip',
        'file_size': 25000000,  # 25MB each = 125MB total
        'result': 'success'
    })

# Check dashboard - should see "Large Data Transfer" alert
```

### Test 6: Trigger Mass Deletion Alert

```python
# Delete 10+ files in 2 minutes
for i in range(12):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'file_delete',
        'user_id': 'angry_employee',
        'ip_address': '192.168.1.150',
        'file_name': f'important_doc_{i}.pdf'
    })

# Check dashboard - should see "Mass File Deletion" alert (Critical)
```

### Test 7: Trigger Failed MFA Alert

```python
# 5 failed MFA attempts
for i in range(5):
    session.post('http://localhost:5001/api/ingest_log', json={
        'event_type': 'mfa_failed',
        'user_id': 'mfa_victim',
        'ip_address': '192.168.1.100'
    })

# Check dashboard - should see "Failed MFA Attempts" alert (Critical)
```

### Test 8: Trigger Privilege Escalation Alert

```python
session.post('http://localhost:5001/api/ingest_log', json={
    'event_type': 'permission_changed',
    'user_id': 'admin',
    'ip_address': '192.168.1.100',
    'target_user': 'hacker',
    'old_role': 'standard',
    'new_role': 'admin',
    'changed_by': 'hacker'  # Self-escalation = Critical
})

# Check dashboard - should see "Privilege Escalation" alert
```

### Test 9: Trigger Sensitive Data Detection (DLP)

```python
# File with sensitive name
session.post('http://localhost:5001/api/ingest_log', json={
    'event_type': 'file_upload',
    'user_id': 'user123',
    'ip_address': '192.168.1.100',
    'file_name': 'customer_passwords.csv',  # Suspicious filename
    'file_size': 5000
})

# Check dashboard - should see DLP alert
```

---

## Option 3: Test with cURL

```bash
# Login and save cookie
curl -c cookies.txt -X POST http://localhost:5001/login \
  -d "username=$USERNAME&password=$PASSWORD"

# Send a test log
curl -b cookies.txt -X POST http://localhost:5001/api/ingest_log \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "file_download",
    "user_id": "test_user",
    "ip_address": "192.168.1.100",
    "file_name": "test.pdf",
    "result": "success"
  }'
```

---

## Option 4: Test with API Key (No Login)

First, create an API key in the dashboard or via API:

```bash
# Login first
curl -c cookies.txt -X POST http://localhost:5001/login \
  -d "username=$USERNAME&password=$PASSWORD"

# Create API key
curl -b cookies.txt -X POST http://localhost:5001/api/keys \
  -H "Content-Type: application/json" \
  -d '{"key_name": "test_key"}'

# Save the returned api_key value
```

Then use the API key:

```bash
curl -X POST http://localhost:5001/api/ingest_log \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -d '{
    "event_type": "file_download",
    "user_id": "api_user",
    "ip_address": "10.0.0.1",
    "file_name": "document.pdf",
    "result": "success"
  }'
```

---

## Test Playbook Actions

After alerts appear in the dashboard:

1. **Block IP**: Click "Block IP" button on an alert
2. **Terminate Session**: Click "Terminate Session" button
3. **Quarantine File**: Click "Quarantine File" button
4. **Release IP**: Go to Quarantined IPs section, click "Release"

All actions are logged and visible in Security Logs.

---

## Create a Honeytoken

Test the honeytoken (decoy file) feature:

```bash
# Create a honeytoken
curl -b cookies.txt -X POST http://localhost:5001/api/honeytokens \
  -H "Content-Type: application/json" \
  -d '{
    "file_name": "passwords.txt",
    "description": "Decoy password file"
  }'
```

Then trigger it:

```python
session.post('http://localhost:5001/api/ingest_log', json={
    'event_type': 'file_access',
    'user_id': 'attacker',
    'ip_address': '192.168.1.200',
    'file_name': 'passwords.txt'  # The honeytoken
})

# Check dashboard - should see "Honeytoken Access" alert (Critical)
```

---

## Verify in Dashboard

After running tests:

1. Go to `http://localhost:5001`
2. Login with `admin` / (your `ADMIN_PASSWORD` from `.env`)
3. Check:
   - **Statistics cards** - Should show counts
   - **Security Logs table** - Should show your events
   - **Active Alerts** - Should show triggered alerts
   - **Quarantined Items** - After using playbook actions

---

## Troubleshooting

### No alerts appearing?

- Make sure you're sending enough events to trigger thresholds
- Check the event_type matches exactly (e.g., `file_download` not `download`)
- Check the result field (e.g., `failure` for failed logins)

### Connection refused?

- Make sure Docker containers are running: `docker ps`
- Check port 5001 is not blocked

### Login fails?

- Username is `admin`, password is whatever you set in `.env` as `ADMIN_PASSWORD`
- If the admin user doesn't exist, make sure `ADMIN_PASSWORD` was set before the first container start
