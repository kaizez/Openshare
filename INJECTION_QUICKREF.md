# Quick Reference: Log Injection

## Three Ways to Inject Sample Logs

### 1. 🚀 Automated Test Script (Easiest)
```bash
# Install requests (one time)
pip install requests

# Run all tests
python test_system.py
```
Tests all 3 detection rules automatically.

### 2. 🎯 Interactive Quick Inject
```bash
# Install requests (one time)
pip install requests

# Run interactive script
python quick_inject.py
```
Interactive menu to test individual rules.

### 3. 📝 Manual Python Code
```python
import requests

session = requests.Session()
session.post('http://localhost:5000/login', data={
    'username': '240612R',
    'password': 'ispj2025'
})

# Inject log
log_data = {
    'log_source': 'file_transfer_server',
    'event_type': 'file_download',
    'description': 'File downloaded',
    'severity': 'Info',
    'user_id': 'user123',
    'ip_address': '192.168.1.100',
    'file_name': 'document.pdf',
    'result': 'success'
}

response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
print(response.json())
```

## Three Detection Rules

### Rule 1: Suspicious Volume (High Severity)
**Trigger:** 10+ file downloads by same user in 60 seconds

**Quick Test:**
```python
# Send 11 file downloads rapidly
for i in range(11):
    session.post('http://localhost:5000/api/ingest_log', json={
        'log_source': 'file_transfer_server',
        'event_type': 'file_download',
        'description': f'File {i+1}',
        'severity': 'Info',
        'user_id': 'test_user',
        'ip_address': '192.168.1.100',
        'file_name': f'file_{i+1}.pdf',
        'result': 'success'
    })
```

### Rule 2: Failed Access Attempts (Medium Severity)
**Trigger:** 5 consecutive failed attempts from same IP

**Quick Test:**
```python
# Send 5 failed attempts
for i in range(5):
    session.post('http://localhost:5000/api/ingest_log', json={
        'log_source': 'file_transfer_server',
        'event_type': 'access_attempt',
        'description': f'Failed attempt {i+1}',
        'severity': 'Info',
        'ip_address': '10.0.0.50',
        'result': 'failure'
    })
```

### Rule 3: Unauthorized File Type (Critical Severity)
**Trigger:** Access to config files (.cfg, .ini, .conf) without admin role

**Quick Test:**
```python
session.post('http://localhost:5000/api/ingest_log', json={
    'log_source': 'file_transfer_server',
    'event_type': 'file_access',
    'description': 'Config file access',
    'severity': 'Info',
    'user_id': 'standard_user',
    'ip_address': '172.16.0.50',
    'file_name': 'app.config',  # Config file
    'user_role': 'standard',    # Not admin
    'result': 'success'
})
```

## View Results

After injection, check:
- **Dashboard:** http://localhost:5000/dashboard
- **API Response:** JSON with alert details

## Full Documentation

See **SAMPLE_INJECTIONS.md** for complete guide with examples.

