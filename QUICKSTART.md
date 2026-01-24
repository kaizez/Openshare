# Quick Start Guide

## 1. Start MySQL Database

```bash
docker-compose up -d
```

Wait a few seconds for MySQL to initialize.

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

## 3. Run the Application

```bash
python app.py
```

## 4. Access Dashboard

Open browser: `http://localhost:5000`

**Default Login:**
- Username: `admin`
- Password: `admin123`

## 5. Test Log Ingestion

### Using Python:

```python
import requests

# Login
session = requests.Session()
session.post('http://localhost:5000/login', data={
    'username': 'admin',
    'password': 'admin123'
})

# Send a log
log_data = {
    'log_source': 'file_transfer_server',
    'event_type': 'file_download',
    'description': 'Test file download',
    'user_id': 'test_user',
    'ip_address': '192.168.1.100',
    'result': 'success'
}

response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
print(response.json())
```

### Using cURL:

```bash
# First, login and save cookie
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=admin&password=admin123"

# Send a log
curl -b cookies.txt -X POST http://localhost:5000/api/ingest_log \
  -H "Content-Type: application/json" \
  -d '{
    "log_source": "file_transfer_server",
    "event_type": "file_download",
    "description": "Test file download",
    "user_id": "test_user",
    "ip_address": "192.168.1.100",
    "result": "success"
  }'
```

## 6. Trigger an Alert

### Suspicious Volume Alert (10+ files in 60 seconds):

```python
import requests
import time

session = requests.Session()
session.post('http://localhost:5000/login', data={
    'username': 'admin',
    'password': 'admin123'
})

# Send 11 file downloads rapidly
for i in range(11):
    log_data = {
        'log_source': 'file_transfer_server',
        'event_type': 'file_download',
        'description': f'File {i+1} downloaded',
        'user_id': 'user123',
        'ip_address': '192.168.1.100',
        'result': 'success'
    }
    session.post('http://localhost:5000/api/ingest_log', json=log_data)
    time.sleep(0.1)  # Small delay

# Check dashboard - you should see a "Suspicious Volume" alert
```

### Failed Login Alert (5+ failures):

```python
# Send 5 failed login attempts
for i in range(5):
    log_data = {
        'log_source': 'file_transfer_server',
        'event_type': 'login_attempt',
        'description': f'Failed login attempt {i+1}',
        'ip_address': '192.168.1.200',
        'result': 'failure'
    }
    session.post('http://localhost:5000/api/ingest_log', json=log_data)
```

### Unauthorized File Access Alert (Critical):

```python
log_data = {
    'log_source': 'file_transfer_server',
    'event_type': 'file_access',
    'description': 'Attempt to access config file',
    'file_name': 'config.ini',
    'user_id': 'user123',
    'ip_address': '192.168.1.100',
    'user_role': 'standard',  # Not admin!
    'result': 'success'
}

session.post('http://localhost:5000/api/ingest_log', json=log_data)
```

## 7. Use Playbook Actions

When you see an alert in the dashboard:

1. **Block IP**: Click "🚫 Block IP" button on an alert
2. **Terminate Session**: Click "🔌 Terminate Session" button
3. **Quarantine File**: Click "📁 Quarantine File" button
4. **Release IP**: Click "🔓 Release IP" on quarantined IPs

All actions are logged and visible in the Security Logs table.

## Troubleshooting

### Database Connection Error

If you see database connection errors:

1. Check MySQL is running: `docker ps`
2. Check MySQL logs: `docker logs siem-mysql`
3. Verify port 3306 is not in use: `lsof -i :3306`

### Import Errors

If you see import errors, make sure you're running from the project root:

```bash
cd /Users/ayden/School_Project/siem-Moveit
python app.py
```

### Port Already in Use

If port 5000 is in use, change it in `app.py`:

```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Change port
```

## Next Steps

- Review the full README.md for detailed documentation
- Check ANALYSIS.md for event detection details
- Customize detection rules in `src/ingestion/siem_engine.py`
- Add more playbook actions in `src/playbooks/playbook_engine.py`
