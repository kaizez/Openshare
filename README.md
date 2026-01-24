# SIEM/SOAR System for MoveIT File Transfer Monitoring

A comprehensive Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) system built to monitor the MoveIT file transfer system. This system provides real-time security event monitoring with manual playbook response capabilities.

## 🏗️ Architecture

The system is organized into clean, modular components:

```
siem-Moveit/
├── src/
│   ├── database/          # MySQL database connection and models
│   │   ├── connection.py  # Database connection management
│   │   └── models.py      # Data models
│   ├── ingestion/         # SIEM log ingestion engine
│   │   └── siem_engine.py # Security event detection rules
│   ├── dashboard/         # Flask web application
│   │   └── app.py         # Main dashboard routes and logic
│   └── playbooks/         # SOAR manual response actions
│       └── playbook_engine.py  # Playbook execution engine
├── templates/             # HTML templates
├── static/               # CSS and JavaScript
├── app.py                # Application entry point
├── docker-compose.yml     # MySQL database setup
└── requirements.txt      # Python dependencies
```

## 🔍 Critical Events Tracked

Based on analysis of the MoveIT repository (Ayden branch), the SIEM monitors:

1. **Login Failures** - 5+ consecutive failed login attempts from same IP
2. **Suspicious Volume** - 10+ files downloaded by single user within 60 seconds
3. **Unauthorized File Access** - Attempts to access config files (.cfg, .ini, .conf, .env, .key, .pem) without admin role
4. **Large Data Transfers** - 100MB+ transferred by single user within 5 minutes
5. **Failed Access Attempts** - 5+ consecutive failed file access attempts from same IP

## 🚀 Setup Instructions

### Prerequisites

- Python 3.8+
- Docker and Docker Compose
- MySQL client (optional, for direct database access)

### Step 1: Start MySQL Database

```bash
docker-compose up -d
```

This starts a MySQL container on `localhost:3306` with:
- Database: `siem_db`
- Root password: `your_secure_password` (change in docker-compose.yml for production)
- Port: `3306`

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Run the Application

```bash
python app.py
```

The dashboard will be available at `http://localhost:5000`

### Step 4: Login

Default credentials:
- Username: `admin`
- Password: `admin123`

**⚠️ Change default credentials in production!**

## 📊 Features

### SIEM Capabilities

- **Real-time Log Ingestion**: POST logs to `/api/ingest_log`
- **Event Detection**: Automatic detection of security anomalies
- **Alert Generation**: Alerts stored in MySQL with severity levels
- **Persistent Storage**: All logs and alerts stored in MySQL (not mock data)

### SOAR Playbooks (Manual Actions)

All response actions are **MANUAL** - no automatic responses. Admin must click buttons:

1. **🚫 Block Attacker IP**
   - Quarantines an IP address
   - Prevents further access from that IP
   - Can be released manually later

2. **🔌 Terminate User Session**
   - Terminates active user sessions
   - Useful for compromised accounts

3. **📁 Quarantine File**
   - Quarantines suspicious files
   - Prevents file access

4. **🔓 Release IP**
   - Releases a quarantined IP address

### Dashboard Features

- **Real-time Statistics**: Critical events, high severity, quarantined IPs, new alerts
- **Security Logs Table**: Last 20 security events with full details
- **Active Alerts**: Recent alerts with playbook action buttons
- **Quarantined Items**: View and manage quarantined IPs and files
- **Professional UI**: Clean, modern interface with responsive design

## 📡 API Endpoints

### Ingest Log

```bash
POST /api/ingest_log
Content-Type: application/json
Authorization: Required (session cookie)

{
  "timestamp": "2026-01-24T12:00:00",
  "log_source": "file_transfer_server",
  "event_type": "file_download",
  "description": "File downloaded by user",
  "severity": "Info",
  "user_id": "user123",
  "ip_address": "192.168.1.100",
  "file_name": "document.pdf",
  "user_role": "standard",
  "file_size": 1048576,
  "result": "success"
}
```

### Playbook Actions

All playbook endpoints require authentication and return JSON responses.

- `POST /api/playbook/block_ip` - Block an IP address
- `POST /api/playbook/terminate_session` - Terminate user session
- `POST /api/playbook/quarantine_file` - Quarantine a file
- `POST /api/playbook/release_ip` - Release quarantined IP

## 🔐 Database Schema

The system uses MySQL with the following tables:

- `users` - Admin user accounts
- `security_logs` - All ingested security events
- `alerts` - SIEM-generated alerts
- `quarantined_ips` - Blocked IP addresses
- `quarantined_files` - Quarantined files
- `active_sessions` - Active user sessions

## 🎯 Usage Example

### Ingest a Security Event

```python
import requests

session = requests.Session()

# Login
session.post('http://localhost:5000/login', data={
    'username': 'admin',
    'password': 'admin123'
})

# Ingest a log
log_data = {
    'log_source': 'file_transfer_server',
    'event_type': 'file_download',
    'description': 'File downloaded',
    'user_id': 'user123',
    'ip_address': '192.168.1.100',
    'file_name': 'document.pdf',
    'user_role': 'standard',
    'file_size': 1048576,
    'result': 'success'
}

response = session.post('http://localhost:5000/api/ingest_log', json=log_data)
print(response.json())
```

### Trigger an Alert (Suspicious Volume)

```python
# Send 11 file downloads rapidly to trigger suspicious volume alert
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
```

## 🔧 Configuration

Database configuration can be set via environment variables:

- `MYSQL_HOST` - Database host (default: localhost)
- `MYSQL_PORT` - Database port (default: 3306)
- `MYSQL_USER` - Database user (default: root)
- `MYSQL_PASSWORD` - Database password (default: your_secure_password)
- `MYSQL_DATABASE` - Database name (default: siem_db)
- `SECRET_KEY` - Flask secret key (default: random)

## 📝 Notes

- All SOAR actions are **MANUAL** - nothing is automatic
- The system uses **real MySQL storage** - no mock data
- The dashboard provides playbook buttons for each alert
- All actions are logged in the security_logs table
- The system tracks user sessions for termination capabilities

## 🛡️ Security Considerations

- Change default admin credentials in production
- Use strong database passwords
- Set a secure Flask SECRET_KEY
- Consider implementing rate limiting
- Use HTTPS in production
- Regularly review and update detection rules

## 📚 Based on MoveIT Analysis

This SIEM/SOAR system was built specifically to monitor the MoveIT file transfer system (Ayden branch), tracking:

- Authentication events (login attempts, failures)
- File transfer events (downloads, uploads, access attempts)
- User role-based access control violations
- Suspicious activity patterns

All detection rules are based on the actual logic and event types found in the MoveIT repository.
