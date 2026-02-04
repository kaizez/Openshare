# SIEM/SOAR System for MoveIT

Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) system for monitoring the MoveIT file transfer application.

## Quick Start

### Option 1: Run Everything in Docker (Recommended)

```bash
# Build and start both MySQL + SIEM
docker-compose up --build

# Access dashboard at http://localhost:5001
# Login: admin / (password from your .env ADMIN_PASSWORD)
```

### Option 2: Run SIEM Locally (MySQL in Docker)

```bash
# 1. Start MySQL only
docker-compose up db -d

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run SIEM
python app.py

# Access dashboard at http://localhost:5001
```

## Project Structure

```
siem-Moveit/
├── src/
│   ├── database/           # MySQL connection & models
│   ├── ingestion/          # SIEM detection engine
│   │   ├── siem_engine.py  # Detection rules
│   │   ├── geo_lookup.py   # GeoIP for impossible travel
│   │   └── dlp_scanner.py  # Sensitive data detection
│   ├── dashboard/          # Flask web app
│   └── playbooks/          # SOAR response actions
├── templates/              # HTML templates
├── static/                 # CSS & JavaScript
├── siem_logger.py          # DROP-IN FILE FOR TEAMMATES
├── INTEGRATION_GUIDE.md    # GUIDE FOR TEAMMATES
├── TESTING.md              # How to test/inject sample data
├── Dockerfile              # Container build
└── docker-compose.yml      # MySQL + SIEM containers
```

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Failed Logins | 5+ failures from same IP | High |
| Brute Force Success | Login after multiple failures | Critical |
| Impossible Travel | Login from distant locations | Critical |
| Suspicious Volume | 10+ downloads in 60 seconds | High |
| Large Data Transfer | 100MB+ in 5 minutes | Medium |
| Mass Deletion | 10+ files deleted in 2 minutes | Critical |
| Data Staging | Multiple archive files created | High |
| Unauthorized Access | Non-admin accessing config files | Critical |
| Failed MFA | 5+ MFA failures | Critical |
| Privilege Escalation | Role changed to admin | High |
| Honeytoken Access | Decoy file accessed | Critical |
| File Integrity | SHA-256 hash changed | Critical |
| Sensitive Data | SSN, credit cards, API keys detected | Critical |

## Dashboard Features

- **Statistics Cards** - Critical events, high severity, quarantined IPs, new alerts
- **Security Logs** - Last 20 events with details
- **Active Alerts** - With playbook action buttons
- **Quarantined Items** - Manage blocked IPs and files

## Manual Playbook Actions

| Action | What It Does |
|--------|--------------|
| Block IP | Quarantines an IP address |
| Terminate Session | Ends user sessions |
| Quarantine File | Isolates suspicious files |
| Release IP | Removes IP from quarantine |

## Automated Responses (Optional)

Can be enabled in `playbook_engine.py`:

- Auto-disable account after 5 MFA failures
- Auto-block IP after 10 login failures
- Auto-kill sessions from blacklisted networks

## API Endpoints

### Log Ingestion (for teammates)

```bash
POST /api/ingest_log
Header: X-API-Key: your_api_key
Content-Type: application/json

{
  "event_type": "file_download",
  "user_id": "john",
  "ip_address": "192.168.1.100",
  "file_name": "document.pdf",
  "file_size": 1024000,
  "result": "success"
}
```

### Health Check

```bash
GET /health
# Returns: {"status": "healthy", "database": "connected"}
```

### API Key Management

```bash
POST /api/keys          # Create new API key
GET /api/keys           # List API keys
DELETE /api/keys/{id}   # Revoke API key
```

### Honeytoken Management

```bash
POST /api/honeytokens   # Create decoy file tracker
GET /api/honeytokens    # List active honeytokens
```

## Environment Variables

Copy `.env.example` to `.env` and fill in the values before first run.

| Variable | Default | Description |
|----------|---------|-------------|
| MYSQL_ROOT_PASSWORD | — | MySQL root password (required) |
| MYSQL_DATABASE | siem_db | Database name |
| SECRET_KEY | — | Flask session key (required) |
| USERS | — | Admin accounts as `user:pass,user:pass` (required) |
| FLASK_DEBUG | 0 | Set to 1 for development |

## For Teammates

1. Get `siem_logger.py` and `INTEGRATION_GUIDE.md`
2. Copy `siem_logger.py` into your project
3. Follow the examples in the integration guide

## Testing

See `TESTING.md` for how to inject sample data and trigger alerts.

## Security Notes

- Change default admin password in production
- Use strong database passwords
- Generate secure API keys for service-to-service auth
- Use HTTPS in production

## Python Virtual Environment Setup

### Create a Virtual Environment

```bash
# Navigate to project directory
cd /path/to/MoveIT

# Create venv (do this once)
python3 -m venv venv
```

### Activate the Virtual Environment

**macOS/Linux:**
```bash
source venv/bin/activate
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

**Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1
```

### Install Dependencies (after activating)

```bash
pip install -r requirements.txt
```

### Deactivate When Done

```bash
deactivate
```

### How to Tell if venv is Active

When activated, your terminal prompt will show `(venv)` at the beginning:
```
(venv) ayden@mac MoveIT %
```
