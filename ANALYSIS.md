# MoveIT Repository Analysis - Critical Events Identified

## Analysis Summary

This document outlines the critical security events identified in the MoveIT file transfer system (Ayden branch) that the SIEM system monitors.

## Authentication Logic Analysis

### Login Process
- **Location**: `app.py` - `/login` route
- **Method**: Flask session-based authentication
- **Password Storage**: Werkzeug password hashing (bcrypt)
- **Database**: SQLite (in original), MySQL (in SIEM)

### Critical Authentication Events:
1. **Failed Login Attempts**
   - Event Type: `login_attempt`
   - Result: `failure`
   - Detection Rule: 5+ consecutive failures from same IP within 5 minutes
   - Severity: **High**

## File Transfer Logic Analysis

### File Transfer Events
- **Event Types Identified**:
  - `file_download` - File download operations
  - `file_access` - File access attempts
  - `access_attempt` - General access attempts

### Critical File Transfer Events:

1. **Suspicious Volume Downloads**
   - Event Type: `file_download`
   - Result: `success`
   - Detection Rule: 10+ files downloaded by single user within 60 seconds
   - Severity: **High**
   - Original Rule: From `siem_engine.py` Rule 1

2. **Unauthorized File Type Access**
   - Event Type: `file_access`
   - Detection Rule: Attempt to access config files (.cfg, .ini, .conf, .config, .env, .key, .pem) without admin role
   - Severity: **Critical**
   - Original Rule: From `siem_engine.py` Rule 3
   - Authorized Roles: `admin`, `administrator`, `system`

3. **Failed Access Attempts**
   - Event Type: `access_attempt` or `file_access`
   - Result: `failure`
   - Detection Rule: 5+ consecutive failed attempts from same IP within 5 minutes
   - Severity: **Medium**
   - Original Rule: From `siem_engine.py` Rule 2

4. **Large Data Transfers** (NEW - Enhanced)
   - Event Type: `file_download`
   - Result: `success`
   - Detection Rule: 100MB+ transferred by single user within 5 minutes
   - Severity: **Medium**
   - Additional Enhancement: Tracks cumulative file sizes

## Event Data Structure

### Standard Log Format
```json
{
  "timestamp": "2026-01-24T12:00:00",
  "log_source": "file_transfer_server",
  "event_type": "file_download|file_access|access_attempt|login_attempt",
  "description": "Human-readable description",
  "severity": "Critical|High|Medium|Low|Info",
  "user_id": "user123",
  "ip_address": "192.168.1.100",
  "file_name": "document.pdf",
  "user_role": "standard|admin|administrator|system",
  "file_size": 1048576,
  "result": "success|failure"
}
```

## Detection Rules Summary

| Rule | Event Type | Condition | Severity | Action |
|------|-----------|-----------|----------|--------|
| Suspicious Volume | `file_download` | 10+ files in 60s | High | Alert |
| Failed Login | `login_attempt` | 5+ failures from IP | High | Alert |
| Failed Access | `access_attempt` | 5+ failures from IP | Medium | Alert |
| Unauthorized File | `file_access` | Config file + non-admin | Critical | Alert |
| Large Transfer | `file_download` | 100MB+ in 5min | Medium | Alert |

## SOAR Response Actions

All actions are **MANUAL** - triggered by admin button clicks:

1. **Block Attacker IP** - Quarantines IP address
2. **Terminate User Session** - Ends active user sessions
3. **Quarantine File** - Isolates suspicious files
4. **Release IP** - Removes IP from quarantine

## Database Schema

### Tables Created:
- `security_logs` - All ingested events
- `alerts` - SIEM-generated alerts
- `quarantined_ips` - Blocked IP addresses
- `quarantined_files` - Quarantined files
- `active_sessions` - User session tracking
- `users` - Admin accounts

## Integration Points

The SIEM integrates with MoveIT by:
1. Receiving logs via `/api/ingest_log` endpoint
2. Processing through detection rules
3. Storing in MySQL database
4. Displaying alerts in dashboard
5. Providing manual response buttons

## Security Considerations

- All authentication events are logged
- File access attempts are monitored
- Role-based access violations trigger critical alerts
- Suspicious patterns are detected in real-time
- All actions are logged for audit trail
