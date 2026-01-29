# SIEM Integration Guide

This guide explains how to integrate your subsystem with the SIEM (Security Information and Event Management) system.

## Quick Start (5 minutes)

### Step 1: Copy the Logger File

Copy `siem_logger.py` into your project folder:

```
your_project/
├── app.py
├── siem_logger.py  <-- Copy this file here
└── ...
```

### Step 2: Install Dependency

Make sure you have the `requests` library:

```bash
pip install requests
```

### Step 3: Initialize the Logger

In your Flask app:

```python
from siem_logger import SIEMLogger

# Replace with the actual SIEM server IP
SIEM_URL = "http://192.168.x.x:5001"  # Ask Ayden for the IP

# Create the logger
siem = SIEMLogger(SIEM_URL, log_source="your_subsystem_name")
```

### Step 4: Add Logging to Your Code

```python
from flask import request

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    ip = request.remote_addr

    if check_password(username, password):
        # Log successful login
        siem.login_success(user_id=username, ip=ip)
        return redirect('/dashboard')
    else:
        # Log failed login
        siem.login_failed(username=username, ip=ip, reason="wrong password")
        return "Login failed", 401
```

That's it! The SIEM will now receive your events.

---

## Events by Subsystem

### For Authentication Team

```python
# Successful login
siem.login_success(user_id="john", ip=request.remote_addr)

# Failed login
siem.login_failed(username="john", ip=request.remote_addr, reason="wrong password")

# Logout
siem.logout(user_id="john", ip=request.remote_addr)

# MFA verification passed
siem.mfa_success(user_id="john", ip=request.remote_addr)

# MFA verification failed
siem.mfa_failed(user_id="john", ip=request.remote_addr)

# Password changed
siem.password_changed(user_id="john", ip=request.remote_addr)

# Session started (when user logs in)
siem.session_start(user_id="john", ip=request.remote_addr, session_id="abc123")

# Session ended (when user logs out or times out)
siem.session_end(user_id="john", ip=request.remote_addr, session_id="abc123")
```

### For File Transfer Team

```python
# File uploaded
siem.file_uploaded(
    user_id="john",
    filename="document.pdf",
    file_size=1024000,  # in bytes
    ip=request.remote_addr
)

# File downloaded
siem.file_downloaded(
    user_id="john",
    filename="document.pdf",
    file_size=1024000,
    ip=request.remote_addr
)

# File deleted
siem.file_deleted(
    user_id="john",
    filename="document.pdf",
    ip=request.remote_addr
)

# File moved/renamed
siem.file_moved(
    user_id="john",
    filename="document.pdf",
    ip=request.remote_addr,
    source_path="/uploads/document.pdf",
    dest_path="/archive/document.pdf"
)

# File shared with another user
siem.file_shared(
    user_id="john",
    filename="document.pdf",
    ip=request.remote_addr,
    shared_with="jane@example.com"
)

# File accessed (viewed/opened)
siem.file_accessed(
    user_id="john",
    filename="document.pdf",
    ip=request.remote_addr
)

# File access denied
siem.file_access_denied(
    user_id="john",
    filename="secret.pdf",
    ip=request.remote_addr,
    user_role="standard",
    reason="insufficient permissions"
)
```

### For Admin/User Management Team

```python
# New user created
siem.user_created(
    admin_id="admin",
    new_user_id="john",
    ip=request.remote_addr,
    user_role="standard"
)

# User deleted
siem.user_deleted(
    admin_id="admin",
    deleted_user_id="john",
    ip=request.remote_addr
)

# User permissions changed
siem.permission_changed(
    admin_id="admin",
    target_user="john",
    ip=request.remote_addr,
    old_role="standard",
    new_role="admin"
)

# Configuration changed
siem.config_changed(
    admin_id="admin",
    ip=request.remote_addr,
    setting="max_upload_size",
    old_value="10MB",
    new_value="50MB"
)

# Account locked
siem.account_locked(
    user_id="john",
    ip=request.remote_addr,
    reason="too many failed logins",
    locked_by="system"
)
```

### For Chatbot Team

```python
# Normal chatbot query
siem.chatbot_query(
    user_id="john",
    query="How do I upload a file?",
    ip=request.remote_addr
)

# Sensitive query detected (e.g., asking about passwords, security, etc.)
siem.chatbot_sensitive_query(
    user_id="john",
    query="How do I bypass the firewall?",
    ip=request.remote_addr,
    sensitivity_type="security_bypass"
)
```

---

## Advanced: File Hash for Integrity Monitoring

If you want to enable file integrity monitoring, include the file hash:

```python
import hashlib

def calculate_hash(file_content):
    return hashlib.sha256(file_content).hexdigest()

# When uploading
file_content = uploaded_file.read()
file_hash = calculate_hash(file_content)

siem.file_uploaded(
    user_id="john",
    filename="document.pdf",
    file_size=len(file_content),
    ip=request.remote_addr,
    file_hash=file_hash  # Include this for integrity monitoring
)
```

---

## Complete Flask Example

Here's a complete example for a simple file upload endpoint:

```python
from flask import Flask, request, redirect
from siem_logger import SIEMLogger

app = Flask(__name__)

# Initialize SIEM logger
siem = SIEMLogger("http://192.168.x.x:5001", log_source="file_transfer")

@app.route('/upload', methods=['POST'])
def upload_file():
    user_id = session.get('user_id')
    ip = request.remote_addr

    if 'file' not in request.files:
        return "No file", 400

    file = request.files['file']
    filename = file.filename
    file_content = file.read()
    file_size = len(file_content)

    # Save the file
    save_path = f"/uploads/{filename}"
    with open(save_path, 'wb') as f:
        f.write(file_content)

    # Log to SIEM
    siem.file_uploaded(
        user_id=user_id,
        filename=filename,
        file_size=file_size,
        ip=ip
    )

    return "File uploaded!", 200

@app.route('/download/<filename>')
def download_file(filename):
    user_id = session.get('user_id')
    ip = request.remote_addr

    # Get file size
    file_path = f"/uploads/{filename}"
    file_size = os.path.getsize(file_path)

    # Log to SIEM
    siem.file_downloaded(
        user_id=user_id,
        filename=filename,
        file_size=file_size,
        ip=ip
    )

    return send_file(file_path)

if __name__ == '__main__':
    app.run(port=5000)
```

---

## What Gets Detected

When you log events, the SIEM automatically detects these threats:

| Threat | What Triggers It |
|--------|------------------|
| Brute Force Attack | 5+ failed logins from same IP |
| Account Takeover | Successful login after failed attempts |
| Impossible Travel | Login from two distant locations |
| Mass Data Download | 10+ files downloaded in 60 seconds |
| Large Data Exfiltration | 100MB+ transferred in 5 minutes |
| Mass File Deletion | 10+ files deleted in 2 minutes |
| Data Staging | Multiple archive files created |
| Unauthorized Access | Non-admin accessing config files |
| Sensitive Data Leak | Files containing SSN, credit cards, API keys |
| Privilege Escalation | User promoted to admin |

---

## Troubleshooting

### "Connection refused" error

- Check the SIEM server is running: `docker ps`
- Check the IP address is correct
- Check port 5001 is not blocked

### Events not showing in dashboard

- Login to the SIEM dashboard
- Check the "Recent Security Logs" section
- Events appear in real-time

### Need an API key?

If you're calling the SIEM from a server (not a user session):

1. Login to SIEM dashboard
2. Go to API Keys section (or call `POST /api/keys`)
3. Create a new key
4. Use it in your logger:

```python
siem = SIEMLogger(
    "http://192.168.x.x:5001",
    api_key="your_api_key_here"
)
```

---

## Questions?

Ask Ayden in the group chat or open an issue in the repo.
