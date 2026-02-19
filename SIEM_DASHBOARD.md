# SIEM Dashboard — How It Works

## What Is It

The SIEM dashboard is a web page you open in your browser. It shows you every security event happening inside OpenShare — logins, file transfers, failed attempts, alerts, blocked IPs. It is not the security brain. It is a window into the security brain.

The security brain is the **SIEM engine**. It lives in a completely separate repo (`OpenShare-SIEM`), in its own Docker container, with its own database. The dashboard never talks to that database directly. It only asks the engine for data, and the engine answers.

---

## The Architecture

```
Your Browser
     │
     │  opens localhost:5002
     ▼
┌─────────────────────────┐
│   SIEM Dashboard        │   ← siem_dashboard/app.py
│   (the window)          │      renders pages, forwards requests
└────────┬───────┬────────┘
         │       │
         │       │  all data and actions go here
         ▼       ▼
┌─────────────────────────┐
│   SIEM Engine           │   ← OpenShare-SIEM repo (separate docker)
│   (the security brain)  │      stores logs, runs detection, manages alerts
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   SIEM Database         │   ← MySQL inside OpenShare-SIEM
│   (the memory)          │      17 tables: logs, alerts, IPs, files, etc.
└─────────────────────────┘

Meanwhile, in the background:

┌─────────────────────────┐
│   OpenShare App            │   ← the main app (auth + file transfer)
│                         │      sends security events TO the engine
└─────────────────────────┘
```

---

## How Login Works

The dashboard has its own login page. It does not use OpenShare's login. It authenticates directly with the SIEM engine.

```
1. You open localhost:5002
2. Dashboard redirects you to the login page
3. You type a username and password
4. Dashboard sends those credentials to the SIEM engine:
       POST http://host.docker.internal:5001/api/auth/login
5. The engine checks its own users table
6. If valid, the engine returns a session token (a long random string)
7. Dashboard saves that token in your browser session
8. Dashboard redirects you to the main dashboard page
```

The credentials are the ones in `OpenShare-SIEM/.env` under `USERS`. Example: if `USERS=ayden:password123`, you log in as `ayden` / `password123`.

---

## How the Dashboard Page Works

Once you are logged in, the dashboard page loads. Here is what happens behind the scenes:

```
1. Your browser loads localhost:5002/dashboard
2. Dashboard sends a request to the SIEM engine:
       GET http://host.docker.internal:5001/api/dashboard/data
       Header: X-Session-Token: <the token from login>
3. The engine queries its database and returns JSON:
   {
     logs:              the 20 most recent security events
     alerts:            the 10 most recent alerts
     stats:             counts (critical events, high severity, quarantined IPs, new alerts)
     quarantined_ips:   list of all blocked IP addresses
     quarantined_files: list of all quarantined files
   }
4. Dashboard takes that JSON and renders the page:
   - 4 stat cards at the top (critical, high, quarantined IPs, new alerts)
   - A table of recent security logs
   - A list of active alerts, each with action buttons
   - A list of quarantined IPs, each with a Release button
   - A list of quarantined files
```

The dashboard does not store anything locally. Every time the page loads, it fetches fresh data from the engine.

---

## How Playbook Actions Work

Playbook actions are the buttons on the dashboard: **Block IP**, **Terminate Session**, **Quarantine File**, **Release IP**. These are security responses — you click them when you see something suspicious.

```
1. You click a button (e.g., "Block IP" on an alert)
2. A modal pops up asking for confirmation and a reason
3. You fill in the reason and click Confirm
4. The browser sends the action to the dashboard:
       POST localhost:5002/api/playbook/block_ip
       Body: { ip_address: "1.2.3.4", reason: "brute force detected" }
5. The dashboard forwards that exact request to the engine:
       POST http://host.docker.internal:5001/api/playbook/block_ip
       Header: X-Session-Token: <your token>
       Body: { ip_address: "1.2.3.4", reason: "brute force detected" }
6. The engine adds the IP to its quarantined_ips table
7. The engine returns success
8. The dashboard reloads the page — the IP now appears in Quarantined IPs
```

The same pattern applies to all playbook actions:

| Button               | Endpoint                          | What the engine does                        |
|----------------------|-----------------------------------|---------------------------------------------|
| Block IP             | `/api/playbook/block_ip`          | Adds IP to quarantined_ips table            |
| Terminate Session    | `/api/playbook/terminate_session` | Marks the user's session as terminated      |
| Quarantine File      | `/api/playbook/quarantine_file`   | Adds file to quarantined_files table        |
| Release IP           | `/api/playbook/release_ip`        | Removes IP from quarantined_ips table       |

---

## How Logs Get to the Dashboard in the First Place

The dashboard only shows what the engine has. The engine only has what was sent to it. Here is the full loop:

```
1. Something happens in OpenShare (a login, a file upload, a failed attempt)
2. The code calls siem_logger:
       siem.login_success(user_id="ayden", ip="1.2.3.4")
       siem.file_uploaded(user_id="ayden", filename="doc.pdf", ...)
3. siem_logger fires a background thread that POSTs to the engine:
       POST http://host.docker.internal:5001/api/ingest_log
       Header: X-API-Key: <the API key from .env>
       Body:   { event_type: "login_success", user_id: "ayden", ... }
4. The engine receives the log, runs it through detection rules:
       - Is this a brute force? (5+ failed logins in 5 minutes)
       - Impossible travel? (login from two countries too fast)
       - Suspicious volume? (10+ downloads in 60 seconds)
       - DLP violation? (credit card number in a file)
       - ...and 10 more rules
5. The engine stores the log in security_logs table
6. If a rule triggers, the engine also creates an alert in the alerts table
7. Next time you load the dashboard, both the log and the alert show up
```

---

## What Sends Logs to the Engine

Two parts of OpenShare send logs. Each one identifies itself with a `log_source` tag so you can tell them apart on the dashboard.

| log_source        | File                    | Events it sends                                                                 |
|-------------------|-------------------------|---------------------------------------------------------------------------------|
| `authentication`  | `app/routes.py`         | login success/fail, MFA success/fail, password change, logout, account lock, impossible travel, keystroke mismatch, high-risk login blocked, user created/deleted, permission changes |
| `file_transfer`   | `FileTransfer/app.py`   | file uploaded, file downloaded, file deleted                                    |

---

## What Each File Does

| File                              | Role                                                                      |
|-----------------------------------|---------------------------------------------------------------------------|
| `siem_dashboard/app.py`           | The dashboard web app. Serves pages. Forwards everything to the engine.   |
| `siem_dashboard/templates/`       | The HTML pages (login, dashboard, add admin)                              |
| `siem_dashboard/static/`          | CSS and JavaScript for the dashboard UI                                   |
| `siem_dashboard/Dockerfile`       | Builds the dashboard container                                            |
| `app/siem_logger.py`              | The report sender. Fires events to the engine in background threads.      |
| `docker-compose.yml`              | Defines SIEM_URL and SIEM_API_KEY env vars for the app and dashboard      |
| `.env`                            | Holds SIEM_URL (engine address) and SIEM_API_KEY (auth key)               |

---

## Ports

| Port (host)  | What is running                          |
|--------------|------------------------------------------|
| 5001         | SIEM Engine (OpenShare-SIEM docker)         |
| 5002         | SIEM Dashboard (this repo)               |
| 5005         | OpenShare main app (auth + file transfer)   |

---

## Environment Variables

| Variable               | Where it is set      | What it does                                                    |
|------------------------|----------------------|-----------------------------------------------------------------|
| `SIEM_URL`             | `.env`               | Address of the SIEM engine. Both app and dashboard read this.   |
| `SIEM_API_KEY`         | `.env`               | API key for siem_logger to authenticate log submissions.        |
| `SIEM_DASHBOARD_SECRET`| `.env`               | Secret key for the dashboard's own session encryption.          |
