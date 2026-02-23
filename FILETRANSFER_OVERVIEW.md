# OpenShare File Transfer System — Technical Overview

> Generated: 2026-02-23

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Container Layout](#2-container-layout)
3. [Network Architecture](#3-network-architecture)
4. [Database Architecture](#4-database-architecture)
5. [Database Class](#5-database-class-filetransferdbpy)
6. [Encryption System](#6-encryption-system-filetransferencryptionpy)
7. [File Upload Flow](#7-file-upload-flow)
8. [File Download Flow](#8-file-download-flow)
9. [VirusTotal Integration](#9-virustotal-integration)
10. [DB Sync Service](#10-db-sync-service-filetransfersync_servicepy)
11. [Retention Service](#11-retention-service-filetransferretention_servicepy)
12. [Forensic Watermark System](#12-forensic-watermark-system-filetransferwatermarkpy)
13. [ML Trust-Score Analyzer](#13-ml-trust-score-analyzer-filetransferml_analyzerpy)
14. [Admin File Transfer Panel](#14-admin-file-transfer-panel)
15. [Security Layers Summary](#15-security-layers-summary)
16. [Session Format](#16-session-format)
17. [SIEM Integration](#17-siem-integration)

---

## 1. High-Level Architecture

OpenShare is a dual-application Flask platform composed of:

| Component | Path | Role |
|-----------|------|------|
| **Auth App** | `app/` | User authentication, admin panel, session management |
| **FileTransfer** | `FileTransfer/` | File upload/download logic (Flask Blueprint) |

The FileTransfer module is **not** a standalone Flask app in production. It is registered as a Blueprint inside the main Auth App. This means they share one process, one port (`5000` internally / `5005` externally), and one Flask session. `app/routes.py` adds FileTransfer to the main app via `sys.path` and Blueprint registration.

---

## 2. Container Layout

Defined in `docker-compose.yml`:

| Container | External Port | Role |
|-----------|--------------|------|
| `openshare-app` | `5005→5000` | Main Flask app (auth + file transfer) |
| `openshare-auth-db` | `3307→3306` | MySQL: user accounts, sessions, SIEM |
| `openshare-working-db` | `3309→3306` | MySQL: active files, scan queue, logs |
| `openshare-storage-db` | *(none)* | MySQL: archived file content — **isolated** |
| `openshare-movelorh-db` | `3310→3306` | MySQL: auxiliary / legacy |
| `openshare-sync` | `8081→8080` | Sync service (working-db → storage-db) |
| `openshare-vt-worker` | *(none)* | VirusTotal background scanner |
| `openshare-retention` | *(none)* | Data retention cleanup daemon |

> `storage-db` has **no external port** by design. It is only reachable by the sync-service and retention-service containers through the isolated `sync_network`.

---

## 3. Network Architecture

Three Docker bridge networks divide traffic by trust level:

```
openshare-network  (bridge)
  └── app ←→ auth-db

app_network  (bridge)
  └── app ←→ working-db ←→ sync-service ←→ vt-worker ←→ retention-service

sync_network  (bridge, internal=true — NO host routing)
  └── working-db ←→ storage-db ←→ sync-service ←→ retention-service
```

`sync_network` is declared `internal: true`, meaning Docker will not route packets from it to the host or internet. Only the `sync-service` and `retention-service` containers straddle both `app_network` and `sync_network`, acting as the only bridge to `storage-db`.

**Key implication:** A compromised main app cannot directly query or modify the long-term archive database — it must go through the sync-service HTTP API on port 8080.

---

## 4. Database Architecture

### 4a. Auth DB (`auth-db`)

- **ORM:** SQLAlchemy (via `app/models.py`)
- **Accessed by:** main app only
- **Tables:**
  - `users` — accounts, hashed passwords, MFA secrets, roles
  - `login_history` — session audit log
- **Connection:** env vars `MYSQL_HOST` / `MYSQL_PORT` / `MYSQL_USER` / `MYSQL_PASSWORD`

### 4b. Working DB (`working-db`)

- **ORM:** Raw `mysql.connector` (no SQLAlchemy), via `FileTransfer/db.py`
- **Accessed by:** main app, sync-service, vt-worker, retention-service
- **Tables:**

| Table | Purpose |
|-------|---------|
| `file_metadata` | Per-file record: filename, hash, OTP, VT status, classification, uploader, encrypted file content |
| `access_logs` | Every OTP attempt, download, verification event |
| `failed_upload_logs` | Rejected uploads (bad MIME, malicious, etc.) |
| `virus_scan_logs` | VT scan outcomes (clean / malicious / pending) |
| `approval_requests` | Two-person rule queue for Classified files |
| `download_watermarks` | Encrypted forensic watermarks per download event |
| `file_ml_analysis` | ML trust-score results per file |

### 4c. Storage DB (`storage-db`)

- **ORM:** Raw `mysql.connector`
- **Accessed by:** sync-service and retention-service **only**
- **Tables (subset of working-db):**
  - `file_metadata` — archived copy; includes `file_content LONGBLOB` + `synced_at` timestamp
  - `access_logs` — replicated from working-db
- **NOTE:** Never queried directly by the main app.

---

## 5. Database Class (`FileTransfer/db.py`)

The `Database` class wraps raw `mysql.connector` with `autocommit=True`. Every method calls `self.ensure_connection()` first to reconnect if the socket dropped.

**Key patterns:**

- `cursor(dictionary=True, buffered=True)` — returns rows as dicts, avoids unread-result errors on multiple sequential queries per connection.
- All `datetime` fields are converted to `.isoformat()` strings before returning, so callers always receive plain strings (no datetime objects leaking out).
- File content is stored as an encrypted `LONGBLOB` in `file_metadata.file_content`.
- OTP codes are **never stored in plaintext** — Fernet-encrypted before `INSERT`, decrypted on `SELECT`.
- `get_db()` is a module-level singleton factory — one `Database` instance per process. The VT worker intentionally bypasses this and creates a fresh `Database()` each cycle to avoid stale connection caching.

---

## 6. Encryption System (`FileTransfer/encryption.py`)

Two separate Fernet (AES-128-CBC + HMAC-SHA256) keys are used:

| Key | Purpose |
|-----|---------|
| `FILE_ENCRYPTION_KEY` | Encrypts raw file bytes before storing in the DB |
| `OTP_ENCRYPTION_KEY` | Encrypts OTP codes before storing in the DB |

**Key resolution order (for each key):**
1. Environment variable (`FILE_ENCRYPTION_KEY` / `OTP_ENCRYPTION_KEY`)
2. Persistent file in Docker volume at `/app/keys/<name>.key`
3. Auto-generate and save (first-run only)

The `/app/keys` volume is declared in `docker-compose.yml` so keys survive container restarts.

> Because Fernet encryption is **non-deterministic** (random IV per encrypt call), OTP lookup cannot use a `WHERE` clause. Instead `find_file_by_otp()` fetches all encrypted OTPs, decrypts each one in Python, and compares in memory.

---

## 7. File Upload Flow

`POST /upload` → `FileTransfer/app.py → upload_file()`

```
1.  Login check          (login_required decorator)
2.  Rate limiting        (secure_endpoint decorator, security.py)
3.  Extension whitelist  (ALLOWED_EXTENSIONS set)
4.  Read file into memory
5.  Magic-byte validation
      - Write bytes to temp file, detect actual MIME type via python-magic
      - Compare detected MIME against expected types for the claimed extension
      - Block any executable MIME regardless of extension
      - Log to failed_upload_logs on rejection
6.  VirusTotal hybrid scan
      a. Hash lookup (instant if VT knows this SHA-256)
      b. Unknown hash → submit full file → status = 'pending'
         File IS stored but OTP is NOT returned until background worker confirms clean
7.  Generate unique file_id   (secrets.token_urlsafe(16))
8.  Generate 16-char OTP      (secrets.choice, cryptographically secure, 24h expiry)
9.  Encrypt file content      (Fernet / FILE_ENCRYPTION_KEY)
10. Encrypt OTP code          (Fernet / OTP_ENCRYPTION_KEY)
11. INSERT into working-db    (encrypted content + encrypted OTP)
12. ML trust-score analysis   (non-blocking try/except — never fails an upload)
13. Log VT scan result        (virus_scan_logs)
14. SIEM event                (siem.file_uploaded)
15. Return JSON               (file_id, otp_code only if scan_status='clean', VT details)
```

---

## 8. File Download Flow

### Step 1 — OTP Verification &nbsp;`POST /verify-code`

- User submits the 16-char OTP received after upload.
- `find_file_by_otp()` scans all encrypted OTPs, decrypts, compares in memory.
- `validate_otp()` checks: code match, 24-hour expiry, not already used.
- Marks OTP as used (`otp_used=TRUE`).
- **Classification-based session branching:**

| Classification | Gates |
|---------------|-------|
| Public | OTP only → full access granted |
| Internal Use | OTP + TOTP required |
| Classified | OTP + TOTP + owner approval (two-person rule) |

### Step 2 — TOTP Verification &nbsp;`POST /verify-totp`

- User submits their TOTP code (from authenticator app).
- Verified against user's MFA secret via `pyotp.TOTP.verify`.
- Session upgraded to `session['verified_<file_id>']` with `totp_verified: True`.

### Step 3 — Owner Approval (Classified only) &nbsp;`POST /request-approval`

- Creates `approval_requests` record with 5-minute TTL.
- File owner sees pending badge and approves or denies via UI.
- On approval: `session['verified_<file_id>']['approval_granted'] = True`.

### Step 4 — Actual Download &nbsp;`GET /get-file/<file_id>`

```
1.  Verify session['verified_<file_id>'] present and unexpired
2.  If is_archived=TRUE → fetch content from sync-service API
      GET http://sync-service:8080/retrieve/<file_id>
3.  Decrypt file content (Fernet / FILE_ENCRYPTION_KEY)
4.  Forensic watermark
      - create_watermark() → AES-256-GCM encrypted payload
        (user ID, username, email, IP, user-agent, timestamp, access context)
      - embed_watermark_in_file() → append bytes → unique SHA-256 per downloader
      - Store watermark record in download_watermarks table
5.  Increment download_count
6.  SIEM event (siem.file_downloaded)
7.  Stream file to browser (send_file, as_attachment=True)
```

---

## 9. VirusTotal Integration

Two components handle VT scanning:

| Component | File | Role |
|-----------|------|------|
| API wrapper | `FileTransfer/virustotal_service.py` | Used by upload route |
| Background daemon | `FileTransfer/vt_worker.py` | Separate container |

**Hybrid scan strategy:**

- **On upload:** `scan_file_async_start()` first does a hash lookup (`GET /files/{sha256}`). If VT knows the hash → immediate result. If not → submit file bytes (`POST /files`) and store `analysis_id` with `scan_status='pending'`. OTP is withheld from the user.
- **VT worker** runs every `VT_WORKER_INTERVAL` seconds (default: 10). Polls `GET /analyses/{id}` for each pending file:
  - **Clean** → `scan_status='clean'`, log to `virus_scan_logs`
  - **Malicious** → `scan_status='malicious'`, then `db.delete_file()` removes the record entirely (cascades to `access_logs`)
  - **Still scanning** → skip, retry next cycle

The sync-service only copies files with `scan_status='clean'` (or `NULL`) to `storage-db`, so malicious or pending files never reach the archive.

---

## 10. DB Sync Service (`FileTransfer/sync_service.py`)

Runs as `openshare-sync` with access to both `working-db` and `storage-db` via `sync_network`. The main app has no direct path to `storage-db` — only this container bridges them.

### Two threads run simultaneously:

**Thread 1 — Flask API on port 8080**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/retrieve/<file_id>` | `GET` | Returns encrypted file bytes from storage-db |
| `/delete/<file_id>` | `DELETE` | Removes file from storage-db (on user deletion) |
| `/health` | `GET` | Health check |

**Thread 2 — Sync loop (main thread)**

Runs every `SYNC_INTERVAL_SECONDS` (default: `3600` = 1 hour).

```
sync_files():
  SELECT * FROM working-db.file_metadata
  WHERE is_archived=FALSE AND (scan_status='clean' OR scan_status IS NULL)

  For each row:
    INSERT INTO storage-db.file_metadata ... ON DUPLICATE KEY UPDATE
    (only mutable fields: download_count, otp state, file_content)

  If DELETE_FILES_OLDER_THAN_SECONDS > 0 and file exceeds age threshold:
    SET file_content=NULL, is_archived=TRUE in working-db
    (content now lives only in storage-db; working-db keeps metadata shell)

sync_logs():
  Replicate all access_logs rows from working-db → storage-db
  INSERT ... ON DUPLICATE KEY UPDATE (idempotent, uses PK id column)
```

**Archiving semantics:**
- "Archived" = `file_content IS NULL` and `is_archived=TRUE` in working-db.
- Metadata (filename, hash, OTP state, scan status) remains in working-db.
- The download route detects `is_archived=TRUE` and transparently fetches content from the sync-service API.
- This keeps working-db lean while preserving long-term copies in storage-db.

---

## 11. Retention Service (`FileTransfer/retention_service.py`)

Runs as `openshare-retention`. Reads `retention_policy.json` from a shared Docker volume — the main app can update this file via the admin panel without restarting the container.

**Each cleanup cycle:**

1. Reload policy file (picks up live admin changes)
2. Delete from `working-db.file_metadata` where `upload_time < cutoff`
3. Delete from `storage-db.file_metadata` where `upload_time < cutoff`
4. Delete physical files from `/app/uploads/` filesystem
5. Delete old `access_logs`, `failed_upload_logs`, `virus_scan_logs`, `approval_requests` per individual retention windows
6. Clean up orphaned files on disk (files with no DB record)

Supports **dry-run mode** — logs what would be deleted without acting. Separate retention windows are configurable per storage layer: `working_db`, `storage_db`, `filesystem`.

---

## 12. Forensic Watermark System (`FileTransfer/watermark.py`)

**Purpose:** Identify exactly which user leaked a file if it appears externally.

**Encryption:** AES-256-GCM (not Fernet). Key at `/app/keys/watermark.key` or env `WATERMARK_KEY` (base64-encoded 32 bytes).

### On every download:

`create_watermark()` builds a JSON payload containing:

```json
{
  "watermark_id": "<uuid>",
  "watermark_version": "1.0",
  "created_at": "<UTC ISO timestamp>",
  "file_id": "...",
  "file_hash_sha256": "...",
  "original_filename": "...",
  "file_classification": "...",
  "downloader": {
    "user_id": 42,
    "username": "...",
    "email": "...",
    "ip_address": "...",
    "user_agent": "...",
    "session_id": "..."
  },
  "access_context": {
    "otp_verified": true,
    "totp_verified": true,
    "approval_granted": false
  },
  "system": {
    "app_version": "1.0",
    "system_fingerprint": "...",
    "server_hostname": "..."
  }
}
```

`embed_watermark_in_file()` **appends** to the file bytes:

```
[original content] + [_WM_HEADER 14B] + [payload_len 4B uint32] + [encrypted blob] + [_WM_FOOTER 15B]
```

This changes the file's SHA-256, making each user's download **uniquely identifiable by hash alone**.

Both the encrypted payload and the `watermarked_hash` are stored in the `download_watermarks` table.

### Forensic check (admin panel):

Admin uploads a suspected leaked file → system:
1. SHA-256 hashes the uploaded file
2. Looks up `download_watermarks` by `watermarked_hash` (exact match)
3. If found: `decrypt_watermark()` reveals full downloader identity
4. Fallback: `extract_watermark_from_file()` scans file bytes for embedded sentinel bytes and decrypts inline

---

## 13. ML Trust-Score Analyzer (`FileTransfer/ml_analyzer.py`)

Called **non-blocking** after every successful upload. Extracts heuristic features from the file and produces:

| Output | Description |
|--------|-------------|
| `trust_score` | 0–100 (higher = more trustworthy) |
| `risk_level` | `low`, `medium`, `high`, `critical` |
| `risk_signals` | List of human-readable warning flags |
| `anomaly_score` | IsolationForest outlier score |

Results stored in `file_ml_analysis` table. If analysis fails for any reason, the **upload is not blocked** — the exception is caught and logged.

An IsolationForest model is retrained as new data accumulates via `get_all_ml_features()`. Trust scores are visible in the admin FileTransfer panel alongside VT scan results.

---

## 14. Admin File Transfer Panel

All routes require: active session **and** `user.is_admin = True`.

| Route | Method | Purpose |
|-------|--------|---------|
| `/admin/filetransfer` | `GET` | File list with VT status, ML scores, retention config form |
| `/admin/filetransfer/retention` | `POST` | Update retention policy *(requires TOTP)* |
| `/admin/filetransfer/search` | `GET` | Full-text search across file metadata |
| `/admin/filetransfer/ml-analysis/<file_id>` | `GET` | Detailed ML analysis JSON |
| `/admin/filetransfer/ml-scores` | `GET` | All trust scores for dashboard charts |
| `/admin/filetransfer/watermarks/<file_id>` | `GET` | All decrypted watermarks for a file |
| `/admin/filetransfer/forensic-check` | `POST` | Upload leaked file → identify downloader |
| `/admin/filetransfer/file/<file_id>/logs` | `GET` | Full access log history (JSON) |

> Retention changes require a valid TOTP code before any settings are saved — an extra verification layer for potentially destructive operations.

---

## 15. Security Layers Summary

### Transport / Input
- All responses receive security headers via `after_request` hook (CSP, HSTS, etc.)
- IP blocker records and rate-limits repeated violations (`security.py`)
- File extension whitelist **+** magic-byte MIME validation (double check)
- Executable MIME types blocked unconditionally

### At-Rest Encryption

| Data | Algorithm | Key Location |
|------|-----------|-------------|
| File content | Fernet (AES-128-CBC + HMAC) | `/app/keys/file_encryption.key` |
| OTP codes | Fernet (AES-128-CBC + HMAC) | `/app/keys/otp_encryption.key` |
| Forensic watermarks | AES-256-GCM | `/app/keys/watermark.key` |

All keys are stored in a Docker named volume — never in the image or source code.

### Access Control

| Classification | Required Gates |
|---------------|---------------|
| Public | Login + OTP |
| Internal Use | Login + OTP + TOTP |
| Classified | Login + OTP + TOTP + file owner approval |

Admin routes additionally check `user.is_admin`; retention changes also require TOTP.

### Audit / Forensics
- Every access attempt (success, failure, verification) logged to `access_logs`
- All uploads and downloads reported to SIEM
- Each download produces a unique AES-256-GCM encrypted watermark tied to the downloader
- Failed uploads (bad MIME, malicious) logged to `failed_upload_logs`

### Network Isolation
- `storage-db` has no external port; only reachable via `sync_network`
- Main app cannot query `storage-db` directly — must use sync-service HTTP API
- `sync_network` declared `internal: true` (no Docker host routing)

### Malware Prevention
- VirusTotal hash lookup before saving any file
- Background worker auto-deletes files flagged as malicious
- Only `scan_status='clean'` files ever replicate to `storage-db`

---

## 16. Session Format

| Key | Value |
|-----|-------|
| `session['user']` | Username string |
| `session['user_id']` | `user.id` integer |
| `session['verified_<file_id>']` | `{timestamp, ip, totp_verified, approval_granted}` |
| `session['otp_verified_<file_id>']` | Intermediate state — OTP passed, TOTP/approval pending |

---

## 17. SIEM Integration

Two `SIEMLogger` instances (`app/siem_logger.py`):

| Instance | `log_source` |
|----------|-------------|
| Auth app | `"authentication"` |
| FileTransfer | `"file_transfer"` |

Both post JSON events to `SIEM_URL`. Key FileTransfer events:

```python
siem.file_uploaded(user_id, filename, file_size, ip, file_hash)
siem.file_downloaded(user_id, filename, ip, file_hash)
siem.custom_event(event_type, description, severity, user_id, ip, **extras)
```

> The standalone `siem-dashboard` container is decommissioned. SIEM is now integrated into the main app at the `/siem` route.

---

*End of document.*
