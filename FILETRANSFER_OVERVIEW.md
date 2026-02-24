# OpenShare File Transfer System — Technical Overview

> Updated: 2026-02-24

---

## 1. Dual Database System

Files live in **working-db** while active. The `openshare-sync` container runs hourly, copying clean files into the isolated **storage-db**, then NULLing the content in working-db and setting `is_archived=TRUE`.

**`FileTransfer/sync_service.py` — `sync_files()`**
```python
working_cursor.execute("""
    SELECT * FROM file_metadata
    WHERE (is_archived = FALSE OR is_archived IS NULL)
    AND (scan_status = 'clean' OR scan_status IS NULL)
""")
```
Filters out `pending` and `malicious` files — only clean files ever reach storage-db.

```python
storage_cursor.execute("""
    INSERT INTO file_metadata (file_id, ..., file_content, synced_at)
    VALUES (%s, ..., %s, %s)
    ON DUPLICATE KEY UPDATE
        download_count = VALUES(download_count),
        file_content   = VALUES(file_content),
        synced_at      = VALUES(synced_at)
""", (...))
```
Upserts into storage-db — safe to run repeatedly, only mutable fields are overwritten.

```python
archive_cursor.execute(
    "UPDATE file_metadata SET file_content = NULL, is_archived = TRUE WHERE file_id = %s",
    (file['file_id'],)
)
```
Once synced, the file content is NULLed in working-db. The metadata row stays so the file is still listed and searchable, but the bytes only live in storage-db.

When a user downloads an archived file, the main app calls the sync-service HTTP API — it has no direct DB path:

**`FileTransfer/app.py` — `get_file()`**
```python
if file_info.get('is_archived', False):
    response = http_requests.get(f'http://sync-service:8080/retrieve/{file_id}', timeout=30)
    file_content = response.content
else:
    file_info_with_content = db.get_file_metadata(file_id, include_content=True)
    file_content = file_info_with_content['file_content']
```
Checks `is_archived` flag first. If set, it hits the sync-service REST API (`/retrieve/<file_id>`) which pulls the encrypted blob from storage-db and returns it. Otherwise it reads directly from working-db. Transparent to the user either way.

---

## 2. Data Classification

Three levels are set at upload and drive every downstream auth decision:

| Level | Download gates |
|-------|---------------|
| Public | OTP only |
| Internal Use | OTP + TOTP |
| Classified | OTP + TOTP + owner approval |

**`FileTransfer/app.py` — `verify_code()`**
```python
classification = file_info.get('classification', 'Public')

if classification == 'Internal Use' or classification == 'Classified':
    session[f'otp_verified_{file_id}'] = {
        'timestamp': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'totp_verified': False,
        'classification': classification
    }
    return jsonify({'success': True, 'requires_totp': True, ...})

session[f'verified_{file_id}'] = {'timestamp': ..., 'ip': ...}
```
After a valid OTP, Public files write the final `verified_<file_id>` session key immediately — download is unlocked. Internal Use and Classified write a partial `otp_verified_<file_id>` key instead, signalling the frontend to prompt for TOTP next.

**`FileTransfer/app.py` — `verify_totp()`**
```python
if classification == 'Classified':
    otp_session['totp_verified'] = True
    session[f'otp_verified_{file_id}'] = otp_session  # still partial — approval still needed
    return jsonify({'success': True, 'requires_approval': True, ...})

session[f'verified_{file_id}'] = {'totp_verified': True, ...}
```
After a valid TOTP, Internal Use is promoted to full access. Classified stays in the partial `otp_verified_` state with `totp_verified=True`, and the frontend is told to request owner approval next.

---

## 3. Upload Pipeline & Scans

**`FileTransfer/app.py` — `upload_file()`** runs three sequential checks before storing anything.

### Magic-byte validation
```python
detected_mime = magic.Magic(mime=True).from_file(temp_path)

dangerous_mimes = ['application/x-executable', 'application/x-dosexec',
                   'application/x-elf', 'application/x-mach-binary', ...]

if detected_mime in dangerous_mimes:
    return False, f'Executable files are not allowed (detected: {detected_mime})'

if detected_mime not in expected_mimes:
    return False, f'File type mismatch: appears to be {detected_mime} but has .{ext} extension'
```
`python-magic` reads the actual file header bytes (not the filename) to determine the real type. First checks if the real type is a known executable — blocked unconditionally. Then checks if the real type matches the expected types for the declared extension, catching extension spoofing (e.g. a `.jpg` that is actually a PE binary).

### VirusTotal hybrid scan
```python
scan_result = vt_service.scan_file_async_start(file_content, original_filename, file_hash)

if scan_result['immediate_result']:
    if not scan_result['passed']:
        return jsonify({'error': 'File is suspected to be malicious'}), 400
    scan_status = 'clean'
else:
    scan_status = 'pending'
    vt_analysis_id = scan_result['analysis_id']

if scan_status == 'clean':
    response_data['otp_code'] = otp_code
```
First tries a hash lookup against VirusTotal — if VT already knows this SHA-256, the result is instant. If VT doesn't know the file, it's submitted for a full scan and stored with `scan_status='pending'`. The OTP is intentionally withheld from the response until the background `vt_worker` confirms it clean. Malicious files are rejected immediately (known hash) or auto-deleted by the worker (new submission).

### Encrypt & store
```python
db.save_file_metadata(file_id, metadata, file_content)
# Inside db.py: encrypt_file(file_content) → LONGBLOB, encrypt_otp(otp_code) → TEXT
```
Both the file bytes and the OTP code are Fernet-encrypted with separate keys before being written to working-db. Nothing sensitive is stored in plaintext.

### ML analysis (non-blocking)
```python
try:
    ml_result = ml_analyze_file(file_content, original_filename, detected_mime, db)
    db.store_ml_analysis(file_id=file_id, **ml_result)
except Exception as _ml_e:
    print(f'[ML] Analysis skipped for {file_id}: {_ml_e}')
```
Wrapped in a bare `try/except` so any ML failure — missing model, sklearn not installed, DB error — silently logs and continues. The upload is never blocked by the analysis step.

---

## 4. Download — OTP Lookup

**`FileTransfer/db.py` — `find_file_by_otp()`**
```python
cursor.execute("""
    SELECT file_id, current_otp_code FROM file_metadata
    WHERE current_otp_code IS NOT NULL
""")
for row in cursor.fetchall():
    decrypted_otp = decrypt_otp(row['current_otp_code'])
    if decrypted_otp == otp_code:
        return row['file_id']
return None
```
Fernet encryption is non-deterministic (random IV per call), so the same OTP string encrypts to a different ciphertext each time — a SQL `WHERE` comparison is impossible. Instead, every stored OTP is fetched and decrypted in Python one by one until a match is found. `validate_otp()` then checks expiry and the `otp_used` flag before granting access.

---

## 5. Approval System (Classified — Two-Person Rule)

**`FileTransfer/app.py` — `request_approval()`**
```python
if int(owner_id) == int(requester_id):
    session[f'verified_{file_id}'] = {'totp_verified': True, 'self_approved': True, ...}
    return jsonify({'success': True, 'self_approved': True})

request_id = db.create_approval_request(
    file_id=file_id, requester_id=requester_id,
    owner_id=owner_id, requester_ip=request.remote_addr
)
session[f'approval_request_{file_id}'] = request_id
```
If the requester is the file owner, the two-person rule is bypassed and the session is promoted immediately — owners can always access their own files. Otherwise, an `approval_requests` row is created with a 5-minute TTL and the `request_id` is stored in the session so the poll endpoint can verify the right user is checking it.

**`FileTransfer/app.py` — `check_approval_status()`**
```python
if approval['status'] == 'approved':
    session.pop(f'otp_verified_{file_id}', None)
    session[f'verified_{file_id}'] = {'totp_verified': True, 'owner_approved': True, ...}
```
The requester's browser polls this endpoint. Once the owner has approved, the partial `otp_verified_` session is cleared and replaced with the final `verified_` key, unlocking the download. If the 5-minute TTL expires before the owner responds, the status is set to `'expired'` and the requester must start over.

---

## 6. ML Trust-Score Analyzer

**`FileTransfer/ml_analyzer.py` — `analyze_file()`** runs on every upload, non-blocking.

### Stage 1 — Feature extraction
```python
entropy               = _shannon_entropy(file_bytes)
mime_mismatch         = int(declared_is_text and not detected_is_text)
dangerous_extension   = int(ext in DANGEROUS_EXTENSIONS)
pe_in_non_exe         = int(file_bytes[:2] == b'\x4d\x5a' and ext not in {'.exe', ...})
null_byte_ratio       = file_bytes.count(b'\x00') / len(file_bytes)
printable_ratio       = sum(1 for b in file_bytes if 32 <= b <= 126) / len(file_bytes)
suspicious_pattern_count = sum(1 for pat in _COMPILED_PATTERNS if pat.search(file_bytes))
```
Eight numeric features are computed purely from the file bytes and filename — no external calls. `pe_in_non_exe` checks for the Windows PE magic bytes `\x4d\x5a` (MZ header) in a file that isn't declared as an executable. `_COMPILED_PATTERNS` catches PowerShell cmdlets, `eval()`, `<script>` tags, and base64 blobs ≥60 chars.

### Stage 2 — IsolationForest anomaly score
```python
existing_rows = db.get_all_ml_features()
model = _get_or_train_model(feature_rows)   # retrains when sample count grows by ≥10

if model is not None:
    anomaly_score_val = float(model.decision_function([vec])[0])
```
Loads all previously analyzed files' feature vectors from the DB and (re)trains a sklearn `IsolationForest`. The model scores the new file — a negative score means it looks like an outlier compared to everything seen before. Requires at least 5 samples to activate.

### Stage 3 — Trust score
```python
if entropy > 7.5:          score -= 25   # likely encrypted/packed
if mime_mismatch:          score -= 30
if pe_in_non_exe:          score -= 35   # critical — likely embedded malware
if pattern_count >= 3:     score -= 25
if anomaly_score < -0.1:   score -= 15
# ≥80 trustworthy | ≥60 caution | ≥40 suspicious | <40 high_risk
```
Starts at 100 and deducts for each risk signal. Each deduction is recorded with a human-readable description and severity, stored as JSON in `file_ml_analysis.risk_signals`. The final score and `risk_level` label are surfaced in the admin panel.

---

## 7. Forensic Watermark System

On every download, an AES-256-GCM encrypted payload (user identity, IP, user-agent, timestamp, which auth gates passed) is appended to the file bytes — changing the SHA-256 so every user's copy is unique.

**`FileTransfer/watermark.py` — `embed_watermark_in_file()`**
```python
_WM_HEADER = b'\x00\x00OpenShare_WMv1\x00'   # 14 bytes
_WM_FOOTER = b'\x00OpenShare_WMEv1\x00\x00'  # 15 bytes

def embed_watermark_in_file(file_content, encrypted_blob):
    length = struct.pack('>I', len(encrypted_blob))
    return file_content + _WM_HEADER + length + encrypted_blob + _WM_FOOTER
```
Appends a fixed-format block after the original content: a sentinel header, a 4-byte length prefix, the encrypted payload, and a sentinel footer. The sentinels are used by the forensic extractor to locate the block even if the file hash doesn't match.

**`FileTransfer/app.py` — `get_file()`**
```python
watermark_id, encrypted_payload = create_watermark(
    file_id=file_id, user_id=session.get('user_id'),
    download_ip=request.remote_addr, ...
)
watermarked_content = embed_watermark_in_file(file_content, encrypted_payload)
watermarked_hash    = hashlib.sha256(watermarked_content).hexdigest()
db.store_watermark(watermark_id, file_id, original_hash, watermarked_hash, encrypted_payload)
```
After decrypting the file, the watermark is built and embedded before streaming. The resulting SHA-256 (`watermarked_hash`) is stored in `download_watermarks` alongside the encrypted payload so it can be looked up later. The whole block is in a `try/except` — if watermarking fails, the original bytes are sent instead.

**`app/routes.py` — `admin_forensic_check()`**
```python
file_hash = hashlib.sha256(file_bytes).hexdigest()

# Path 1: O(1) hash lookup
wm_row = db.get_watermark_by_watermarked_hash(file_hash)

# Path 2: scan for embedded sentinel bytes if hash lookup misses
if wm_row is None:
    embedded_blob = extract_watermark_from_file(file_bytes)
    if embedded_blob:
        decrypted = decrypt_watermark(embedded_blob)
```
Path 1 is instant — hashes the uploaded file and looks it up directly in `download_watermarks`. Path 2 is the fallback for cases where someone stripped or modified the trailing bytes but the sentinels survived: `extract_watermark_from_file()` scans for `_WM_FOOTER` then `_WM_HEADER`, reads the length prefix, and extracts the encrypted blob to decrypt inline.

---

## 8. Admin File Transfer Panel

All routes in `app/routes.py` require `user.is_admin`.

**File search** — `GET /admin/filetransfer/search` joins `file_metadata` with `file_ml_analysis` to return trust scores alongside file info. Supports `file_id` (exact), `filename` (LIKE), `hash` (LIKE), or `all` (keyword across all three fields).

**ML dashboard** — `GET /admin/filetransfer/ml-scores` returns all analyzed files with trust scores, risk levels, and per-risk-band aggregate stats (count/avg/min/max) used for charts.

**Retention policy** — `POST /admin/filetransfer/retention`
```python
totp = pyotp.TOTP(user.mfa_secret)
if not totp.verify(totp_code, valid_window=1):
    return jsonify({'success': False, 'message': 'Invalid TOTP code'}), 400
```
TOTP is verified before any retention settings are saved. Once saved, `retention_policy.json` is updated on the shared Docker volume — the `openshare-retention` container reads it on every cleanup cycle, so changes take effect without a restart.

**Watermark viewer** — `GET /admin/filetransfer/watermarks/<file_id>` decrypts and returns every download record for a file, showing full downloader identity per event.

**Access logs** — `GET /admin/filetransfer/file/<file_id>/logs` returns the last 100 rows from `access_logs` (every OTP attempt, TOTP check, approval event, and download for that file).

---

*End of document.*
