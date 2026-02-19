"""
Forensic watermark system for OpenShare file transfer.

Each download produces a UNIQUE copy of the file with the watermark bytes
appended to the end.  This changes the file's SHA-256 hash, so uploading a
suspected leaked file to the admin forensic checker identifies exactly one
downloader — not a history of everyone who ever touched the file.

Flow:
  download  → embed_watermark_in_file() → unique bytes → unique hash stored in DB
  forensic  → hash uploaded file → look up in download_watermarks by watermarked_hash
            → fallback: scan file for embedded marker → decrypt inline

Encryption: AES-256-GCM, key stored in /app/keys/watermark.key
"""

import os
import json
import uuid
import base64
import hashlib
import socket
import struct
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


WATERMARK_KEY_ENV  = 'WATERMARK_KEY'
WATERMARK_KEY_FILE = '/app/keys/watermark.key'
WATERMARK_VERSION  = '1.0'

# Sentinel bytes that bracket the appended watermark block.
# Chosen to be highly unlikely to appear in ordinary file content.
_WM_HEADER = b'\x00\x00OpenShare_WMv1\x00'   # 14 bytes
_WM_FOOTER = b'\x00OpenShare_WMEv1\x00\x00'  # 15 bytes


# ── Key management ────────────────────────────────────────────────────────────

def _get_or_create_watermark_key() -> bytes:
    """Load or generate the 32-byte AES-256 watermark key."""
    env_key = os.environ.get(WATERMARK_KEY_ENV)
    if env_key:
        raw = base64.urlsafe_b64decode(env_key.encode())
        if len(raw) == 32:
            return raw

    os.makedirs('/app/keys', exist_ok=True)
    if os.path.exists(WATERMARK_KEY_FILE):
        with open(WATERMARK_KEY_FILE, 'rb') as f:
            raw = f.read()
        if len(raw) == 32:
            return raw

    raw = os.urandom(32)
    with open(WATERMARK_KEY_FILE, 'wb') as f:
        f.write(raw)
    os.chmod(WATERMARK_KEY_FILE, 0o600)
    print('[Watermark] Generated new AES-256-GCM watermark key')
    return raw


def _get_system_fingerprint() -> str:
    parts = [
        os.environ.get('HOSTNAME', socket.gethostname()),
        os.environ.get('WORKING_DB_HOST', ''),
        os.environ.get('WORKING_DB_NAME', ''),
    ]
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]


# ── Encryption / decryption ───────────────────────────────────────────────────

def _encrypt(plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt; returns base64(nonce || ciphertext+tag)."""
    key    = _get_or_create_watermark_key()
    nonce  = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ct_tag)


def _decrypt(blob: bytes | str) -> bytes:
    """AES-256-GCM decrypt; raises on failure."""
    if isinstance(blob, str):
        blob = blob.encode()
    raw   = base64.urlsafe_b64decode(blob)
    nonce = raw[:12]
    return AESGCM(_get_or_create_watermark_key()).decrypt(nonce, raw[12:], None)


# ── Public API ────────────────────────────────────────────────────────────────

def create_watermark(
    file_id: str,
    file_hash: str,
    original_filename: str,
    file_classification: str,
    user_id: int,
    username: str,
    email: str,
    download_ip: str,
    user_agent: str,
    session_id: str | None = None,
    otp_verified: bool = True,
    totp_verified: bool = False,
    approval_granted: bool = False,
) -> tuple[str, bytes]:
    """
    Build and encrypt a forensic watermark payload.

    Returns:
        (watermark_id, encrypted_blob)
        encrypted_blob is base64-encoded bytes, safe to store as TEXT or
        to pass into embed_watermark_in_file().
    """
    watermark_id = str(uuid.uuid4())

    payload = {
        'watermark_id':      watermark_id,
        'watermark_version': WATERMARK_VERSION,
        'created_at':        datetime.now(timezone.utc).isoformat(),

        'file_id':              file_id,
        'file_hash_sha256':     file_hash,
        'original_filename':    original_filename,
        'file_classification':  file_classification,

        'downloader': {
            'user_id':    user_id,
            'username':   username,
            'email':      email,
            'ip_address': download_ip,
            'user_agent': user_agent,
            'session_id': session_id,
        },

        'access_context': {
            'otp_verified':      otp_verified,
            'totp_verified':     totp_verified,
            'approval_granted':  approval_granted,
        },

        'system': {
            'app_version':        '1.0',
            'system_fingerprint': _get_system_fingerprint(),
            'server_hostname':    os.environ.get('HOSTNAME', socket.gethostname()),
        },
    }

    blob = _encrypt(json.dumps(payload, ensure_ascii=False).encode('utf-8'))
    return watermark_id, blob


def embed_watermark_in_file(file_content: bytes, encrypted_blob: bytes) -> bytes:
    """
    Append the encrypted watermark to the file bytes.

    Layout (appended after original content):
        _WM_HEADER  (14 bytes)
        payload_len (4 bytes, big-endian uint32)
        encrypted_blob
        _WM_FOOTER  (15 bytes)

    The result has a different SHA-256 than the original, making each
    user's download uniquely identifiable.
    """
    if isinstance(encrypted_blob, str):
        encrypted_blob = encrypted_blob.encode()
    length = struct.pack('>I', len(encrypted_blob))
    return file_content + _WM_HEADER + length + encrypted_blob + _WM_FOOTER


def extract_watermark_from_file(file_content: bytes) -> bytes | None:
    """
    Scan file bytes for an embedded watermark block and return the
    raw encrypted blob, or None if no watermark is present.
    """
    footer_pos = file_content.rfind(_WM_FOOTER)
    if footer_pos == -1:
        return None

    header_pos = file_content.rfind(_WM_HEADER, 0, footer_pos)
    if header_pos == -1:
        return None

    payload_start = header_pos + len(_WM_HEADER)
    if payload_start + 4 > footer_pos:
        return None

    payload_len = struct.unpack('>I', file_content[payload_start:payload_start + 4])[0]
    blob_start  = payload_start + 4
    blob_end    = blob_start + payload_len

    if blob_end != footer_pos:
        return None

    return file_content[blob_start:blob_end]


def decrypt_watermark(encrypted_blob: bytes | str) -> dict | None:
    """
    Decrypt a forensic watermark payload (from DB or embedded in file).

    Returns the payload dict, or None on failure.
    """
    try:
        return json.loads(_decrypt(encrypted_blob).decode('utf-8'))
    except Exception as e:
        print(f'[Watermark] Decryption failed: {e}')
        return None
