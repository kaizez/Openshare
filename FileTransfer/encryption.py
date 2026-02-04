"""
Encryption utilities for MoveIT file transfer system.
Provides encryption for files and sensitive data like OTP codes.
Uses Fernet (AES-128-CBC with HMAC) for symmetric encryption.
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Get encryption key from environment or generate one
# In production, this should be stored securely and persistently
ENCRYPTION_KEY = os.environ.get('FILE_ENCRYPTION_KEY')
OTP_ENCRYPTION_KEY = os.environ.get('OTP_ENCRYPTION_KEY')

def _get_or_create_key(env_var_name, key_file_name):
    """Get encryption key from environment or file, or generate a new one."""
    # First try environment variable
    key = os.environ.get(env_var_name)
    if key:
        return key.encode() if isinstance(key, str) else key

    # Try to load from file
    key_path = f'/app/keys/{key_file_name}'
    os.makedirs('/app/keys', exist_ok=True)

    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            return f.read()

    # Generate new key and save it
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    os.chmod(key_path, 0o600)  # Restrict permissions
    print(f"[Encryption] Generated new encryption key: {key_file_name}")
    return key


def get_file_cipher():
    """Get Fernet cipher for file encryption."""
    key = _get_or_create_key('FILE_ENCRYPTION_KEY', 'file_encryption.key')
    return Fernet(key)


def get_otp_cipher():
    """Get Fernet cipher for OTP encryption."""
    key = _get_or_create_key('OTP_ENCRYPTION_KEY', 'otp_encryption.key')
    return Fernet(key)


# ==================== FILE ENCRYPTION ====================

def encrypt_file(file_data: bytes) -> bytes:
    """
    Encrypt file data.

    Args:
        file_data: Raw file bytes

    Returns:
        Encrypted file bytes
    """
    cipher = get_file_cipher()
    return cipher.encrypt(file_data)


def decrypt_file(encrypted_data: bytes) -> bytes:
    """
    Decrypt file data.

    Args:
        encrypted_data: Encrypted file bytes

    Returns:
        Decrypted file bytes
    """
    cipher = get_file_cipher()
    return cipher.decrypt(encrypted_data)


def encrypt_file_stream(input_path: str, output_path: str) -> bool:
    """
    Encrypt a file from disk and save to another location.

    Args:
        input_path: Path to the unencrypted file
        output_path: Path to save the encrypted file

    Returns:
        True on success, False on failure
    """
    try:
        with open(input_path, 'rb') as f:
            file_data = f.read()

        encrypted_data = encrypt_file(file_data)

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return True
    except Exception as e:
        print(f"[Encryption] Error encrypting file: {e}")
        return False


def decrypt_file_stream(input_path: str, output_path: str) -> bool:
    """
    Decrypt a file from disk and save to another location.

    Args:
        input_path: Path to the encrypted file
        output_path: Path to save the decrypted file

    Returns:
        True on success, False on failure
    """
    try:
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_file(encrypted_data)

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return True
    except Exception as e:
        print(f"[Encryption] Error decrypting file: {e}")
        return False


# ==================== OTP/DATA ENCRYPTION ====================

def encrypt_otp(otp_code: str) -> str:
    """
    Encrypt an OTP code for database storage.

    Args:
        otp_code: Plain text OTP code

    Returns:
        Base64 encoded encrypted OTP
    """
    cipher = get_otp_cipher()
    encrypted = cipher.encrypt(otp_code.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_otp(encrypted_otp: str) -> str:
    """
    Decrypt an OTP code from database.

    Args:
        encrypted_otp: Base64 encoded encrypted OTP

    Returns:
        Plain text OTP code
    """
    try:
        cipher = get_otp_cipher()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_otp.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        print(f"[Encryption] Error decrypting OTP: {e}")
        # If decryption fails, assume it's a legacy unencrypted OTP
        return encrypted_otp


def encrypt_sensitive_field(data: str) -> str:
    """
    Encrypt a sensitive database field.

    Args:
        data: Plain text data

    Returns:
        Base64 encoded encrypted data
    """
    if not data:
        return data
    cipher = get_otp_cipher()
    encrypted = cipher.encrypt(data.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_sensitive_field(encrypted_data: str) -> str:
    """
    Decrypt a sensitive database field.

    Args:
        encrypted_data: Base64 encoded encrypted data

    Returns:
        Plain text data
    """
    if not encrypted_data:
        return encrypted_data
    try:
        cipher = get_otp_cipher()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        # If decryption fails, assume it's legacy unencrypted data
        return encrypted_data


# ==================== KEY MANAGEMENT ====================

def rotate_keys():
    """
    Rotate encryption keys. This should be called during maintenance.
    Note: This requires re-encrypting all existing data with the new keys.
    """
    # TODO: Implement key rotation with re-encryption of existing data
    pass


def verify_encryption_setup():
    """Verify that encryption is properly configured."""
    try:
        # Test file encryption
        test_data = b"test encryption data"
        encrypted = encrypt_file(test_data)
        decrypted = decrypt_file(encrypted)
        assert decrypted == test_data, "File encryption test failed"

        # Test OTP encryption
        test_otp = "123456"
        encrypted_otp = encrypt_otp(test_otp)
        decrypted_otp = decrypt_otp(encrypted_otp)
        assert decrypted_otp == test_otp, "OTP encryption test failed"

        print("[Encryption] Encryption setup verified successfully")
        return True
    except Exception as e:
        print(f"[Encryption] Encryption verification failed: {e}")
        return False
