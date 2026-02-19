"""
Shamir's Secret Sharing for TOTP Recovery
Splits MFA secret into shares using polynomial interpolation over a finite field.
Any k of n shares can reconstruct the original secret.
"""

import secrets
import hashlib
import base64
import string
from typing import List, Tuple, Optional

# A large prime for the finite field (must be larger than any secret we encode)
# TOTP secrets are 32-char base32 strings = 256 bits as UTF-8, so we need a prime > 256 bits
# Using a 521-bit prime (13th Mersenne prime: 2^521 - 1)
_PRIME = 2**521 - 1

# Default scheme: 3-of-5
DEFAULT_THRESHOLD = 3
DEFAULT_SHARES = 5


def _mod_inverse(a: int, p: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    if a < 0:
        a = a % p
    g, x, _ = _extended_gcd(a, p)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % p


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _eval_polynomial(coefficients: List[int], x: int, prime: int) -> int:
    """Evaluate polynomial at x over finite field."""
    result = 0
    for i, coeff in enumerate(coefficients):
        result = (result + coeff * pow(x, i, prime)) % prime
    return result


def _lagrange_interpolation(shares: List[Tuple[int, int]], prime: int) -> int:
    """Reconstruct secret using Lagrange interpolation at x=0."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (-xj)) % prime
                denominator = (denominator * (xi - xj)) % prime
        lagrange = (yi * numerator * _mod_inverse(denominator, prime)) % prime
        secret = (secret + lagrange) % prime
    return secret


def _secret_to_int(secret: str) -> int:
    """Convert a string secret to an integer."""
    return int.from_bytes(secret.encode('utf-8'), byteorder='big')


def _int_to_secret(number: int) -> str:
    """Convert an integer back to a string secret."""
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder='big').decode('utf-8')


def split_secret(secret: str, threshold: int = DEFAULT_THRESHOLD,
                 num_shares: int = DEFAULT_SHARES) -> List[str]:
    """
    Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret string (e.g., TOTP base32 key)
        threshold: Minimum shares needed to reconstruct (default 3)
        num_shares: Total number of shares to generate (default 5)

    Returns:
        List of share strings in format "index-hexvalue"
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")

    secret_int = _secret_to_int(secret)

    if secret_int >= _PRIME:
        raise ValueError("Secret too large for the prime field")

    # Generate random polynomial coefficients
    # coefficients[0] = secret, rest are random
    coefficients = [secret_int]
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(_PRIME))

    # Evaluate polynomial at points 1..num_shares
    shares = []
    for i in range(1, num_shares + 1):
        y = _eval_polynomial(coefficients, i, _PRIME)
        share_hex = format(y, 'x')
        share_str = f"{i}-{share_hex}"
        # Encode with mixed symbols for stronger-looking shares
        encoded = _encode_share(share_str)
        shares.append(encoded)

    return shares


# Custom encoding alphabet: uppercase, lowercase, digits, symbols
_SHARE_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + '!@#$%&*+-=?~'
_SHARE_BASE = len(_SHARE_ALPHABET)  # 75 characters


_GROUP_SEP = '.'  # Use dot as group separator (not in alphabet)


def _encode_share(raw: str) -> str:
    """Encode a share string into a mixed alphanumeric+symbol format with grouping."""
    raw_bytes = raw.encode('utf-8')
    num = int.from_bytes(raw_bytes, byteorder='big')

    if num == 0:
        return _SHARE_ALPHABET[0]

    chars = []
    while num > 0:
        chars.append(_SHARE_ALPHABET[num % _SHARE_BASE])
        num //= _SHARE_BASE
    encoded = ''.join(reversed(chars))

    # Format in groups of 5 separated by dots for readability
    groups = [encoded[i:i+5] for i in range(0, len(encoded), 5)]
    return _GROUP_SEP.join(groups)


def _decode_share(encoded: str) -> str:
    """Decode a mixed symbol share back to raw format."""
    clean = encoded.replace(_GROUP_SEP, '')
    num = 0
    for char in clean:
        num = num * _SHARE_BASE + _SHARE_ALPHABET.index(char)
    raw_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    return raw_bytes.decode('utf-8')


def reconstruct_secret(shares: List[str], threshold: int = DEFAULT_THRESHOLD) -> Optional[str]:
    """
    Reconstruct a secret from shares.

    Args:
        shares: List of share strings (at least `threshold` shares needed)
        threshold: Minimum shares required

    Returns:
        The original secret string, or None if reconstruction fails
    """
    if len(shares) < threshold:
        return None

    try:
        # Decode shares
        points = []
        for share in shares[:threshold]:
            # Try new mixed-symbol format first
            try:
                decoded = _decode_share(share)
            except Exception:
                # Fallback: legacy base32 format
                padded = share + '=' * ((8 - len(share) % 8) % 8)
                decoded = base64.b32decode(padded).decode()

            # Parse "index-hexvalue"
            parts = decoded.split('-', 1)
            x = int(parts[0])
            y = int(parts[1], 16)
            points.append((x, y))

        # Reconstruct using Lagrange interpolation
        secret_int = _lagrange_interpolation(points, _PRIME)
        return _int_to_secret(secret_int)

    except Exception:
        return None


def hash_share(share: str) -> str:
    """Hash a share for storage (so we can verify shares without storing plaintext)."""
    return hashlib.sha256(share.encode()).hexdigest()


def generate_recovery_shares(mfa_secret: str) -> Tuple[List[str], List[str]]:
    """
    Generate recovery shares for an MFA secret.

    Returns:
        Tuple of (shares, hashed_shares)
        - shares: List of 5 share codes to give to the user
        - hashed_shares: List of SHA256 hashes for storage in DB
    """
    shares = split_secret(mfa_secret, DEFAULT_THRESHOLD, DEFAULT_SHARES)
    hashed = [hash_share(s) for s in shares]
    return shares, hashed


def recover_mfa_secret(shares: List[str]) -> Optional[str]:
    """
    Recover MFA secret from user-provided shares.

    Args:
        shares: List of at least 3 share codes

    Returns:
        The original MFA secret, or None if recovery fails
    """
    return reconstruct_secret(shares, DEFAULT_THRESHOLD)
