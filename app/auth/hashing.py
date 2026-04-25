"""
app/auth/hashing.py — Password hashing with bcrypt

WHY NOT store plaintext passwords?
  If your database is stolen, every user's password is exposed.
  Users reuse passwords → attacker gains access to their other accounts.

WHY NOT use SHA-256 / MD5?
  These hash functions are designed to be FAST (millions of hashes/sec).
  An attacker with a stolen DB can brute-force millions of guesses per second.
  MD5 is completely broken; SHA-256 is fine for integrity, bad for passwords.

WHY bcrypt?
  1. SLOW by design — the "cost factor" (default 12) means each hash
     takes ~100ms. An attacker can only try ~10 passwords/sec instead of millions.
  2. Built-in SALT — bcrypt generates a random 128-bit salt per password,
     so two users with the same password have different hashes.
     This defeats rainbow table attacks.
  3. Adaptive — as CPUs get faster, increase the cost factor.

bcrypt output format:
  $2b$12$<22-char-salt><31-char-hash>
       ↑   ↑
  version  cost factor (2^12 = 4096 iterations)
"""
from passlib.context import CryptContext

# CryptContext handles algorithm selection and deprecation gracefully
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt. Never store plaintext."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.
    Returns True only if they match.
    Uses constant-time comparison to prevent timing attacks.
    """
    return pwd_context.verify(plain_password, hashed_password)
