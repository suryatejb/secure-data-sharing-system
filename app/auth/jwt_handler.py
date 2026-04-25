"""
app/auth/jwt_handler.py — JSON Web Token (JWT) creation and verification

WHAT IS A JWT?
  A JWT is a compact, self-contained token used to transmit identity claims.
  It replaces traditional server-side sessions — the server doesn't store anything.

JWT STRUCTURE (3 base64url-encoded parts separated by dots):
  eyJhbGciOiJIUzI1NiJ9   ← Header  (algorithm: HS256)
  .eyJzdWIiOiI1IiwiZXhwIjoxNzA5MDAwMDAwfQ==  ← Payload (claims: user_id, expiry)
  .XbD6-jPzOlZ4R7...     ← Signature (HMAC-SHA256 of header + payload + secret)

WHY IS IT SECURE?
  The signature is computed using a SECRET KEY only the server knows.
  If an attacker modifies the payload (e.g., changes user_id=5 to user_id=1),
  the signature won't match and the server rejects the token.

WHAT TO PUT IN THE PAYLOAD (claims)?
  ✓ user_id (enough to look up the user)
  ✓ expiry timestamp (exp)
  ✗ passwords — never!
  ✗ sensitive PII — anyone can base64-decode the payload
  → JWT is SIGNED (tamper-proof) but NOT ENCRYPTED (readable)

FLOW:
  1. Client sends POST /auth/login {username, password}
  2. Server verifies password, creates JWT {sub: user_id, exp: now+30min}
  3. Server signs with SECRET_KEY → returns token string
  4. Client stores token (localStorage / cookie)
  5. Client sends: Authorization: Bearer <token>
  6. Server verifies signature, extracts user_id, loads user from DB
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session, selectinload
from app.config import settings
from app.database import get_db

# Tells FastAPI where the login endpoint is (used to generate OpenAPI docs)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Claims to include (should only contain non-sensitive info like user_id)
        expires_delta: Optional custom expiry; defaults to settings value
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency — validates the Bearer token and returns the User object.

    This is injected into route handlers that require authentication:
        def my_route(user = Depends(get_current_user)): ...

    Raises 401 if:
      - Token is missing / malformed
      - Signature is invalid (tampered)
      - Token has expired
      - User no longer exists or is inactive
    """
    # Import here to avoid circular imports (jwt_handler ← models ← database ← config)
    from app.models.user import User, Role

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials — token missing, expired, or tampered.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Eager-load roles → permissions in a single query to avoid N+1 problems
    user = (
        db.query(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .filter(User.id == int(user_id))
        .first()
    )
    if user is None or not user.is_active:
        raise credentials_exception

    return user
