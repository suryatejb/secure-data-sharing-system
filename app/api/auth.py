"""
app/api/auth.py — Authentication endpoints

POST /auth/login  → validates credentials, returns JWT
GET  /auth/me     → returns info about the currently authenticated user
"""
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.models.user import User, SecurityLevel
from app.auth.hashing import verify_password
from app.auth.jwt_handler import create_access_token, get_current_user
from app.rbac.engine import get_user_permissions
from app.audit import log_auth

router = APIRouter()

# ─── Rate Limiter ─────────────────────────────────────────────────────────────
# In-memory store: IP address → list of failed-attempt timestamps
# Resets on successful login or after the window expires.
# For production use a distributed cache (Redis) so multiple instances share state.

_failed_attempts: dict[str, list[datetime]] = defaultdict(list)
_rate_lock = threading.Lock()
_MAX_FAILURES = 5
_WINDOW_SECONDS = 300  # 5 minutes


def _check_rate_limit(ip: str) -> None:
    """Raise HTTP 429 if this IP has hit the failure threshold."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=_WINDOW_SECONDS)
    with _rate_lock:
        # Slide the window — discard expired timestamps
        _failed_attempts[ip] = [t for t in _failed_attempts[ip] if t > cutoff]
        if len(_failed_attempts[ip]) >= _MAX_FAILURES:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Too many failed login attempts from this IP. "
                    f"Try again in {_WINDOW_SECONDS // 60} minutes."
                ),
                headers={"Retry-After": str(_WINDOW_SECONDS)},
            )


def _record_failure(ip: str) -> None:
    with _rate_lock:
        _failed_attempts[ip].append(datetime.utcnow())


def _clear_failures(ip: str) -> None:
    with _rate_lock:
        _failed_attempts.pop(ip, None)


# ─── Response Schemas (Pydantic) ─────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    roles: list[str]
    security_level_name: str
    security_level_value: int


class UserInfoResponse(BaseModel):
    id: int
    username: str
    email: str
    security_level_name: str
    security_level_value: int
    roles: list[str]
    permissions: list[str]


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse, summary="Login and get JWT token")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Authenticate with username + password (OAuth2 Password Flow).

    On success → returns a signed JWT access token.
    Include it in subsequent requests as:  Authorization: Bearer <token>

    Test credentials (created by seed):
      admin        / admin123    → Admin,        TOP_SECRET clearance
      alice_analyst/ analyst123  → Analyst,      SECRET clearance
      bob_guest    / guest123    → Guest,         CONFIDENTIAL clearance
      mallory      / mallory123  → SeniorAnalyst, CONFIDENTIAL clearance (BLP read demo)
      curator      / curator123  → DataCurator,   SECRET clearance     (BLP write demo)
    """
    ip = request.client.host if request.client else "unknown"

    # ① Rate limit: 5 failures per 5-minute window per IP
    _check_rate_limit(ip)

    user = db.query(User).filter(User.username == form_data.username).first()

    # Constant-time comparison prevents username enumeration via timing
    if not user or not verify_password(form_data.password, user.hashed_password):
        _record_failure(ip)
        log_auth(form_data.username, success=False, ip=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="User account is disabled.")

    _clear_failures(ip)
    log_auth(user.username, success=True, ip=ip)

    # JWT payload: only the user's numeric ID — nothing sensitive
    token = create_access_token(data={"sub": str(user.id)})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        username=user.username,
        roles=[r.name for r in user.roles],
        security_level_name=SecurityLevel(user.security_level).name,
        security_level_value=user.security_level,
    )


@router.get("/me", response_model=UserInfoResponse, summary="Get current user info")
def get_me(current_user: User = Depends(get_current_user)):
    """
    Return profile and permissions of the authenticated user.
    Requires a valid Bearer token in the Authorization header.
    """
    return UserInfoResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        security_level_name=SecurityLevel(current_user.security_level).name,
        security_level_value=current_user.security_level,
        roles=[r.name for r in current_user.roles],
        permissions=sorted(get_user_permissions(current_user)),
    )
