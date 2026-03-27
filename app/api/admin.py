"""
app/api/admin.py — Administration endpoints

Demonstrates the 'users:manage' permission which was previously a dead
permission with no associated route.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models.user import User, Role
from app.rbac.engine import require_permission

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/users",
    summary="List all users and their roles",
    description=(
        "**Requires**: `users:manage` permission (Admin role only).\n\n"
        "Returns every registered user with their assigned roles and "
        "security clearance level."
    ),
)
def list_users(
    _: None = Depends(require_permission("users:manage")),
    db: Session = Depends(get_db),
):
    """
    WHY THIS EXISTS
    ===============
    The 'users:manage' permission was seeded but had no route, making it dead
    code.  This endpoint gives it purpose: only a user with that permission
    (i.e. the Admin role) can enumerate all users and their roles.

    In a real system this would support pagination, filtering, and
    role-assignment operations.
    """
    users = db.query(User).options(selectinload(User.roles)).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "security_level": u.security_level,
            "security_level_name": u.clearance.name,
            "roles": [r.name for r in u.roles],
            "is_active": u.is_active,
        }
        for u in users
    ]
