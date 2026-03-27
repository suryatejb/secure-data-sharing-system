"""
app/rbac/engine.py — Role-Based Access Control (RBAC) enforcement

RBAC CONCEPT
============
Managing permissions per individual user is a nightmare at scale.
RBAC solves this by introducing ROLES as an indirection layer:

  WITHOUT RBAC (DAC — Discretionary Access Control):
    alice → {read_medical, write_medical, delete_medical, read_audit, ...}
    bob   → {read_medical, read_audit}
    carol → {read_medical}
    → 1000 users × 50 permissions = 50,000 mappings to manage!

  WITH RBAC:
    alice → [Admin]    → {all permissions}
    bob   → [Analyst]  → {data:anonymized:read, data:summary:read, attack:demo}
    carol → [Guest]    → {data:summary:read}
    → 3 roles × 6 permissions = 18 mappings to manage!

RBAC COMPONENTS
===============
  • Users       — individual people (alice, bob)
  • Roles       — job functions (Admin, Analyst, Guest)
  • Permissions — atomic operations (resource:sub:action)
  • Sessions    — active user + active role subset (we use JWTs for this)

PRINCIPLE OF LEAST PRIVILEGE
==============================
Users should only have the permissions they NEED for their job.
  Guest can only see aggregated stats → cannot see individual records
  Analyst can see anonymized data   → cannot see raw records
  Admin can see everything           → but is logged and auditable

ROLE HIERARCHY (this system — flat, could be extended to hierarchical):
  Admin   > Analyst > Guest
  (not enforced by inheritance here; each role's permissions are explicit)
"""
from fastapi import Depends, HTTPException, status
from app.auth.jwt_handler import get_current_user
from app.models.user import User
from app.audit import log_access


def get_user_permissions(user: User) -> set[str]:
    """
    Return the complete set of permission names for a user.
    Traverses: User → Roles → Permissions.
    """
    permissions: set[str] = set()
    for role in user.roles:
        for perm in role.permissions:
            permissions.add(perm.name)
    return permissions


def require_permission(permission_name: str):
    """
    FastAPI dependency factory — enforces RBAC on a route.

    This uses Python's CLOSURE pattern. Calling require_permission("data:raw:read")
    returns a new function (dependency) that checks for that specific permission.

    Usage:
        @router.get("/data/raw")
        def get_raw(user = Depends(require_permission("data:raw:read"))):
            # Only reaches here if user has the permission
            ...

    Returns the User object so routes can use it directly.
    Raises HTTP 403 Forbidden if the permission is not held.
    """
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        user_permissions = get_user_permissions(current_user)

        if permission_name not in user_permissions:
            # Construct a helpful error — tell them WHAT permission is needed
            user_roles = [r.name for r in current_user.roles]
            log_access(
                current_user.username, "ACCESS", permission_name, "RBAC_DENIED",
                f"roles={user_roles}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "RBAC Access Denied",
                    "required_permission": permission_name,
                    "your_roles": user_roles,
                    "your_permissions": sorted(user_permissions),
                    "hint": (
                        f"Your role(s) {user_roles} do not grant '{permission_name}'. "
                        "Contact an Admin to request elevated access."
                    ),
                },
            )
        return current_user

    return dependency
