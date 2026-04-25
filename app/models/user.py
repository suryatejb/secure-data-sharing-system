"""
app/models/user.py — User, Role, Permission database models

This file encodes two major security concepts:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CONCEPT 1: SecurityLevel (Bell-LaPadula)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Every user has a CLEARANCE level, every data object has a CLASSIFICATION level.
The BLP model enforces:
  • No Read Up:    clearance(user) >= classification(data)   → can read
  • No Write Down: clearance(user) <= classification(target) → can write

Levels form a total order:
  PUBLIC(0) < CONFIDENTIAL(1) < SECRET(2) < TOP_SECRET(3)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CONCEPT 2: RBAC (Role-Based Access)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Instead of assigning permissions to individual users (too complex at scale),
we assign ROLES to users, and PERMISSIONS to roles.

  User  ──assigned──▶  Role(s)  ──grants──▶  Permission(s)
  alice                Analyst               data:anonymized:read
  bob                  Guest                 data:summary:read

Many-to-many relationships:
  users ←──── user_roles ────→ roles ←──── role_permissions ────→ permissions
"""
import enum
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base


class SecurityLevel(int, enum.Enum):
    """
    Bell-LaPadula security classification levels.
    Inheriting from int means these can be stored directly as integers in the DB.
    """
    PUBLIC      = 0
    CONFIDENTIAL = 1
    SECRET      = 2
    TOP_SECRET  = 3


# ─── Association Tables (many-to-many join tables) ────────────────────────────

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id",  Integer, ForeignKey("users.id"),  primary_key=True),
    Column("role_id",  Integer, ForeignKey("roles.id"),  primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id",       Integer, ForeignKey("roles.id"),       primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
)


# ─── ORM Models ───────────────────────────────────────────────────────────────

class User(Base):
    """A system user (subject in BLP terminology)."""
    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String,  unique=True, index=True, nullable=False)
    email           = Column(String,  unique=True, index=True, nullable=False)
    hashed_password = Column(String,  nullable=False)
    # BLP clearance level — determines what data this user can read/write
    security_level  = Column(Integer, default=SecurityLevel.PUBLIC, nullable=False)
    is_active       = Column(Boolean, default=True)

    # RBAC: a user can have multiple roles
    roles = relationship("Role", secondary=user_roles, back_populates="users")


class Role(Base):
    """A job function that bundles related permissions (Admin, Analyst, Guest)."""
    __tablename__ = "roles"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, unique=True, nullable=False)
    description = Column(String)

    users       = relationship("User",       secondary=user_roles,       back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions,  back_populates="roles")


class Permission(Base):
    """
    A fine-grained access right.
    Naming convention: resource:sub-resource:action
    Examples:
      data:raw:read         → read unanonymized records
      data:anonymized:read  → read k-anonymized records
      data:summary:read     → read aggregate stats only
      users:manage          → create/modify users and roles
      attack:demo           → run the linking-attack demo
    """
    __tablename__ = "permissions"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String,  unique=True,  nullable=False)  # e.g. "data:raw:read"
    resource    = Column(String,  nullable=False)                 # e.g. "data"
    action      = Column(String,  nullable=False)                 # e.g. "raw:read"
    description = Column(String)

    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
