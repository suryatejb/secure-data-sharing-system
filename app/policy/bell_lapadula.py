"""
app/policy/bell_lapadula.py — Bell-LaPadula (BLP) Security Model Enforcement

HISTORY
=======
Developed by David Elliott Bell and Leonard J. LaPadula (1973) for the US DoD
to prevent classified military information from leaking to lower-cleared personnel.
It was the first formal mathematical model of computer security policy.

SECURITY LEVELS (mandatory, totally ordered)
============================================
  PUBLIC(0)  <  CONFIDENTIAL(1)  <  SECRET(2)  <  TOP_SECRET(3)
  
  • Subjects (users) have CLEARANCE levels
  • Objects (files/data) have CLASSIFICATION levels

THE TWO CORE RULES
==================

  ┌──────────────────────────────────────────────────────────────────────────┐
  │  Rule 1 — Simple Security Property ("No Read Up")                        │
  │                                                                          │
  │  Subject S can READ object O  iff  clearance(S) >= classification(O)     │
  │                                                                          │
  │  A SECRET-cleared analyst CAN read CONFIDENTIAL data.                    │
  │  A CONFIDENTIAL-cleared guest CANNOT read SECRET data.                   │
  │  → Information flows DOWN or SIDEWAYS only (toward lower clearances).    │
  └──────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────┐
  │  Rule 2 — ★-Property ("No Write Down" / Star Property)                   │
  │                                                                          │
  │  Subject S can WRITE object O  iff  clearance(S) <= classification(O)    │
  │                                                                          │
  │  A TOP_SECRET user CAN write to a TOP_SECRET document.                   │
  │  A TOP_SECRET user CANNOT write to a PUBLIC document                     │
  │  (that would leak TOP_SECRET info downward).                             │
  │  → Information flows UP or SIDEWAYS only (toward higher classification). │
  └──────────────────────────────────────────────────────────────────────────┘

COMBINED EFFECT
===============
  Information flows UPWARD:  Public → Confidential → Secret → Top Secret
  Information CANNOT flow downward (no leakage to lower-cleared subjects).

LIMITATION & COMPARISON
========================
  • BLP focuses purely on CONFIDENTIALITY (secrecy).
  • The Biba Model is the DUAL — it enforces INTEGRITY:
      Biba No Write Up:   subject writes only objects at or below its integrity level
      Biba No Read Down:  subject reads only objects at or above its integrity level
  • Real systems often combine both (e.g., Lipner model).

This implementation enforces BLP as a second layer on top of RBAC.
RBAC says "does this role allow the action?"; BLP says "is the clearance sufficient?"
"""
from fastapi import HTTPException, status
from app.models.user import SecurityLevel
from app.audit import log_access


class BLPEnforcer:
    """Stateless enforcer for Bell-LaPadula read and write rules."""

    @staticmethod
    def check_read(
        subject_level: int,
        object_level: int,
        context: str = "resource",
        username: str = "unknown",
    ) -> None:
        """
        Enforce the Simple Security Property (No Read Up).

        Raises HTTP 403 with a detailed BLP explanation if violated.

        Args:
            subject_level: Clearance of the user attempting to read
            object_level:  Classification of the data being read
            context:       Human-readable name for the data (used in error message)
        """
        if subject_level < object_level:
            log_access(
                username, "READ", context, "BLP_DENIED",
                f"clearance={SecurityLevel(subject_level).name} < classification={SecurityLevel(object_level).name}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Bell-LaPadula Violation — No Read Up",
                    "rule": "clearance(subject) >= classification(object) required",
                    "subject_clearance": SecurityLevel(subject_level).name,
                    "object_classification": SecurityLevel(object_level).name,
                    "resource": context,
                    "explanation": (
                        f"Your clearance level '{SecurityLevel(subject_level).name}' ({subject_level}) "
                        f"is below the classification '{SecurityLevel(object_level).name}' ({object_level}) "
                        f"of this {context}. BLP prevents reading UP the security lattice."
                    ),
                },
            )

    @staticmethod
    def check_write(
        subject_level: int,
        object_level: int,
        context: str = "resource",
        username: str = "unknown",
    ) -> None:
        """
        Enforce the ★-Property (No Write Down).

        Raises HTTP 403 if the subject's clearance is HIGHER than the target's
        classification (writing down would leak info to lower-cleared readers).

        Args:
            subject_level: Clearance of the user attempting to write
            object_level:  Classification of the target being written to
            context:       Human-readable name for the data
        """
        if subject_level > object_level:
            log_access(
                username, "WRITE", context, "BLP_WRITE_DENIED",
                f"clearance={SecurityLevel(subject_level).name} > classification={SecurityLevel(object_level).name}",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Bell-LaPadula Violation — No Write Down (★-Property)",
                    "rule": "clearance(subject) <= classification(object) required",
                    "subject_clearance": SecurityLevel(subject_level).name,
                    "object_classification": SecurityLevel(object_level).name,
                    "resource": context,
                    "explanation": (
                        f"Your clearance '{SecurityLevel(subject_level).name}' ({subject_level}) "
                        f"exceeds the classification '{SecurityLevel(object_level).name}' ({object_level}) "
                        f"of this {context}. Writing would leak higher-classified info to "
                        "lower-cleared readers of this object."
                    ),
                },
            )

    @staticmethod
    def can_read(subject_level: int, object_level: int) -> bool:
        """Return True if No-Read-Up rule is satisfied (no exception raised)."""
        return subject_level >= object_level

    @staticmethod
    def can_write(subject_level: int, object_level: int) -> bool:
        """Return True if No-Write-Down rule is satisfied (no exception raised)."""
        return subject_level <= object_level


# Singleton — import and use this everywhere
blp = BLPEnforcer()
