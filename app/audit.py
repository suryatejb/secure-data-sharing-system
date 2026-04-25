"""
app/audit.py — Security audit logging

WHY AUDIT LOGGING?
==================
Access control without logging is unenforceable in practice.
You need to know:
  • WHO accessed WHAT, WHEN
  • Which requests were DENIED (and by which layer — RBAC or BLP)
  • Failed login attempts (detect brute-force)

In production this log would be shipped to a SIEM (Security Information and
Event Management) system like Splunk, Elastic SIEM, or AWS CloudTrail.

Log format (one line per event):
  2026-03-26T14:05:01Z | USER=alice | ACTION=READ | RESOURCE=patient_records:anonymized | DECISION=ALLOWED | k=2, records=21
  2026-03-26T14:05:03Z | USER=bob   | ACTION=READ | RESOURCE=patient_records:raw        | DECISION=RBAC_DENIED | required=data:raw:read
  2026-03-26T14:05:10Z | AUTH | USER=eve | DECISION=FAILURE | IP=192.168.1.5

The file is written to audit.log in the working directory.
audit.log is in .gitignore — it may contain sensitive access patterns.
"""
import logging
import os

# Dedicated logger — separate from the uvicorn/FastAPI request logger
_audit_logger = logging.getLogger("security.audit")

if not _audit_logger.handlers:
    _handler = logging.FileHandler(
        os.path.join(os.getcwd(), "audit.log"),
        encoding="utf-8",
    )
    _handler.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
    )
    _audit_logger.addHandler(_handler)
    _audit_logger.setLevel(logging.INFO)
    # Also echo to console so it's visible during development
    _console = logging.StreamHandler()
    _console.setFormatter(logging.Formatter("[AUDIT] %(message)s"))
    _audit_logger.addHandler(_console)


def log_access(
    username: str,
    action: str,
    resource: str,
    decision: str,
    detail: str = "",
) -> None:
    """
    Log a data access or policy enforcement event.

    Args:
        username: Authenticated username (or "unauthenticated")
        action:   READ | WRITE | ACCESS
        resource: Endpoint or resource name (e.g. "patient_records:raw")
        decision: ALLOWED | RBAC_DENIED | BLP_DENIED | BLP_WRITE_DENIED
        detail:   Free-form additional context
    """
    _audit_logger.info(
        f"USER={username} | ACTION={action} | RESOURCE={resource} | "
        f"DECISION={decision} | {detail}"
    )


def log_auth(username: str, success: bool, ip: str = "unknown") -> None:
    """
    Log an authentication attempt (login success or failure).
    Failed login logs are the first line of defence against brute-force attacks.
    """
    decision = "SUCCESS" if success else "FAILURE"
    _audit_logger.info(
        f"AUTH | USER={username} | DECISION={decision} | IP={ip}"
    )
