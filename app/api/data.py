"""
app/api/data.py — Protected data access endpoints

Each endpoint enforces TWO security layers in sequence:

  Layer 1 — RBAC:  Does this user's role grant the required permission?
  Layer 2 — BLP:   Does this user's clearance level meet the data classification?

Both must pass. RBAC failing → 403 with "permission denied".
BLP failing → 403 with "Bell-LaPadula violation" detail.

Endpoints:
  GET  /data/raw          → Admin only              (raw records, no privacy filter)
  GET  /data/anonymized   → Analyst and up          (k-anonymized release)
  GET  /data/summary      → Guest and up            (aggregate stats only)
  POST /data/records      → DataCurator or Admin    (BLP No-Write-Down demo)

  The POST endpoint is the key BLP ★-Property demo:
    - DataCurator (SECRET=2): RBAC ✓, BLP 2≤1=2 ✓ → 201 Created
    - Admin      (TOP_SECRET=3): RBAC ✓, BLP 3>2 ✗ → 403 BLP Write Denied
"""
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User, SecurityLevel
from app.models.data import PatientRecord
from app.rbac.engine import require_permission
from app.policy.bell_lapadula import blp
from app.privacy.kanonymity import anonymize_dataset
from app.audit import log_access

router = APIRouter()

# Classification level assigned to raw patient data
RAW_DATA_LEVEL      = SecurityLevel.SECRET        # level 2
ANON_DATA_LEVEL     = SecurityLevel.CONFIDENTIAL  # level 1


# ─── Request Schema for POST /data/records ────────────────────────────────────

class NewPatientRecord(BaseModel):
    """Payload for creating a new patient record (all records are classified SECRET)."""
    age:     int   = Field(ge=0, le=150, description="Patient age in years")
    zipcode: str   = Field(min_length=5, max_length=10, description="Postal code")
    gender:  str   = Field(pattern="^[MF]$",            description="M or F")
    disease: str   = Field(min_length=1, max_length=100)
    salary:  float = Field(ge=0.0,                      description="Annual salary")


@router.get(
    "/raw",
    summary="[Admin] Raw patient records (RBAC + BLP enforced)",
)
def get_raw_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("data:raw:read")),
):
    """
    Return the complete, unanonymized patient dataset.

    Security gates:
      ① RBAC check:  must hold 'data:raw:read' (Admin role only)
      ② BLP No-Read-Up: clearance(user) >= SECRET(2)

    Even if RBAC passes, a user manually assigned a lower BLP level
    would still be rejected by the second check.
    """
    # ② BLP enforcement — independent second check
    blp.check_read(
        subject_level=current_user.security_level,
        object_level=RAW_DATA_LEVEL,
        context="raw patient records (classified SECRET)",
        username=current_user.username,
    )

    records = db.query(PatientRecord).all()
    log_access(current_user.username, "READ", "patient_records:raw", "ALLOWED",
               f"records={len(records)}")

    return {
        "security_checks_passed": ["RBAC: data:raw:read ✓", f"BLP: No-Read-Up ✓"],
        "user":              current_user.username,
        "user_clearance":    SecurityLevel(current_user.security_level).name,
        "data_classification": SecurityLevel(RAW_DATA_LEVEL).name,
        "record_count":      len(records),
        "warning":           "This is raw unanonymized data — do NOT share externally",
        "records": [
            {
                "id":            r.id,
                "name":          r.name,
                "age":           r.age,
                "zipcode":       r.zipcode,
                "gender":        r.gender,
                "disease":       r.disease,
                "salary":        r.salary,
                "classification": SecurityLevel(r.classification_level).name,
            }
            for r in records
        ],
    }


@router.get(
    "/anonymized",
    summary="[Analyst] k-Anonymized patient records (RBAC + BLP + k-Anonymity)",
)
def get_anonymized_data(
    k: int = Query(
        default=2,
        ge=2,
        le=10,
        description="k-anonymity parameter — minimum indistinguishable group size",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("data:anonymized:read")),
):
    """
    Return k-anonymized patient data.

    Security gates:
      ① RBAC check:  must hold 'data:anonymized:read' (Analyst or Admin)
      ② BLP No-Read-Up: clearance(user) >= CONFIDENTIAL(1)

    Privacy:
      • Explicit identifiers (name) removed
      • Quasi-identifiers generalized (age → decade range, zipcode → prefix)
      • k-anonymity guaranteed — every QI group has ≥ k records
    """
    blp.check_read(
        subject_level=current_user.security_level,
        object_level=ANON_DATA_LEVEL,
        context="anonymized patient records (classified CONFIDENTIAL)",
        username=current_user.username,
    )

    records = db.query(PatientRecord).all()
    raw_dicts = [
        {
            "name": r.name, "age": r.age, "zipcode": r.zipcode,
            "gender": r.gender, "disease": r.disease, "salary": r.salary,
        }
        for r in records
    ]

    result = anonymize_dataset(raw_dicts, k=k)
    log_access(current_user.username, "READ", "patient_records:anonymized", "ALLOWED",
               f"k={k}, records={result.get('record_count', '?')}")
    result["security_checks_passed"] = [
        "RBAC: data:anonymized:read ✓",
        f"BLP: No-Read-Up ✓ (clearance={SecurityLevel(current_user.security_level).name})",
    ]
    result["user"] = current_user.username
    return result


@router.get(
    "/summary",
    summary="[Guest] Aggregate statistics only (no individual records)",
)
def get_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("data:summary:read")),
):
    """
    Return aggregate statistics — completely safe for Guest access.

    No individual records are returned, only counts and averages.
    This is the 'minimum necessary' principle in action.
    """
    records = db.query(PatientRecord).all()

    if not records:
        return {"message": "No records in the database."}

    disease_dist: dict[str, int] = {}
    gender_dist:  dict[str, int] = {"M": 0, "F": 0}
    total_salary = 0.0

    for r in records:
        disease_dist[r.disease] = disease_dist.get(r.disease, 0) + 1
        gender_dist[r.gender]   = gender_dist.get(r.gender, 0) + 1
        total_salary += r.salary

    log_access(current_user.username, "READ", "patient_records:summary", "ALLOWED",
               f"records={len(records)}")
    return {
        "access_level": "GUEST — aggregate statistics only",
        "security_checks_passed": ["RBAC: data:summary:read ✓"],
        "user": current_user.username,
        "note": "No individual records returned — only population-level aggregates.",
        "total_patients":       len(records),
        "disease_distribution": disease_dist,
        "gender_distribution":  gender_dist,
        "average_salary":       round(total_salary / len(records), 2),
    }


@router.post(
    "/records",
    status_code=201,
    summary="[DataCurator] Create patient record (BLP No-Write-Down demo)",
)
def create_record(
    record: NewPatientRecord,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("data:write")),
):
    """
    Create a new patient record (classified SECRET).

    This endpoint is the live demo of the Bell-LaPadula **★-Property**
    (No Write Down).  Both Admin and DataCurator have the `data:write` RBAC
    permission, but:

    | User         | Clearance         | BLP check (clearance <= SECRET=2) | Result |
    |---|---|---|---|
    | curator      | SECRET (2)        | 2 ≤ 2  ✓                          | 201 Created |
    | admin        | TOP_SECRET (3)    | 3 > 2  ✗ — would leak TOP_SECRET info into SECRET object | 403 |

    Why does this matter?
    ---------------------
    If the Admin writes to a SECRET-classified object, any SECRET-cleared user
    can later read it.  That leaks TOP_SECRET information downward — exactly
    what BLP prevents.

    Try it in /docs:
      1. Login as **curator / curator123** → POST succeeds
      2. Login as **admin  / admin123**   → POST returns 403 BLP violation
    """
    # ② BLP No-Write-Down — clearance(user) must be <= classification(data)
    blp.check_write(
        subject_level=current_user.security_level,
        object_level=SecurityLevel.SECRET,
        context="patient records (classified SECRET)",
        username=current_user.username,
    )

    new_record = PatientRecord(
        name="[redacted — added via API]",
        age=record.age,
        zipcode=record.zipcode,
        gender=record.gender,
        disease=record.disease,
        salary=record.salary,
        classification_level=SecurityLevel.SECRET,
    )
    db.add(new_record)
    db.commit()
    db.refresh(new_record)

    log_access(current_user.username, "WRITE", "patient_records:raw", "ALLOWED",
               f"new_record_id={new_record.id}")

    return {
        "security_checks_passed": [
            "RBAC: data:write ✓",
            f"BLP: No-Write-Down ✓ (clearance={SecurityLevel(current_user.security_level).name} <= SECRET)",
        ],
        "created": {
            "id":             new_record.id,
            "age":            new_record.age,
            "zipcode":        new_record.zipcode,
            "gender":         new_record.gender,
            "disease":        new_record.disease,
            "salary":         new_record.salary,
            "classification": SecurityLevel(new_record.classification_level).name,
        },
    }
