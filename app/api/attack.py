"""
app/api/attack.py — Linking attack simulation endpoint

GET /attack/linking-demo → runs the full attack + defense walkthrough
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.data import PatientRecord
from app.rbac.engine import require_permission
from app.privacy.attack import simulate_linking_attack

router = APIRouter()


@router.get(
    "/linking-demo",
    summary="[Analyst/Admin] Full linking attack + k-anonymity defense demo",
)
def linking_attack_demo(
    k: int = Query(
        default=2,
        ge=2,
        le=10,
        description="k value for the k-anonymity defense",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("attack:demo")),
):
    """
    Runs a complete linking attack simulation and demonstrates k-anonymity defense.

    Returns:
      - Naive anonymized dataset (just name removed — vulnerable)
      - Simulated voter registration (attacker's public database)
      - Re-identified records (attack success)
      - k-Anonymized dataset
      - Failed re-identification attempts (defense success)
      - Explanations of every step

    RBAC: requires 'attack:demo' permission (Analyst or Admin).
    """
    records = db.query(PatientRecord).all()
    record_dicts = [
        {
            "name":    r.name,
            "age":     r.age,
            "zipcode": r.zipcode,
            "gender":  r.gender,
            "disease": r.disease,
            "salary":  r.salary,
        }
        for r in records
    ]

    result = simulate_linking_attack(record_dicts, k=k)
    result["run_by"] = current_user.username
    return result
