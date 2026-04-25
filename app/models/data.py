"""
app/models/data.py — PatientRecord (the sensitive dataset)

This simulates a HEALTH DATASET — the typical target in privacy attacks.

Field Classification (important for understanding k-anonymity):

  ┌──────────────────────┬──────────────────────────────────────────────────────┐
  │ Field                │ Type & Privacy Role                                  │
  ├──────────────────────┼──────────────────────────────────────────────────────┤
  │ name                 │ Explicit Identifier — uniquely identifies a person   │
  │                      │ → MUST be removed before any data release            │
  ├──────────────────────┼──────────────────────────────────────────────────────┤
  │ age, zipcode, gender │ Quasi-Identifiers (QI) — don't identify alone,      │
  │                      │ but can be LINKED to public records to re-identify   │
  │                      │ → Must be GENERALIZED (age→range, zip→prefix)        │
  ├──────────────────────┼──────────────────────────────────────────────────────┤
  │ disease, salary      │ Sensitive Attributes — what we're PROTECTING         │
  │                      │ → Released only with k-anonymity guarantees          │
  └──────────────────────┴──────────────────────────────────────────────────────┘

Linking Attack uses quasi-identifiers to JOIN with a public database
(like voter registration) and re-identify the sensitive attributes.
"""
from sqlalchemy import Column, Integer, String, Float
from app.database import Base


class PatientRecord(Base):
    """Synthetic medical record — the sensitive data asset being protected."""
    __tablename__ = "patient_records"

    id   = Column(Integer, primary_key=True, index=True)

    # ── Explicit Identifier (always strip before release) ──────────────────
    name = Column(String, nullable=False)

    # ── Quasi-Identifiers (generalize before release) ──────────────────────
    age     = Column(Integer, nullable=False)
    zipcode = Column(String(10), nullable=False)
    gender  = Column(String(1),  nullable=False)  # "M" or "F"

    # ── Sensitive Attributes (what we protect) ──────────────────────────────
    disease = Column(String,  nullable=False)
    salary  = Column(Float,   nullable=False)

    # ── BLP classification of this record ───────────────────────────────────
    # Raw records → SECRET (level 2).  Anonymized releases → CONFIDENTIAL (level 1).
    classification_level = Column(Integer, default=2)  # 2 = SECRET
