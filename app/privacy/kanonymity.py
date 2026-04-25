"""
app/privacy/kanonymity.py — k-Anonymity implementation

BACKGROUND
==========
Introduced by Latanya Sweeney (PhD thesis & 2002 IJUFKS paper).
Motivated by a real incident: the Massachusetts Group Insurance Commission
released "anonymized" hospital records (names removed).
Sweeney spent $20 on the Cambridge voter registration list and re-identified
the medical record of the state governor within days.

THE CORE INSIGHT
================
Removing EXPLICIT IDENTIFIERS (name, SSN) is NOT enough.
QUASI-IDENTIFIERS (QI) — attributes like age, zip code, gender —
are individually harmless but can be COMBINED to uniquely identify a person.
Sweeney showed that 87% of Americans are uniquely identified by {ZIP, DOB, Sex}.

k-ANONYMITY DEFINITION
=======================
A dataset D satisfies k-anonymity if, for every record r in D,
there exist at least (k - 1) other records in D with IDENTICAL values
on all quasi-identifier attributes.

In other words: you cannot tell one person apart from at least (k-1) others.

Example (k = 2):

  NOT 2-anonymous (Alice is unique → re-identifiable):
  ┌──────┬─────────┬────────┬─────────────┐
  │ Age  │ Zipcode │ Gender │ Disease      │
  ├──────┼─────────┼────────┼─────────────┤
  │  34  │  10025  │   F    │ Cancer       │  ← UNIQUE group
  │  34  │  10025  │   M    │ Flu          │  ← 2 M records = safe
  │  34  │  10025  │   M    │ Diabetes     │  ↑
  └──────┴─────────┴────────┴─────────────┘

  2-ANONYMOUS (every row indistinguishable from ≥ 1 other):
  ┌───────┬─────────┬────────┬─────────────┐
  │ Age   │ Zipcode │ Gender │ Disease      │
  ├───────┼─────────┼────────┼─────────────┤
  │ 30-39 │  100**  │   F    │ Cancer       │  ← group size 2 ✓
  │ 30-39 │  100**  │   F    │ Flu          │  ↑
  │ 30-39 │  100**  │   M    │ Flu          │  ← group size 2 ✓
  │ 30-39 │  100**  │   M    │ Diabetes     │  ↑
  └───────┴─────────┴────────┴─────────────┘

GENERALIZATION HIERARCHY
=========================
Each quasi-identifier has a domain generalization hierarchy (DGH):

  Age:     34  →  30-39  →  20-39  →  *
  Zipcode: 10025  →  100**  →  10***  →  *****
  Gender:  F / M  → (already binary, suppress if necessary)

TECHNIQUE 1 — Generalization: Replace specific values with broader categories.
TECHNIQUE 2 — Suppression:    Remove records whose QI combo is too rare
                               to generalize into a k-sized group.

PRIVACY vs. UTILITY TRADEOFF
==============================
Higher k → more privacy, less useful data (blurrier age ranges, shorter zipcodes).
Lower k  → more detail, higher re-identification risk.
Typical values: k = 2 (basic), k = 5 (healthcare), k = 10+ (high-sensitivity).

LIMITATIONS
===========
  • k-anonymity doesn't protect against attribute disclosure
    (if all k records in a group have the same disease, it's still revealed).
    → l-diversity and t-closeness address this.
  • Doesn't account for attackers with background knowledge.
"""
import pandas as pd
from typing import List, Tuple

# Quasi-identifiers — attributes linkable to external databases
QUASI_IDENTIFIERS = ["age", "zipcode", "gender"]

# Sensitive attributes — what we're protecting
SENSITIVE_ATTRIBUTES = ["disease", "salary"]


# ─── Generalization Functions ─────────────────────────────────────────────────

def generalize_age(age: int, level: int = 1) -> str:
    """
    Generalize age into decade or 20-year buckets.

    Level 1: 10-year ranges  →  34 becomes "30-39"
    Level 2: 20-year ranges  →  34 becomes "20-39"
    Level 3: fully suppress  →  34 becomes "*"
    """
    if level == 1:
        base = (age // 10) * 10
        return f"{base}-{base + 9}"
    elif level == 2:
        base = (age // 20) * 20
        return f"{base}-{base + 19}"
    return "*"


def generalize_zipcode(zipcode: str, level: int = 1) -> str:
    """
    Generalize zipcode by masking trailing digits.

    Level 0: exact           →  "10025"
    Level 1: mask last 2     →  "100**"
    Level 2: mask last 3     →  "10***"
    Level 3: fully suppress  →  "*****"
    """
    z = str(zipcode).strip()
    if level == 0:
        return z
    elif level == 1:
        return (z[:3] + "**") if len(z) >= 3 else "*" * len(z)
    elif level == 2:
        return (z[:2] + "***") if len(z) >= 2 else "*" * len(z)
    return "*" * 5


# ─── k-Anonymity Checker ──────────────────────────────────────────────────────

def check_k_anonymity(
    df: pd.DataFrame,
    quasi_cols: List[str],
    k: int,
) -> Tuple[bool, pd.DataFrame]:
    """
    Check whether a DataFrame satisfies k-anonymity on the given QI columns.

    Returns:
        (is_k_anonymous, violations_df)
        violations_df contains each QI combination with group_size < k.
    """
    group_counts = df.groupby(quasi_cols).size().reset_index(name="group_size")
    violations = group_counts[group_counts["group_size"] < k]
    return len(violations) == 0, violations


# ─── Main Anonymization Pipeline ─────────────────────────────────────────────

def anonymize_dataset(records: List[dict], k: int = 2) -> dict:
    """
    Apply k-anonymity to a list of patient record dicts.

    Algorithm (progressive generalization):
      1. Strip explicit identifiers (name)
      2. Try generalization at (age_level=1, zip_level=1)
      3. If k-anonymity not achieved, escalate generalization
      4. If still violated after max generalization, SUPPRESS violating groups

    Returns a result dict with:
      - anonymized records (safe to release)
      - statistics (group sizes, suppression count, etc.)
      - generalization level applied
    """
    if not records:
        return {
            "anonymized": [], "k": k,
            "total_original": 0, "total_released": 0,
            "suppressed_count": 0,
        }

    original_df = pd.DataFrame(records)
    qi_cols = ["age", "zipcode", "gender"]

    # Generalization strategies to try (escalating from least to most lossy)
    strategies = [
        (1, 1),  # 10-yr age buckets + 3-digit zip prefix
        (1, 2),  # 10-yr age buckets + 2-digit zip prefix
        (2, 1),  # 20-yr age buckets + 3-digit zip prefix
        (2, 2),  # 20-yr age buckets + 2-digit zip prefix
    ]

    df_anon = None
    applied_age_level, applied_zip_level = 1, 1
    is_anon = False

    for age_level, zip_level in strategies:
        # Build a generalized copy without the explicit identifier
        candidate = original_df.drop(columns=["name"], errors="ignore").copy()
        candidate["age"]     = original_df["age"].apply(lambda x: generalize_age(int(x), age_level))
        candidate["zipcode"] = original_df["zipcode"].apply(lambda z: generalize_zipcode(str(z), zip_level))

        is_anon, _ = check_k_anonymity(candidate, qi_cols, k)
        df_anon = candidate
        applied_age_level, applied_zip_level = age_level, zip_level

        if is_anon:
            break

    # Last resort: suppress records in groups that still violate k
    suppressed_count = 0
    if not is_anon and df_anon is not None:
        group_sizes = df_anon.groupby(qi_cols).size().reset_index(name="_count")
        valid_combos = group_sizes[group_sizes["_count"] >= k][qi_cols]
        df_anon = df_anon.merge(valid_combos, on=qi_cols, how="inner")
        suppressed_count = len(original_df) - len(df_anon)

    # Compute group statistics for the audit report
    group_stats = df_anon.groupby(qi_cols).size().reset_index(name="group_size")
    min_gs = int(group_stats["group_size"].min()) if len(group_stats) > 0 else 0
    max_gs = int(group_stats["group_size"].max()) if len(group_stats) > 0 else 0

    return {
        "anonymized": df_anon.to_dict(orient="records"),
        "k_requested": k,
        "k_achieved": min_gs,          # actual minimum group size
        "total_original": len(original_df),
        "total_released": len(df_anon),
        "suppressed_count": suppressed_count,
        "utility_retention": f"{round(len(df_anon) / len(original_df) * 100, 1)}%",
        "generalization_applied": {
            "age_level":     applied_age_level,
            "age_transform": f"exact → {'decade' if applied_age_level == 1 else '20-yr' if applied_age_level == 2 else '*'} ranges",
            "zip_level":     applied_zip_level,
            "zip_transform": f"exact → {['exact','3-digit+**','2-digit+***','*****'][applied_zip_level]}",
        },
        "group_distribution": group_stats.to_dict(orient="records"),
        "quasi_identifiers":   QUASI_IDENTIFIERS,
        "sensitive_attributes": SENSITIVE_ATTRIBUTES,
        "explicit_identifiers_removed": ["name"],
    }
