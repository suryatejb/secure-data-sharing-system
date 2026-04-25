"""
app/privacy/attack.py — Linking Attack demonstration

THE REAL INCIDENT (Sweeney, 1997)
==================================
The Massachusetts Group Insurance Commission (GIC) released hospital discharge
records for research, removing "obvious" identifiers: name, SSN, address.
They kept: ZIP code, birthdate, sex, diagnosis, procedure, charge, etc.

Latanya Sweeney (then a graduate student) bought the Cambridge, MA voter
registration list for $20. It contained: name, address, ZIP, birthdate, sex.

By joining on {ZIP, birthdate, sex}:
  → She re-identified 87% of Americans' medical records
  → She mailed the governor's medical records to his office

Lesson: Removing names is NOT anonymization.

HOW THE ATTACK WORKS
=====================

  Attacker holds TWO databases:

  ┌── "Public" Voter Registration ─┐   ┌── "Anonymized" Medical Records ──┐
  │ Name  | Age | ZIP   | Gender  │   │ Age | ZIP   | Gender | Disease    │
  │ Alice │  34 │ 10025 │  F       │   │  34 │ 10025 │   F    │ Cancer     │
  │ Bob   │  34 │ 10025 │  M       │   │  34 │ 10025 │   M    │ Diabetes   │
  └────────────────────────────────┘   └────────────────────────────────────┘

  JOIN on (Age, ZIP, Gender):
  → (34, 10025, F) appears ONCE in both → Alice has Cancer
  
  If (Age, ZIP, Gender) is UNIQUE → perfect re-identification.

HOW k-ANONYMITY DEFEATS IT
============================
After generalization (10-year age buckets, masked ZIP):

  ┌── k-Anonymized Medical Records ─────────────────────────────────────────┐
  │ Age   | ZIP  | Gender | Disease                                          │
  │ 30-39 │ 100**│   F    │ Cancer     ← 2 F records with same QI           │
  │ 30-39 │ 100**│   F    │ Flu        ↑ attacker can't tell which is Alice │
  │ 30-39 │ 100**│   M    │ Diabetes   ← 2 M records similarly              │
  │ 30-39 │ 100**│   M    │ Flu        ↑                                     │
  └──────────────────────────────────────────────────────────────────────────┘

  JOIN now returns 2 matches for Alice → attacker can't determine her disease.
"""
import pandas as pd
from typing import List
from app.privacy.kanonymity import generalize_age, generalize_zipcode, check_k_anonymity


def simulate_linking_attack(patient_records: List[dict], k: int = 2) -> dict:
    """
    Full linking attack simulation — attack, then defend.

    Steps:
      1. Naive anonymization (only remove name) → show it's vulnerable
      2. Simulate a public voter registration database
      3. JOIN on quasi-identifiers → compute re-identification rate
      4. Apply k-anonymity defense
      5. Re-run the attack → show failure rate

    Returns a comprehensive report suitable for API response or presentation.
    """
    df_medical = pd.DataFrame(patient_records)
    qi_cols = ["age", "zipcode", "gender"]

    # ── STEP 1: Naive "anonymization" (just drop name) ────────────────────────
    df_naive = df_medical.drop(columns=["name"]).copy()
    df_naive["record_id"] = range(1, len(df_naive) + 1)

    # ── STEP 2: Simulate public voter registration database ───────────────────
    # In a real attack the adversary purchases or downloads this from public sources.
    df_voter = df_medical[["name", "age", "zipcode", "gender"]].copy()
    df_voter["voter_id"] = range(1001, 1001 + len(df_medical))

    # Add two decoy voters whose QI values don't exist in the medical dataset.
    # In a real voter roll, most registrants have no associated medical record —
    # the dataset just happens to share some QI values, enabling the attack.
    decoys = pd.DataFrame([
        {"name": "Zara Malik",   "age": 19, "zipcode": "99999", "gender": "F", "voter_id": 9001},
        {"name": "Owen Maxwell", "age": 72, "zipcode": "88888", "gender": "M", "voter_id": 9002},
    ])
    df_voter = pd.concat([df_voter, decoys], ignore_index=True)

    # ── STEP 3: Linking attack on naive dataset ───────────────────────────────
    # JOIN voter list + medical records on quasi-identifiers
    df_linked = df_voter.merge(df_naive, on=qi_cols, how="inner")

    # Count how many medical records each name matches
    match_counts = (
        df_linked.groupby("name")["record_id"]
        .count()
        .reset_index(name="match_count")
    )

    # A record is RE-IDENTIFIED when exactly ONE match exists (unique QI combo)
    unique_matches = match_counts[match_counts["match_count"] == 1]
    df_reidentified = df_linked.merge(unique_matches[["name"]], on="name")

    # ── STEP 4: k-Anonymity defense ───────────────────────────────────────────
    # Try progressively stronger generalizations until k-anonymity is achieved
    strategies = [(1, 1), (1, 2), (2, 1), (2, 2)]
    df_defended = None
    applied_age_level, applied_zip_level = 1, 1
    is_anon = False

    for age_level, zip_level in strategies:
        candidate = df_naive.copy()
        candidate["age"]     = df_medical["age"].apply(lambda x: generalize_age(int(x), age_level))
        candidate["zipcode"] = df_medical["zipcode"].apply(lambda z: generalize_zipcode(str(z), zip_level))

        is_anon, _ = check_k_anonymity(candidate, qi_cols, k)
        df_defended = candidate
        applied_age_level, applied_zip_level = age_level, zip_level

        if is_anon:
            break

    # If no generalization strategy achieved k-anonymity, suppress the outlier records
    if not is_anon and df_defended is not None:
        group_sizes = df_defended.groupby(qi_cols).size().reset_index(name="_c")
        valid = group_sizes[group_sizes["_c"] >= k][qi_cols]
        df_defended = df_defended.merge(valid, on=qi_cols, how="inner")

    # ── STEP 5: Re-run attack on k-anonymized data ────────────────────────────
    # Must generalize the voter data with THE SAME mapping used on medical records
    # so both sides have identical data types for the join columns.
    df_voter_gen = df_voter.copy()
    df_voter_gen["age"]     = df_medical["age"].apply(lambda x: generalize_age(int(x), applied_age_level))
    df_voter_gen["zipcode"] = df_medical["zipcode"].apply(lambda z: generalize_zipcode(str(z), applied_zip_level))

    df_attack_defended = df_voter_gen.merge(df_defended, on=qi_cols, how="inner")

    match_counts_def = (
        df_attack_defended.groupby("name")["record_id"]
        .count()
        .reset_index(name="match_count")
    )
    unique_matches_def = match_counts_def[match_counts_def["match_count"] == 1]
    df_reidentified_after = df_attack_defended.merge(unique_matches_def[["name"]], on="name")

    # ── Assemble report ───────────────────────────────────────────────────────
    reidentified_before = len(df_reidentified["name"].unique()) if len(df_reidentified) > 0 else 0
    reidentified_after  = len(df_reidentified_after["name"].unique()) if len(df_reidentified_after) > 0 else 0

    return {
        "attack_summary": {
            "total_records": len(df_medical),
            "re_identified_WITHOUT_defense": reidentified_before,
            "re_identified_WITH_k_anonymity": reidentified_after,
            "re_identification_rate_before": f"{round(reidentified_before / len(df_medical) * 100, 1)}%",
            "re_identification_rate_after":  f"{round(reidentified_after  / len(df_medical) * 100, 1)}%",
            "k_value_used": k,
        },
        "step1_naive_anonymized_sample": df_naive.head(5).to_dict(orient="records"),
        "step2_voter_registration_sample": (
            df_voter[["name", "age", "zipcode", "gender"]].head(5).to_dict(orient="records")
        ),
        "step3_reidentified_records": (
            df_reidentified[["name", "age", "zipcode", "gender", "disease"]]
            .head(10)
            .to_dict(orient="records")
            if len(df_reidentified) > 0
            else []
        ),
        "step4_k_anonymous_sample": df_defended.head(5).to_dict(orient="records"),
        "step5_failed_reidentification_attempts": (
            df_reidentified_after[["name", "age", "zipcode", "gender"]].head(5).to_dict(orient="records")
            if len(df_reidentified_after) > 0
            else []
        ),
        "generalization_applied": {
            "age":     f"Level {applied_age_level} — {'decade ranges' if applied_age_level == 1 else '20-yr ranges'}",
            "zipcode": f"Level {applied_zip_level} — mask last {2 if applied_zip_level == 1 else 3} digits",
        },
        "concept_explanation": {
            "naive_anonymization": (
                "Simply removing the name field is insufficient. "
                "Quasi-identifiers (age, ZIP, gender) still uniquely identify individuals "
                "when joined with publicly available data (voter records, social media profiles)."
            ),
            "linking_attack": (
                "The attacker joins the 'anonymized' medical dataset with a public voter "
                "registration database on shared quasi-identifiers. If a QI combination "
                "is unique across both datasets, the individual is perfectly re-identified."
            ),
            "k_anonymity_defense": (
                f"k-Anonymity (k={k}) guarantees every QI combination appears in ≥{k} records. "
                f"After generalization, a JOIN produces ≥{k} candidates per name — "
                "the attacker cannot determine which record belongs to a specific individual."
            ),
            "real_world_lesson": (
                "Latanya Sweeney (1997) demonstrated this attack on Massachusetts hospital "
                "records — she re-identified the governor's medical history using only a "
                "$20 voter registration list. This incident led directly to HIPAA regulations."
            ),
        },
    }
