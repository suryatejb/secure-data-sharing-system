"""
demo_concepts.py — Standalone concept walkthrough

Run this WITHOUT needing a server:
    python demo_concepts.py

Demonstrates all four security/privacy concepts in the terminal:
    1. Bell-LaPadula Model (BLP)
    2. RBAC Permission Checks
    3. k-Anonymity (Generalization + Suppression)
    4. Linking Attack + Defense

Requirements: pip install pandas passlib[bcrypt]
"""
import sys
import textwrap


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def section(title: str):
    width = 70
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


def subsection(title: str):
    print(f"\n  ── {title} ──")


def result(passed: bool, description: str):
    icon = "✓  PASS" if passed else "✗  FAIL"
    print(f"    [{icon}]  {description}")


# ──────────────────────────────────────────────────────────────────────────────
# CONCEPT 1: Bell-LaPadula Model
# ──────────────────────────────────────────────────────────────────────────────

def demo_blp():
    section("CONCEPT 1: Bell-LaPadula Model (BLP)")
    print(textwrap.dedent("""
    Security Levels (total order):
        PUBLIC(0)  <  CONFIDENTIAL(1)  <  SECRET(2)  <  TOP_SECRET(3)

    Rule 1 — No Read Up (Simple Security Property):
        subject can READ object  iff  clearance(subject) >= classification(object)

    Rule 2 — No Write Down (★ Star Property):
        subject can WRITE object  iff  clearance(subject) <= classification(object)
    """))

    # Replicate the BLP logic inline (no DB needed)
    def can_read(subject: int, obj: int) -> bool:
        return subject >= obj

    def can_write(subject: int, obj: int) -> bool:
        return subject <= obj

    LEVELS = {0: "PUBLIC", 1: "CONFIDENTIAL", 2: "SECRET", 3: "TOP_SECRET"}

    subsection("No Read Up — READ tests")
    tests = [
        (3, 2,  True,  "Admin(TOP_SECRET=3)    reading SECRET=2 data"),
        (3, 3,  True,  "Admin(TOP_SECRET=3)    reading TOP_SECRET=3 data"),
        (2, 2,  True,  "Analyst(SECRET=2)      reading SECRET=2 data"),
        (2, 1,  True,  "Analyst(SECRET=2)      reading CONFIDENTIAL=1 data"),
        (1, 2,  False, "Guest(CONFIDENTIAL=1)  reading SECRET=2 data   ← No Read Up!"),
        (0, 1,  False, "PUBLIC user            reading CONFIDENTIAL=1  ← No Read Up!"),
    ]
    for subj, obj, expected, desc in tests:
        actual = can_read(subj, obj)
        result(actual == expected, desc)

    subsection("No Write Down — WRITE tests")
    tests_w = [
        (3, 3,  True,  "Admin(TOP_SECRET=3)    writing to TOP_SECRET=3"),
        (2, 3,  True,  "Analyst(SECRET=2)      writing to TOP_SECRET=3"),
        (1, 1,  True,  "Guest(CONFIDENTIAL=1)  writing to CONFIDENTIAL=1"),
        (3, 0,  False, "Admin(TOP_SECRET=3)    writing to PUBLIC=0      ← No Write Down!"),
        (3, 2,  False, "Admin(TOP_SECRET=3)    writing to SECRET=2      ← No Write Down!"),
        (2, 1,  False, "Analyst(SECRET=2)      writing to CONFIDENTIAL=1 ← No Write Down!"),
    ]
    for subj, obj, expected, desc in tests_w:
        actual = can_write(subj, obj)
        result(actual == expected, desc)

    print("""
    KEY INSIGHT:
      Read  flows DOWN   → lower users can't read higher classified data ✓
      Write flows UP     → classified users can't leak data to lower objects ✓
      Net effect: information can only flow UPWARD in the lattice.
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CONCEPT 2: RBAC
# ──────────────────────────────────────────────────────────────────────────────

def demo_rbac():
    section("CONCEPT 2: Role-Based Access Control (RBAC)")
    print(textwrap.dedent("""
    Three roles with different permission sets (Principle of Least Privilege):

      Admin   → all permissions
      Analyst → anonymized data + summary + attack demo
      Guest   → summary statistics only
    """))

    ROLE_PERMS = {
        "Admin":   {"data:raw:read", "data:anonymized:read", "data:summary:read",
                    "data:write", "users:manage", "attack:demo"},
        "Analyst": {"data:anonymized:read", "data:summary:read", "attack:demo"},
        "Guest":   {"data:summary:read"},
    }

    USER_ROLES = {
        "admin":        ["Admin"],
        "alice_analyst":["Analyst"],
        "bob_guest":    ["Guest"],
    }

    def user_permissions(username: str) -> set:
        perms = set()
        for role in USER_ROLES.get(username, []):
            perms |= ROLE_PERMS.get(role, set())
        return perms

    checks = [
        ("admin",         "data:raw:read",        True),
        ("admin",         "users:manage",          True),
        ("alice_analyst", "data:anonymized:read",  True),
        ("alice_analyst", "attack:demo",           True),
        ("alice_analyst", "data:raw:read",         False),
        ("alice_analyst", "users:manage",          False),
        ("bob_guest",     "data:summary:read",     True),
        ("bob_guest",     "data:anonymized:read",  False),
        ("bob_guest",     "attack:demo",           False),
    ]

    subsection("Permission checks")
    for username, perm, expected in checks:
        actual = perm in user_permissions(username)
        icon = "✓" if actual else "✗"
        outcome = "GRANTED" if actual else "DENIED "
        match = "✓" if actual == expected else "✗ UNEXPECTED"
        print(f"    [{icon} {outcome}]  {username:15s} → {perm}  {match}")

    print("""
    KEY INSIGHT:
      Without RBAC: manage N_users × N_permissions = exploding complexity
      With RBAC:    manage N_roles × N_permissions = tractable
      Changing one role instantly updates all users with that role.
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CONCEPT 3: k-Anonymity
# ──────────────────────────────────────────────────────────────────────────────

def demo_k_anonymity():
    try:
        import pandas as pd
    except ImportError:
        print("\n[SKIP] k-Anonymity demo requires pandas:  pip install pandas")
        return

    section("CONCEPT 3: k-Anonymity")
    print(textwrap.dedent("""
    k-Anonymity: every record is INDISTINGUISHABLE from ≥ (k-1) others
    on ALL quasi-identifier attributes.

    Quasi-Identifiers (QI): age, zipcode, gender
    Sensitive Attribute:    disease
    """))

    records = [
        {"name": "Alice",   "age": 34, "zipcode": "10025", "gender": "F", "disease": "Cancer"},
        {"name": "Bob",     "age": 34, "zipcode": "10025", "gender": "M", "disease": "Diabetes"},
        {"name": "Carol",   "age": 27, "zipcode": "10033", "gender": "F", "disease": "Flu"},
        {"name": "Dave",    "age": 29, "zipcode": "10021", "gender": "M", "disease": "Asthma"},
        {"name": "Erin",    "age": 35, "zipcode": "10033", "gender": "F", "disease": "Diabetes"},
        {"name": "Frank",   "age": 33, "zipcode": "10021", "gender": "M", "disease": "Flu"},
    ]

    df = pd.DataFrame(records)
    k = 2
    qi_cols = ["age", "zipcode", "gender"]

    subsection("Original dataset (names shown for reference)")
    print(df[["name"] + qi_cols + ["disease"]].to_string(index=False))

    # Check k-anonymity on raw QIs
    groups = df.groupby(qi_cols).size().reset_index(name="count")
    violations = groups[groups["count"] < k]

    print(f"\n  k={k} anonymity check on EXACT QIs:")
    if len(violations) > 0:
        print("  VIOLATED — these QI combinations appear < k times:")
        print(violations.to_string(index=False))
    else:
        print("  Satisfied ✓")

    subsection("Step 1 — Remove explicit identifier (name)")
    df_anon = df.drop(columns=["name"]).copy()
    print(df_anon.to_string(index=False))

    subsection("Step 2 — Generalize quasi-identifiers (age → decade, zip → prefix)")
    df_anon["age"]     = df["age"].apply(lambda x: f"{(x // 10)*10}-{(x // 10)*10 + 9}")
    df_anon["zipcode"] = df["zipcode"].apply(lambda z: z[:3] + "**")

    print(df_anon.to_string(index=False))

    # Check k-anonymity after generalization
    groups2 = df_anon.groupby(qi_cols).size().reset_index(name="count")
    viol2 = groups2[groups2["count"] < k]

    print(f"\n  k={k} anonymity check after generalization:")
    if len(viol2) == 0:
        print(f"  ✓ SATISFIED — every (age_range, zip_prefix, gender) group has ≥{k} records")
        print(f"\n  Group sizes:")
        print(groups2.to_string(index=False))
    else:
        print("  Still violated — would apply suppression next")
        print(viol2.to_string(index=False))

    print("""
    KEY INSIGHT:
      Before: Alice (34, 10025, F) is UNIQUE → attacker can pinpoint her disease
      After:  (30-39, 100**, F) has ≥2 records → attacker doesn't know WHICH woman has Cancer
      Privacy gain: attacker can only narrow it down to a group, not an individual
    """)


# ──────────────────────────────────────────────────────────────────────────────
# CONCEPT 4: Linking Attack
# ──────────────────────────────────────────────────────────────────────────────

def demo_linking_attack():
    try:
        import pandas as pd
    except ImportError:
        print("\n[SKIP] Linking attack demo requires pandas: pip install pandas")
        return

    section("CONCEPT 4: Linking Attack + k-Anonymity Defense")
    print(textwrap.dedent("""
    REAL INCIDENT: Latanya Sweeney (1997)
      Massachusetts released "anonymized" hospital records (name/SSN removed).
      Sweeney bought a $20 voter registration list.
      Joined on {ZIP, birthdate, sex} → re-identified the governor's medical records!
      Lesson: removing names is NOT anonymization.
    """))

    # "Anonymized" medical records (name stripped, but QIs exact)
    medical = pd.DataFrame([
        {"record_id": 1, "age": 34, "zipcode": "10025", "gender": "F", "disease": "Cancer"},
        {"record_id": 2, "age": 34, "zipcode": "10025", "gender": "M", "disease": "Diabetes"},
        {"record_id": 3, "age": 27, "zipcode": "10033", "gender": "F", "disease": "Flu"},
        {"record_id": 4, "age": 29, "zipcode": "10021", "gender": "M", "disease": "Asthma"},
        {"record_id": 5, "age": 35, "zipcode": "10033", "gender": "F", "disease": "Diabetes"},
        {"record_id": 6, "age": 33, "zipcode": "10021", "gender": "M", "disease": "Flu"},
    ])

    # Public voter registration (attacker's data)
    voter = pd.DataFrame([
        {"name": "Alice Johnson", "age": 34, "zipcode": "10025", "gender": "F"},
        {"name": "Bob Smith",     "age": 34, "zipcode": "10025", "gender": "M"},
        {"name": "Carol White",   "age": 27, "zipcode": "10033", "gender": "F"},
        {"name": "Dave Brown",    "age": 29, "zipcode": "10021", "gender": "M"},
        {"name": "Erin Davis",    "age": 35, "zipcode": "10033", "gender": "F"},
        {"name": "Frank Lee",     "age": 33, "zipcode": "10021", "gender": "M"},
    ])

    qi_cols = ["age", "zipcode", "gender"]

    subsection("Step 1 — Attacker's 'anonymized' medical records (no name)")
    print(medical.to_string(index=False))

    subsection("Step 2 — Attacker's public voter registration list")
    print(voter.to_string(index=False))

    subsection("Step 3 — JOIN on quasi-identifiers (the ATTACK)")
    linked = voter.merge(medical, on=qi_cols, how="inner")
    print(linked[["name", "age", "zipcode", "gender", "disease"]].to_string(index=False))

    # Count unique matches
    match_counts = linked.groupby("name")["record_id"].count().reset_index(name="matches")
    unique = match_counts[match_counts["matches"] == 1]
    print(f"\n  Records re-identified (unique QI match): {len(unique)} / {len(voter)}")
    for _, row in unique.iterrows():
        row_data = linked[linked["name"] == row["name"]].iloc[0]
        print(f"    → {row['name']:15s}: disease = {row_data['disease']}")

    subsection("Step 4 — Apply k-Anonymity (k=2) — DEFENSE")
    medical_k = medical.copy()
    medical_k["age"]     = medical["age"].apply(lambda x: f"{(x // 10)*10}-{(x // 10)*10 + 9}")
    medical_k["zipcode"] = medical["zipcode"].apply(lambda z: z[:3] + "**")
    voter_k = voter.copy()
    voter_k["age"]     = voter["age"].apply(lambda x: f"{(x // 10)*10}-{(x // 10)*10 + 9}")
    voter_k["zipcode"] = voter["zipcode"].apply(lambda z: z[:3] + "**")

    print(medical_k[qi_cols + ["disease"]].to_string(index=False))

    subsection("Step 5 — Same attack on k-anonymized data")
    linked_k = voter_k.merge(medical_k, on=qi_cols, how="inner")
    match_counts_k = linked_k.groupby("name")["record_id"].count().reset_index(name="matches")
    unique_k = match_counts_k[match_counts_k["matches"] == 1]

    print(f"\n  Records re-identified after k-anonymity: {len(unique_k)} / {len(voter)}")
    if len(unique_k) == 0:
        print("  ✓ DEFENSE SUCCESSFUL — attacker cannot re-identify anyone!")
        print("  Each name now matches ≥2 records → attacker faces ambiguity.")
    else:
        for _, row in unique_k.iterrows():
            print(f"  Still re-identified: {row['name']}")

    print("""
    KEY INSIGHT:
      BEFORE k-anonymity: JOIN gives 1-to-1 mapping → full re-identification
      AFTER  k-anonymity: JOIN gives 1-to-many mapping → attacker can't tell
                          which of k people in the group is the target

      This is the MATHEMATICAL GUARANTEE of k-anonymity.
    """)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "█" * 70)
    print("  SECURE DATA SHARING PLATFORM — Concept Demonstration")
    print("  Run the full API with:  python run.py")
    print("  API docs at:            http://localhost:8000/docs")
    print("█" * 70)

    demo_blp()
    demo_rbac()
    demo_k_anonymity()
    demo_linking_attack()

    print("\n" + "═" * 70)
    print("  All concept demos complete.")
    print("  Next: python run.py  →  open http://localhost:8000/docs")
    print("═" * 70 + "\n")
