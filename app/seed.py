"""
app/seed.py — Initial database population

Creates:
  1. Permissions  (fine-grained operation rights)
  2. Roles        (Admin, Analyst, Guest, SeniorAnalyst, DataCurator)
  3. Users        (one per role demo scenario)
  4. Patient records  (22 synthetic records for k-anonymity and linking attack demos)

FULLY IDEMPOTENT — each entity is upserted by its unique name/username.
Safe to call on every startup; adding new roles/users here will just insert
the missing rows without touching existing data.

Demo users and what they prove
================================
  admin          / admin123    TOP_SECRET  Admin        — can read everything; CANNOT write (BLP No-Write-Down)
  alice_analyst  / analyst123  SECRET      Analyst      — RBAC allows anonymized; blocked from raw
  bob_guest      / guest123    CONFIDENTIAL Guest       — summary only
  mallory        / mallory123  CONFIDENTIAL SeniorAnalyst — RBAC grants data:raw:read BUT BLP blocks (1 < 2)
  curator        / curator123  SECRET      DataCurator  — data:write + SECRET clearance -> only one who CAN write
"""
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.user import User, Role, Permission, SecurityLevel
from app.models.data import PatientRecord
from app.auth.hashing import hash_password


# ─── 1. Permissions ───────────────────────────────────────────────────────────

PERMISSIONS = [
    {
        "name": "data:raw:read",
        "resource": "data",
        "action": "raw:read",
        "description": "Read unanonymized, raw patient records (highly sensitive)",
    },
    {
        "name": "data:anonymized:read",
        "resource": "data",
        "action": "anonymized:read",
        "description": "Read k-anonymized patient records",
    },
    {
        "name": "data:summary:read",
        "resource": "data",
        "action": "summary:read",
        "description": "Read aggregate statistics only (no individual records)",
    },
    {
        "name": "data:write",
        "resource": "data",
        "action": "write",
        "description": "Create or modify patient records (POST /data/records)",
    },
    {
        "name": "users:manage",
        "resource": "users",
        "action": "manage",
        "description": "List and manage users (GET /admin/users)",
    },
    {
        "name": "attack:demo",
        "resource": "attack",
        "action": "demo",
        "description": "Run the linking attack demonstration",
    },
]


# ─── 2. Role → Permission mappings ────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "Admin": [
        "data:raw:read",
        "data:anonymized:read",
        "data:summary:read",
        "data:write",       # RBAC passes but BLP No-Write-Down will block (TOP_SECRET > SECRET)
        "users:manage",
        "attack:demo",
    ],
    "Analyst": [
        "data:anonymized:read",
        "data:summary:read",
        "attack:demo",
    ],
    "Guest": [
        "data:summary:read",
    ],
    # NEW: SeniorAnalyst has raw-read permission but only CONFIDENTIAL clearance
    # → RBAC passes, BLP No-Read-Up blocks (CONFIDENTIAL=1 < SECRET=2)
    # This is the scenario where RBAC and BLP give different answers.
    "SeniorAnalyst": [
        "data:raw:read",
        "data:anonymized:read",
        "data:summary:read",
        "attack:demo",
    ],
    # NEW: DataCurator can write patient records and has SECRET clearance
    # → RBAC passes (data:write), BLP passes (SECRET=2 <= SECRET=2) → 201 Created
    # Admin has data:write too but TOP_SECRET=3 > SECRET=2 → BLP blocks Admin
    "DataCurator": [
        "data:write",
        "data:summary:read",
    ],
}


# ─── 3. Users ─────────────────────────────────────────────────────────────────

USERS = [
    {
        "username":       "admin",
        "email":          "admin@example.com",
        "password":       "admin123",
        "security_level": SecurityLevel.TOP_SECRET,    # 3
        "roles":          ["Admin"],
    },
    {
        "username":       "alice_analyst",
        "email":          "alice@example.com",
        "password":       "analyst123",
        "security_level": SecurityLevel.SECRET,         # 2
        "roles":          ["Analyst"],
    },
    {
        "username":       "bob_guest",
        "email":          "bob@example.com",
        "password":       "guest123",
        "security_level": SecurityLevel.CONFIDENTIAL,   # 1
        "roles":          ["Guest"],
    },
    {
        # BLP No-Read-Up demo: RBAC says OK, BLP says NO
        "username":       "mallory",
        "email":          "mallory@example.com",
        "password":       "mallory123",
        "security_level": SecurityLevel.CONFIDENTIAL,   # 1 — below SECRET(2) data
        "roles":          ["SeniorAnalyst"],
    },
    {
        # BLP No-Write-Down demo: only user who CAN write SECRET records
        "username":       "curator",
        "email":          "curator@example.com",
        "password":       "curator123",
        "security_level": SecurityLevel.SECRET,         # 2 — exactly matches SECRET(2) data
        "roles":          ["DataCurator"],
    },
]


# ─── 4. Synthetic Patient Dataset ─────────────────────────────────────────────

PATIENT_RECORDS = [
    # ── 20s, zipcodes 100xx ───────────────────────────────────────────────────
    {"name": "Alice Johnson",   "age": 23, "zipcode": "10025", "gender": "F", "disease": "Flu",          "salary": 52000.0},
    {"name": "Carol Williams",  "age": 27, "zipcode": "10033", "gender": "F", "disease": "Hypertension", "salary": 58000.0},
    {"name": "Diana Prince",    "age": 29, "zipcode": "10021", "gender": "F", "disease": "Flu",          "salary": 49500.0},
    {"name": "Ethan Hunt",      "age": 25, "zipcode": "10025", "gender": "M", "disease": "Asthma",       "salary": 61000.0},

    # ── 30s, zipcodes 100xx ───────────────────────────────────────────────────
    {"name": "Bob Smith",       "age": 34, "zipcode": "10025", "gender": "M", "disease": "Diabetes",    "salary": 75000.0},
    {"name": "Edward Norton",   "age": 37, "zipcode": "10033", "gender": "M", "disease": "Asthma",      "salary": 82000.0},
    {"name": "Fiona Green",     "age": 31, "zipcode": "10021", "gender": "F", "disease": "Cancer",      "salary": 90000.0},
    {"name": "Grace Kelly",     "age": 38, "zipcode": "10025", "gender": "F", "disease": "Diabetes",    "salary": 67000.0},

    # ── 40s, zipcodes 200xx ───────────────────────────────────────────────────
    {"name": "Henry Ford",      "age": 44, "zipcode": "20001", "gender": "M", "disease": "Heart Disease","salary": 110000.0},
    {"name": "Ivan Drago",      "age": 47, "zipcode": "20002", "gender": "M", "disease": "Hypertension","salary":  95000.0},
    {"name": "James Bond",      "age": 42, "zipcode": "20001", "gender": "M", "disease": "Flu",         "salary": 105000.0},
    {"name": "Karen Page",      "age": 45, "zipcode": "20002", "gender": "F", "disease": "Asthma",      "salary":  88000.0},
    {"name": "Laura Palmer",    "age": 48, "zipcode": "20001", "gender": "F", "disease": "Cancer",      "salary":  72000.0},

    # ── 50s, zipcodes 303xx ───────────────────────────────────────────────────
    {"name": "Michael Scott",   "age": 53, "zipcode": "30301", "gender": "M", "disease": "Diabetes",   "salary": 120000.0},
    {"name": "Nancy Drew",      "age": 56, "zipcode": "30302", "gender": "F", "disease": "Flu",         "salary":  65000.0},
    {"name": "Oscar Martinez",  "age": 51, "zipcode": "30301", "gender": "M", "disease": "Hypertension","salary":  98000.0},
    {"name": "Pam Beesly",      "age": 58, "zipcode": "30302", "gender": "F", "disease": "Asthma",      "salary":  71000.0},

    # ── 60s, zipcodes 400xx ───────────────────────────────────────────────────
    {"name": "Patricia Smith",  "age": 62, "zipcode": "40001", "gender": "F", "disease": "Heart Disease","salary":  85000.0},
    {"name": "Quinn Hughes",    "age": 67, "zipcode": "40001", "gender": "M", "disease": "Cancer",      "salary":  78000.0},
    {"name": "Rachel Green",    "age": 64, "zipcode": "40002", "gender": "F", "disease": "Diabetes",    "salary":  91000.0},
    {"name": "Steve Rogers",    "age": 68, "zipcode": "40002", "gender": "M", "disease": "Hypertension","salary":  92000.0},
    {"name": "Tina Turner",     "age": 61, "zipcode": "40001", "gender": "F", "disease": "Asthma",      "salary":  76000.0},
]


# ─── Idempotent helpers ───────────────────────────────────────────────────────

def _ensure_permissions(db: Session) -> dict[str, Permission]:
    """Upsert every permission by name. Returns {name: Permission}."""
    perm_map: dict[str, Permission] = {}
    for p in PERMISSIONS:
        perm = db.query(Permission).filter(Permission.name == p["name"]).first()
        if perm is None:
            perm = Permission(**p)
            db.add(perm)
            db.flush()
        perm_map[perm.name] = perm
    return perm_map


def _ensure_roles(db: Session, perm_map: dict[str, Permission]) -> dict[str, Role]:
    """Upsert every role by name and sync its permissions. Returns {name: Role}."""
    role_map: dict[str, Role] = {}
    for role_name, perm_names in ROLE_PERMISSIONS.items():
        role = db.query(Role).filter(Role.name == role_name).first()
        if role is None:
            role = Role(name=role_name, description=f"{role_name} — system role")
            db.add(role)
            db.flush()
        # Sync permissions (idempotent — sets the full list each time)
        role.permissions = [perm_map[pn] for pn in perm_names]
        role_map[role_name] = role
    return role_map


def _ensure_users(db: Session, role_map: dict[str, Role]) -> int:
    """Insert missing users. Returns count of newly created users."""
    created = 0
    for u in USERS:
        existing = db.query(User).filter(User.username == u["username"]).first()
        if existing is None:
            user = User(
                username=u["username"],
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                security_level=u["security_level"],
            )
            user.roles = [role_map[rn] for rn in u["roles"]]
            db.add(user)
            created += 1
    return created


def _ensure_records(db: Session) -> int:
    """Insert patient records only if the table is empty. Returns count inserted."""
    if db.query(PatientRecord).first() is not None:
        return 0
    for rec in PATIENT_RECORDS:
        db.add(PatientRecord(
            name=rec["name"],
            age=rec["age"],
            zipcode=rec["zipcode"],
            gender=rec["gender"],
            disease=rec["disease"],
            salary=rec["salary"],
            classification_level=SecurityLevel.SECRET,
        ))
    return len(PATIENT_RECORDS)


# ─── Public entry point ───────────────────────────────────────────────────────

def seed_database() -> None:
    """
    Populate the database with initial data (fully idempotent).
    Each helper upserts by unique key so re-running never duplicates data.
    New roles/users added to the lists above will be inserted on next startup.
    """
    db: Session = SessionLocal()
    try:
        perm_map  = _ensure_permissions(db)
        role_map  = _ensure_roles(db, perm_map)
        new_users = _ensure_users(db, role_map)
        new_recs  = _ensure_records(db)
        db.commit()

        if new_users or new_recs:
            # ASCII safe print — no unicode checkmarks (fixes Windows UTF-8 crash)
            print(
                f"[Seed] OK — {new_users} user(s) | "
                f"{new_recs} patient record(s) | "
                f"{len(perm_map)} permission(s) ensured."
            )
        else:
            print("[Seed] OK — database already fully seeded, nothing to do.")

    except Exception as exc:
        db.rollback()
        print(f"[Seed] ERROR during seeding: {exc}")
        raise
    finally:
        db.close()
