# Secure Data Sharing Platform

A demonstration system implementing four foundational security and privacy concepts
from the ground up: **JWT Authentication**, **RBAC**, **Bell-LaPadula Policy**, and **k-Anonymity**.

---

## Architecture

```
HTTP Request
     │
     ▼
┌─────────────────┐
│  JWT Auth Layer │  Verifies the Bearer token, loads user from DB
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   RBAC Engine   │  Does this user's ROLE have the required PERMISSION?
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  BLP Enforcer   │  Is the user's CLEARANCE >= data CLASSIFICATION?
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Privacy Module  │  Apply k-anonymity before releasing individual records
└────────┬────────┘
         │
         ▼
     Response
```

---

## Project Structure

```
secure-data-sharing-system/
├── app/
│   ├── main.py               # FastAPI app, startup, router registration
│   ├── config.py             # Settings (SECRET_KEY, DB URL, token expiry)
│   ├── database.py           # SQLAlchemy engine, session factory, Base
│   ├── seed.py               # Initial data: users, roles, permissions, patients
│   ├── models/
│   │   ├── user.py           # User, Role, Permission ORM models + SecurityLevel enum
│   │   └── data.py           # PatientRecord ORM model
│   ├── auth/
│   │   ├── hashing.py        # bcrypt password hashing
│   │   └── jwt_handler.py    # JWT creation + verification dependency
│   ├── rbac/
│   │   └── engine.py         # require_permission() FastAPI dependency
│   ├── policy/
│   │   └── bell_lapadula.py  # BLP check_read() / check_write() enforcement
│   ├── privacy/
│   │   ├── kanonymity.py     # k-anonymity algorithm (generalize + suppress)
│   │   └── attack.py         # Linking attack simulation
│   └── api/
│       ├── auth.py           # POST /auth/login, GET /auth/me
│       ├── data.py           # GET /data/raw, /data/anonymized, /data/summary
│       └── attack.py         # GET /attack/linking-demo
├── demo_concepts.py          # Standalone terminal demo (no server needed)
├── run.py                    # Starts uvicorn dev server
├── requirements.txt
└── .env.example
```

---

## Quick Start

```bash
# 1. Create a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the standalone concept demo (no server needed)
python demo_concepts.py

# 4. Start the API server
python run.py
# → Open http://localhost:8000/docs
```

---

## API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login` | Login → returns JWT Bearer token |
| `GET`  | `/auth/me`    | Current user info + permissions |

### Data Access (protected)

| Method | Path | Who | Security |
|--------|------|-----|----------|
| `GET` | `/data/raw`        | Admin only   | RBAC + BLP(SECRET) |
| `GET` | `/data/anonymized` | Analyst+     | RBAC + BLP(CONFIDENTIAL) + k-anonymity |
| `GET` | `/data/summary`    | Guest+       | RBAC (aggregate stats only) |

### Attack Simulation

| Method | Path | Who | Description |
|--------|------|-----|-------------|
| `GET` | `/attack/linking-demo` | Analyst+ | Full attack + defense walkthrough |

---

## Test Credentials

| Username | Password | Role | Clearance |
|---|---|---|---|
| `admin` | `admin123` | Admin | TOP_SECRET (3) |
| `alice_analyst` | `analyst123` | Analyst | SECRET (2) |
| `bob_guest` | `guest123` | Guest | CONFIDENTIAL (1) |

---

## Security Concepts

### 1. Bell-LaPadula Model (BLP)

Developed in 1973 for the US DoD. Enforces **confidentiality** using two rules:

| Rule | Condition | Meaning |
|---|---|---|
| No Read Up | `clearance ≥ classification` | Can't read higher-classified data |
| No Write Down | `clearance ≤ classification` | Can't write to lower-classified objects |

**Result:** Information can only flow upward in the security lattice — never leaks downward.

```
clearance check (read):    Analyst(SECRET=2) reading SECRET=2  →  2 >= 2  ✓ PASS
                           Guest(CONF=1)     reading SECRET=2  →  1 >= 2  ✗ FAIL
```

### 2. Role-Based Access Control (RBAC)

Instead of assigning permissions to individual users, assign them to **roles**:

```
alice  →  [Analyst]  →  {data:anonymized:read, data:summary:read, attack:demo}
bob    →  [Guest]    →  {data:summary:read}
```

**Principle of Least Privilege:** users receive only the permissions they need for their job.

### 3. k-Anonymity

A dataset satisfies **k-anonymity** if every record is indistinguishable from at least **(k-1)** others on all quasi-identifier attributes.

**Quasi-identifiers:** age, zipcode, gender — harmless alone, dangerous when combined.

```
BEFORE (not 2-anonymous):      AFTER generalization (2-anonymous):
Age | ZIP   | Gender            Age   | ZIP  | Gender
34  | 10025 | F  ← UNIQUE       30-39 | 100**| F  ← group size ≥ 2 ✓
34  | 10025 | M                  30-39 | 100**| M
34  | 10025 | M                  30-39 | 100**| M
```

**Techniques:**
- **Generalization:** age 34 → "30-39", ZIP 10025 → "100\*\*"
- **Suppression:** remove records that can't form a group of size ≥ k

### 4. Linking Attack

**Real incident (Sweeney, 1997):** Massachusetts released "anonymized" hospital records (names removed). Sweeney bought a \$20 voter registration list and re-identified 87% of records by joining on `{ZIP, birthdate, sex}`.

```
Voter List:           + Anonymized Medical:    = Re-identified:
Name | Age | ZIP | Sex   Age | ZIP | Sex | Disease   Name | Disease
Alice| 34  | 100 | F  →  34  | 100 | F   | Cancer  → Alice has Cancer!
```

**k-Anonymity defense:** After generalization, the JOIN matches ≥k records per name.
The attacker can no longer pinpoint which individual has which disease.

---

## How the Security Layers Interact

```
Request: alice_analyst → GET /data/raw

① RBAC check:  'data:raw:read' in analyst_permissions? → NO
   → HTTP 403 Forbidden (RBAC denied)

Request: alice_analyst → GET /data/anonymized

① RBAC check:  'data:anonymized:read' in analyst_permissions? → YES
② BLP check:   clearance(SECRET=2) >= classification(CONFIDENTIAL=1)? → YES
③ Privacy:     apply k-anonymity to records before returning
   → HTTP 200 OK (k-anonymized data returned)

Request: bob_guest → GET /data/anonymized

① RBAC check:  'data:anonymized:read' in guest_permissions? → NO
   → HTTP 403 Forbidden (RBAC denied, BLP never even reached)
```
