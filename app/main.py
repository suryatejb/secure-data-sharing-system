"""
app/main.py — FastAPI application entry point

Assembles all components:
  • Database table creation
  • Seed data (default users, roles, patient records)
  • CORS middleware
  • API routers (auth, data, attack)

Architecture flow for every request:
  HTTP request
    → JWT middleware (extract + verify token)
    → RBAC check (does this role have the required permission?)
    → BLP check (is clearance >= data classification level?)
    → Privacy filter (k-anonymize if needed)
    → Response

Run with:
  uvicorn app.main:app --reload
  or:
  python run.py

Interactive API docs: http://localhost:8000/docs
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
# Importing these modules registers their ORM classes with Base.metadata
# so create_all() knows about all tables
from app.models import user as _user_models   # noqa: F401
from app.models import data as _data_models   # noqa: F401
from app.api import auth, data, attack
from app.api import admin
from app.seed import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup logic (runs once before serving requests):
      1. Create all DB tables (idempotent — skips existing tables)
      2. Seed initial data (idempotent — skips if already seeded)
    """
    Base.metadata.create_all(bind=engine)
    seed_database()
    yield
    # Shutdown logic (if needed) goes here


app = FastAPI(
    title="Secure Data Sharing Platform",
    description=(
        "## Security Concepts Demonstrated\n\n"
        "| Component | Technology | Concept |\n"
        "|---|---|---|\n"
        "| Authentication | **JWT (HS256)** | Stateless identity |\n"
        "| Access Control | **RBAC** | Roles → Permissions |\n"
        "| Security Policy | **Bell-LaPadula** | No-Read-Up, No-Write-Down |\n"
        "| Privacy | **k-Anonymity** | Generalization + Suppression |\n"
        "| Attack Demo | **Linking Attack** | Re-identification + Defense |\n\n"
        "### Quick Start\n"
        "1. `POST /auth/login` with `admin` / `admin123` → copy the `access_token`\n"
        "2. Click **Authorize** (top right) and paste the token\n"
        "3. Try the data endpoints — observe what changes with different users\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — restricted to trusted local origins.
# In a deployed system, replace these with your actual frontend domains.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Register routers with tag grouping for Swagger UI clarity
app.include_router(auth.router,   prefix="/auth",   tags=["① Authentication (JWT)"])
app.include_router(data.router,   prefix="/data",   tags=["② Data Access  (RBAC + BLP + k-Anonymity)"])
app.include_router(attack.router, prefix="/attack", tags=["③ Attack Simulation (Linking Attack)"])
app.include_router(admin.router,                    tags=["④ Administration  (users:manage)"])

@app.get("/", tags=["Info"], summary="System overview and test credentials")
def root():
    return {
        "system": "Secure Data Sharing Platform",
        "docs_url": "http://localhost:8000/docs",
        "concepts_implemented": [
            "JWT Authentication",
            "RBAC (Role-Based Access Control)",
            "Bell-LaPadula Policy (No-Read-Up + No-Write-Down)",
            "k-Anonymity (Generalization + Suppression)",
            "Linking Attack Simulation",
        ],
        "test_credentials": {
            "admin": {
                "username": "admin",
                "password": "admin123",
                "role": "Admin",
                "clearance": "TOP_SECRET (level 3)",
                "can_access": ["GET /data/raw", "GET /data/anonymized", "GET /data/summary", "GET /attack/linking-demo", "GET /admin/users"],
                "cannot_access": ["POST /data/records  ← BLP No-Write-Down (TOP_SECRET clearance > SECRET classification)"],
            },
            "analyst": {
                "username": "alice_analyst",
                "password": "analyst123",
                "role": "Analyst",
                "clearance": "SECRET (level 2)",
                "can_access": ["GET /data/anonymized", "GET /data/summary", "GET /attack/linking-demo"],
                "cannot_access": ["GET /data/raw  ← RBAC denied (no data:raw:read permission)"],
            },
            "guest": {
                "username": "bob_guest",
                "password": "guest123",
                "role": "Guest",
                "clearance": "CONFIDENTIAL (level 1)",
                "can_access": ["GET /data/summary"],
                "cannot_access": [
                    "GET /data/raw        ← RBAC denied",
                    "GET /data/anonymized ← RBAC denied",
                    "GET /attack/linking-demo ← RBAC denied",
                ],
            },
            "mallory_BLP_READ_DEMO": {
                "username": "mallory",
                "password": "mallory123",
                "role": "SeniorAnalyst",
                "clearance": "CONFIDENTIAL (level 1)",
                "demo": (
                    "GET /data/raw → RBAC passes (has data:raw:read) "
                    "but BLP blocks (clearance CONFIDENTIAL=1 < SECRET=2) → 403 BLP Denied"
                ),
            },
            "curator_BLP_WRITE_DEMO": {
                "username": "curator",
                "password": "curator123",
                "role": "DataCurator",
                "clearance": "SECRET (level 2)",
                "demo": (
                    "POST /data/records → RBAC passes (has data:write) "
                    "and BLP passes (clearance SECRET=2 <= SECRET=2) → 201 Created. "
                    "Admin CANNOT do this (TOP_SECRET=3 > SECRET=2 → BLP write denied)."
                ),
            },
        },
    }
