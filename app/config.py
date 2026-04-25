"""
app/config.py — Centralised application settings

Why a settings class?
  - All config in ONE place instead of scattered os.getenv() calls
  - Pydantic validates types automatically (int stays int, etc.)
  - Values can come from environment variables OR a .env file
  - Easy to swap out in tests by overriding the settings object

Security note: SECRET_KEY must be long, random, and secret.
  Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # JWT signing key — REQUIRED in .env; no hardcoded fallback here.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY: str

    # JWT algorithm (HMAC-SHA256 — symmetric, fast, good for API tokens)
    ALGORITHM: str = "HS256"

    # How long a token stays valid
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # SQLite: file-based SQL database, no server needed — perfect for a demo
    DATABASE_URL: str = "sqlite:///./secure_data.db"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


# Single global instance — import this everywhere
settings = Settings()
