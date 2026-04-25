"""
app/database.py — SQLAlchemy database setup

SQLAlchemy is an ORM (Object-Relational Mapper):
  - Define Python classes → they become SQL tables
  - Query with Python → it generates SQL for you
  - Protects against SQL injection automatically

Components:
  engine       — manages connections to the actual SQLite file
  SessionLocal — factory that creates database sessions (transactions)
  Base         — ALL models inherit from this; it tracks all tables
  get_db()     — FastAPI dependency that opens/closes a session per request
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.config import settings


# check_same_thread=False is SQLite-specific; allows use across FastAPI threads
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# Each request gets its own isolated session (autocommit=False → explicit commits)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """All ORM models inherit from this single Base."""
    pass


def get_db():
    """
    FastAPI dependency — yields a DB session and guarantees cleanup.

    Usage in a route:
        def my_route(db: Session = Depends(get_db)):
            db.query(...)

    The 'try/finally' ensures the session is closed even if an exception occurs,
    preventing connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
