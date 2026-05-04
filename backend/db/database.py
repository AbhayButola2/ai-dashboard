"""
db/database.py
--------------
SQLAlchemy engine + session factory for SQLite.
Keeps JSON export as backup for backward compatibility.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

ROOT = os.path.dirname(os.path.dirname(__file__))  # backend/
DB_PATH = os.path.join(ROOT, "threats.db")

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables (called once at startup)."""
    from db.models import LogEntry  # noqa: F401 — registers model
    Base.metadata.create_all(bind=engine)
