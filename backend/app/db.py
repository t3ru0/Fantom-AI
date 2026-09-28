"""Database engine and session.

The engine is created lazily and never at import time, so the app boots on a
machine with no Postgres running. Callers that need a session get a clear error;
/health reports the database as unreachable instead of the process dying.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import settings

log = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,        # a dropped connection reconnects instead of erroring mid-run
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_pool_size * 2,
            echo=settings.db_echo,
            future=True,
            # A health check that hangs is worse than one that fails. Cap the TCP
            # connect so /health answers in bounded time on a machine with no DB.
            connect_args={"connect_timeout": settings.db_connect_timeout},
        )
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(), autoflush=False, expire_on_commit=False, future=True
        )
    return _SessionLocal


def get_db() -> Iterator[Session]:
    """FastAPI dependency. One session per request, always closed."""
    db = get_sessionmaker()()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """For workers and scripts. Commits on success, rolls back on failure."""
    db = get_sessionmaker()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ping() -> tuple[bool, str | None]:
    """Cheap liveness probe used by /health. Never raises."""
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:  # noqa: BLE001 — health must report, not crash
        return False, f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"


def migration_revision() -> str | None:
    """Current alembic revision in the database, or None if not migrated."""
    try:
        with get_engine().connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
            return row[0] if row else None
    except Exception:
        return None
