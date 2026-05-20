"""
Async database engine and session management.

Refactored for Enterprise:
  - Robust connection pooling for PostgreSQL.
  - Safe initialization for multi-worker environments.
  - Transparent support for both SQLite (local dev) and Postgres (production).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.config import settings
from db.models import Base

log = logging.getLogger(__name__)

# Enterprise-grade engine configuration
def create_engine_for_url(db_url: str):
    is_sqlite = "sqlite" in db_url
    
    connect_args = {}
    if is_sqlite:
        connect_args["check_same_thread"] = False
        # Extract file path and create parent dirs if needed
        if "///" in db_url and ":memory:" not in db_url:
            file_part = db_url.split("///", 1)[1]
            Path(file_part).parent.mkdir(parents=True, exist_ok=True)
            
    kwargs = {
        "echo": False,
        "connect_args": connect_args,
        "pool_pre_ping": True,
    }
    
    if not is_sqlite:
        kwargs["pool_size"] = 20
        kwargs["max_overflow"] = 10
        kwargs["pool_timeout"] = 30
        
    return create_async_engine(db_url, **kwargs)

# Singleton instances
_engine = create_engine_for_url(settings.database_url)
_session_factory = async_sessionmaker(
    _engine, class_=AsyncSession, expire_on_commit=False
)

@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a database session with auto-commit/rollback."""
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

async def init_db() -> None:
    """Initialize database schema. Enables WAL for SQLite."""
    async with _engine.begin() as conn:
        if "sqlite" in settings.database_url:
            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(Base.metadata.create_all)
    log.info("Database initialized (engine: %s)", _engine.url.drivername)

async def reset_db_for_testing(database_url: str) -> None:
    """DANGEROUS: Drop and recreate all tables. Used exclusively for tests."""
    global _engine, _session_factory
    
    # Dispose old engine if it exists
    if _engine:
        await _engine.dispose()
        
    _engine = create_engine_for_url(database_url)
    _session_factory = async_sessionmaker(
        _engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
