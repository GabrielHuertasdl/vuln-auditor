"""
Distributed worker logic — uses arq for persistent task management.

This module replaces FastAPI's BackgroundTasks with a persistent queue
backed by Redis. Benefits:
  - Scans are not lost if the API server restarts.
  - Workers can be scaled independently across multiple containers.
  - Job status and results can be tracked reliably.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings
from arq.worker import Retry

from core.config import settings
from core.storage import ScanStore

log = logging.getLogger(__name__)

MAX_RETRIES = 3
# Delay in seconds before retry 2 and retry 3 (job_try 1→2 uses index 0, 2→3 uses index 1)
_RETRY_DELAYS = [30, 60]


async def _store_failed_job(scan_id: str, error: str, attempt_count: int) -> None:
    """Persist a permanently-failed job to the DB dead-letter table."""
    from db.database import get_session
    from db.models import FailedJob

    try:
        async with get_session() as session:
            record = FailedJob(
                id=str(uuid.uuid4()),
                function="run_scan_task",
                scan_id=scan_id,
                error=error[:4000],
                kwargs_json=None,
                attempt_count=attempt_count,
                failed_at=datetime.now(UTC),
            )
            session.add(record)
    except Exception:
        log.exception("Could not write failed-job record for scan_id=%s", scan_id)


async def run_scan_task(
    ctx: dict[str, Any],
    scan_id: str,
    target_url: str,
    tools: list[Any],
    scan_mode: str,
    org_id: str,
    target_id: str,
    repo_url: str | None = None,
) -> None:
    """Task executed by the worker. Imports run_scan here to avoid circular imports."""
    from api.routes import run_scan

    job_try: int = ctx.get("job_try", 1)
    log.info("Starting scan task scan_id=%s (attempt %d/%d)", scan_id, job_try, MAX_RETRIES)
    store = ScanStore(settings.data_dir)

    try:
        await run_scan(
            scan_id=scan_id,
            target=target_url,
            tools=tools,
            store=store,
            scan_mode=scan_mode,
            org_id=org_id,
            target_id=target_id,
            repo_url=repo_url,
        )
        log.info("Scan task completed successfully for scan_id=%s", scan_id)
    except Exception as e:
        if job_try < MAX_RETRIES:
            delay = _RETRY_DELAYS[job_try - 1]
            log.warning(
                "Scan %s failed (attempt %d/%d) — retrying in %ds: %s",
                scan_id, job_try, MAX_RETRIES, delay, e,
            )
            raise Retry(defer=delay)
        else:
            log.exception("Scan %s permanently failed after %d attempts: %s", scan_id, job_try, e)
            await _store_failed_job(scan_id, str(e), job_try)
            raise


def _redis_settings_from_url(url: str) -> RedisSettings:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        password=parsed.password or None,
    )


async def get_redis_pool():
    """Returns a connection pool for the task queue."""
    return await create_pool(_redis_settings_from_url(settings.redis_url))


class WorkerSettings:
    """Settings for the arq worker."""
    functions = [run_scan_task]
    redis_settings = _redis_settings_from_url(settings.redis_url)
    max_tries = MAX_RETRIES
    job_timeout = settings.scan_timeout_seconds
    on_startup = None
    on_shutdown = None
