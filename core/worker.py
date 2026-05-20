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
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings

from core.config import settings
from core.storage import ScanStore

log = logging.getLogger(__name__)

async def run_scan_task(ctx: dict[str, Any], scan_id: str, target_url: str, tools: list[Any], scan_mode: str, org_id: str, target_id: str) -> None:
    """
    Task executed by the worker. Imports run_scan here to avoid circular imports.
    """
    from api.routes import run_scan
    
    log.info("Starting background scan task for scan_id=%s", scan_id)
    store = ScanStore(settings.data_dir)
    
    try:
        await run_scan(
            scan_id=scan_id,
            target=target_url,
            tools=tools,
            store=store,
            scan_mode=scan_mode,
            org_id=org_id,
            target_id=target_id
        )
        log.info("Scan task completed successfully for scan_id=%s", scan_id)
    except Exception as e:
        log.exception("Scan task failed for scan_id=%s: %s", scan_id, e)

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
    on_startup = None
    on_shutdown = None
