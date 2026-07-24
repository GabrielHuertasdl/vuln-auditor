"""Tests for core/worker.py — arq retry logic and dead-letter recording."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from arq.worker import Retry

from core.worker import (
    MAX_RETRIES,
    WorkerSettings,
    _store_failed_job,
    run_scan_task,
)


# ── Constants ─────────────────────────────────────────────────────────────────

class TestWorkerConstants:
    def test_max_retries_is_three(self):
        assert MAX_RETRIES == 3

    def test_worker_settings_max_tries(self):
        assert WorkerSettings.max_tries == MAX_RETRIES

    def test_worker_settings_has_run_scan_task(self):
        assert run_scan_task in WorkerSettings.functions


# ── Retry behaviour ───────────────────────────────────────────────────────────

_TASK_KWARGS = dict(
    scan_id="scan-x",
    target_url="https://example.com",
    tools=[],
    scan_mode="full",
    org_id="org-1",
    target_id="target-1",
    repo_url=None,
)


class TestRunScanTaskRetry:
    async def test_raises_retry_on_attempt_1(self):
        ctx = {"job_try": 1}
        with patch("core.worker.ScanStore", MagicMock()):
            with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("transient"))):
                with pytest.raises(Retry):
                    await run_scan_task(ctx, **_TASK_KWARGS)

    async def test_retry_defers_30s_on_attempt_1(self):
        ctx = {"job_try": 1}
        caught: list[Retry] = []
        with patch("core.worker.ScanStore", MagicMock()):
            with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("err"))):
                try:
                    await run_scan_task(ctx, **_TASK_KWARGS)
                except Retry as r:
                    caught.append(r)
        assert len(caught) == 1
        # defer_score stores delay in milliseconds (arq converts seconds → ms)
        assert caught[0].defer_score == 30 * 1000

    async def test_raises_retry_on_attempt_2(self):
        ctx = {"job_try": 2}
        with patch("core.worker.ScanStore", MagicMock()):
            with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("transient"))):
                with pytest.raises(Retry):
                    await run_scan_task(ctx, **_TASK_KWARGS)

    async def test_retry_defers_60s_on_attempt_2(self):
        ctx = {"job_try": 2}
        caught: list[Retry] = []
        with patch("core.worker.ScanStore", MagicMock()):
            with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("err"))):
                try:
                    await run_scan_task(ctx, **_TASK_KWARGS)
                except Retry as r:
                    caught.append(r)
        assert len(caught) == 1
        assert caught[0].defer_score == 60 * 1000

    async def test_does_not_raise_retry_on_attempt_3(self):
        """Attempt 3 = max retries; should re-raise the original exception, not Retry."""
        ctx = {"job_try": 3}
        with patch("core.worker.ScanStore", MagicMock()):
            with patch("core.worker._store_failed_job", AsyncMock()):
                with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("permanent"))):
                    with pytest.raises(RuntimeError, match="permanent"):
                        await run_scan_task(ctx, **_TASK_KWARGS)

    async def test_calls_store_failed_job_on_max_attempt(self):
        ctx = {"job_try": 3}
        recorded: list[tuple] = []

        async def fake_store(scan_id: str, error: str, attempt_count: int) -> None:
            recorded.append((scan_id, error, attempt_count))

        with patch("core.worker.ScanStore", MagicMock()):
            with patch("core.worker._store_failed_job", fake_store):
                with patch("api.routes.run_scan", AsyncMock(side_effect=RuntimeError("dead"))):
                    with pytest.raises(RuntimeError):
                        await run_scan_task(ctx, **_TASK_KWARGS)

        assert len(recorded) == 1
        assert recorded[0][0] == "scan-x"
        assert recorded[0][2] == 3

    async def test_no_exception_no_retry_on_success(self):
        """Successful scan: no Retry raised, no _store_failed_job call."""
        ctx = {"job_try": 1}
        stored: list[str] = []

        async def fake_store(*args, **kwargs) -> None:
            stored.append("called")

        with patch("core.worker.ScanStore", MagicMock()):
            with patch("core.worker._store_failed_job", fake_store):
                with patch("api.routes.run_scan", AsyncMock(return_value=None)):
                    await run_scan_task(ctx, **_TASK_KWARGS)  # must not raise

        assert stored == []


# ── _store_failed_job ─────────────────────────────────────────────────────────

class TestStoreFailedJob:
    async def test_does_not_raise_on_db_error(self):
        """DB write failures must be swallowed — worker must not crash."""
        # get_session is imported at call time inside _store_failed_job, so patch at source
        with patch("db.database.get_session", side_effect=Exception("db down")):
            # Should not raise
            await _store_failed_job("scan-fail", "some error", 3)
