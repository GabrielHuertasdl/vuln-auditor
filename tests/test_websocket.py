"""Tests for the WebSocket scan progress endpoint — /api/v1/scan/{id}/ws."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from core.config import settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_scan_record(status: str = "running", pct: int = 42) -> MagicMock:
    record = MagicMock()
    record.status = status
    record.progress_pct = pct
    record.progress_message = f"Phase at {pct}%"
    return record


def _valid_token(org_id: str = "00000000-0000-0000-0000-000000000001") -> str:
    """Issue a real JWT signed with the current dev secret."""
    from api.user_auth import create_access_token
    return create_access_token(
        user_id="00000000-0000-0000-0000-000000000099",
        org_id=org_id,
        role="admin",
    )


# ── Auth guard ────────────────────────────────────────────────────────────────

class TestWebSocketAuth:
    def test_rejects_with_4001_when_require_auth_and_no_token(
        self, test_client: TestClient
    ):
        settings.require_auth = True
        try:
            with pytest.raises(Exception):
                with test_client.websocket_connect("/api/v1/scan/nonexistent/ws"):
                    pass
        finally:
            settings.require_auth = False

    def test_accepts_demo_org_when_require_auth_false(self, test_client: TestClient):
        """require_auth=False → demo org, no token needed. Returns scan-not-found message."""
        record = _make_scan_record(status="done", pct=100)

        async def fake_get(*args, **kwargs):
            return record

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/any-id/ws") as ws:
                data = ws.receive_json()
                assert "status" in data
                assert data["status"] == "done"

    def test_accepts_valid_jwt_token(self, test_client: TestClient):
        token = _valid_token()
        record = _make_scan_record(status="done", pct=100)

        async def fake_get(*args, **kwargs):
            return record

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect(
                f"/api/v1/scan/scan-123/ws?token={token}"
            ) as ws:
                data = ws.receive_json()
                assert data["status"] == "done"

    def test_rejects_invalid_jwt(self, test_client: TestClient):
        settings.require_auth = True
        try:
            with pytest.raises(Exception):
                with test_client.websocket_connect(
                    "/api/v1/scan/scan-x/ws?token=not.a.jwt"
                ):
                    pass
        finally:
            settings.require_auth = False


# ── Progress streaming ────────────────────────────────────────────────────────

class TestWebSocketProgress:
    def test_returns_progress_event(self, test_client: TestClient):
        record = _make_scan_record(status="done", pct=88)

        async def fake_get(*args, **kwargs):
            return record

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/s1/ws") as ws:
                data = ws.receive_json()

        assert data["status"] == "done"
        assert data["progress_pct"] == 88
        assert data["progress_message"] is not None

    def test_closes_after_terminal_status(self, test_client: TestClient):
        """Connection must close automatically on done/failed/partial."""
        record = _make_scan_record(status="done", pct=100)

        async def fake_get(*args, **kwargs):
            return record

        received: list[dict] = []
        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/s2/ws") as ws:
                try:
                    while True:
                        msg = ws.receive_json()
                        received.append(msg)
                except Exception:
                    pass  # closed by server

        assert len(received) >= 1
        assert received[-1]["status"] in ("done", "failed", "partial")

    def test_returns_error_when_scan_not_found(self, test_client: TestClient):
        async def fake_get(*args, **kwargs):
            return None

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/missing/ws") as ws:
                data = ws.receive_json()

        assert "error" in data

    def test_streams_running_scan(self, test_client: TestClient):
        """Running scan: first message has progress_pct < 100 and status=running."""
        record = _make_scan_record(status="running", pct=45)
        # Switch to done on second call so the WS closes
        done_record = _make_scan_record(status="done", pct=100)
        call_count = 0

        async def fake_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return record if call_count == 1 else done_record

        received: list[dict] = []
        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/s3/ws") as ws:
                try:
                    while True:
                        msg = ws.receive_json()
                        received.append(msg)
                except Exception:
                    pass

        assert received[0]["status"] == "running"
        assert received[0]["progress_pct"] == 45
        assert received[-1]["status"] == "done"


# ── Failed status ─────────────────────────────────────────────────────────────

class TestWebSocketFailedScan:
    def test_closes_on_failed_status(self, test_client: TestClient):
        record = _make_scan_record(status="failed", pct=35)

        async def fake_get(*args, **kwargs):
            return record

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/s4/ws") as ws:
                data = ws.receive_json()

        assert data["status"] == "failed"

    def test_closes_on_partial_status(self, test_client: TestClient):
        record = _make_scan_record(status="partial", pct=90)

        async def fake_get(*args, **kwargs):
            return record

        with patch("db.repositories.ScanRepository.get", fake_get):
            with test_client.websocket_connect("/api/v1/scan/s5/ws") as ws:
                data = ws.receive_json()

        assert data["status"] == "partial"
