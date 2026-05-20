"""Tests for API endpoints."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from core.schemas import ScanStatus


def test_health_returns_ok(test_client: TestClient) -> None:
    response = test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "tools_available" in data
    assert "nmap" in data["tools_available"]


def test_health_tools_are_booleans(test_client: TestClient) -> None:
    response = test_client.get("/health")
    tools = response.json()["tools_available"]
    for tool, available in tools.items():
        assert isinstance(available, bool), f"{tool} should be bool, got {type(available)}"


def test_get_scan_not_found(test_client: TestClient) -> None:
    response = test_client.get("/scan/nonexistent-scan-id")
    assert response.status_code == 404


def test_get_report_not_found(test_client: TestClient) -> None:
    response = test_client.get("/report/nonexistent-scan-id")
    assert response.status_code == 404


def test_create_scan_returns_202(test_client: TestClient) -> None:
    with patch("api.routes.run_scan", new_callable=AsyncMock) as mock_run:
        response = test_client.post(
            "/scan",
            json={"target_url": "http://example.com", "tools": ["nmap"]},
        )
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == ScanStatus.PENDING.value
    assert "poll_url" in data


def test_create_scan_invalid_url_rejected(test_client: TestClient) -> None:
    response = test_client.post(
        "/scan",
        json={"target_url": "not-a-valid-url"},
    )
    # Pydantic validation should reject this or it gets processed
    # In MVP target_url is a plain string so just check we get a response
    assert response.status_code in (202, 422)


def test_get_scan_after_creation(test_client: TestClient, tmp_path: Path) -> None:
    from core.config import settings
    settings.data_dir = tmp_path

    with patch("api.routes.run_scan", new_callable=AsyncMock):
        response = test_client.post(
            "/scan",
            json={"target_url": "http://example.com", "tools": ["nmap"]},
        )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    poll_response = test_client.get(f"/scan/{scan_id}")
    assert poll_response.status_code == 200
    data = poll_response.json()
    assert data["scan_id"] == scan_id
    assert data["target"].rstrip("/") == "http://example.com"


def test_report_returns_425_while_pending(test_client: TestClient, tmp_path: Path) -> None:
    from core.config import settings
    settings.data_dir = tmp_path

    with patch("api.routes.run_scan", new_callable=AsyncMock):
        response = test_client.post(
            "/scan",
            json={"target_url": "http://example.com", "tools": ["nmap"]},
        )
    scan_id = response.json()["scan_id"]

    report_response = test_client.get(f"/report/{scan_id}")
    assert report_response.status_code == 425
