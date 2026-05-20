"""Shared fixtures for all tests."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import app
from core.config import settings
from core.schemas import Finding, RawFinding, Severity, Confidence, ToolName
from core.storage import ScanStore

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def nmap_xml() -> str:
    return (FIXTURES_DIR / "nmap_sample.xml").read_text()


@pytest.fixture
def zap_json() -> str:
    return (FIXTURES_DIR / "zap_sample.json").read_text()


@pytest.fixture
def nikto_json() -> str:
    return (FIXTURES_DIR / "nikto_sample.json").read_text()


@pytest.fixture
def tmp_store(tmp_path: Path) -> ScanStore:
    return ScanStore(tmp_path)


@pytest.fixture
def test_client(tmp_path: Path) -> TestClient:
    """TestClient with isolated temp data_dir and fresh in-memory DB."""
    import asyncio
    from db.database import reset_db_for_testing

    original_data_dir = settings.data_dir
    original_db_url = settings.database_url
    settings.data_dir = tmp_path
    settings.database_url = "sqlite+aiosqlite:///:memory:"
    asyncio.run(reset_db_for_testing("sqlite+aiosqlite:///:memory:"))
    client = TestClient(app)
    yield client
    settings.data_dir = original_data_dir
    settings.database_url = original_db_url


@pytest.fixture
def sample_raw_findings_nmap() -> list[RawFinding]:
    return [
        RawFinding(
            id="nmap_192.168.1.1_80_tcp",
            tool=ToolName.NMAP,
            host="example.com",
            port=80,
            path="/",
            title="Open port 80/tcp (http)",
            description="Port 80/tcp is open. Service: http Apache httpd 2.4.51",
            raw_severity="informational",
            raw_confidence="high",
        ),
        RawFinding(
            id="nmap_192.168.1.1_80_http-vuln-cve2017-5638",
            tool=ToolName.NMAP,
            host="example.com",
            port=80,
            path="/",
            title="Http Vuln Cve2017 5638 On Port 80",
            description="State: VULNERABLE\nIDs: CVE:CVE-2017-5638",
            evidence="State: VULNERABLE",
            raw_severity="high",
            raw_confidence="medium",
        ),
    ]


@pytest.fixture
def sample_raw_findings_zap() -> list[RawFinding]:
    return [
        RawFinding(
            id="zap_40018",
            tool=ToolName.ZAP,
            host="example.com",
            port=80,
            path="/login",
            method="POST",
            parameter="username",
            title="SQL Injection",
            description="SQL injection may be possible.",
            evidence="You have an error in your SQL syntax",
            raw_severity="3",
            raw_confidence="2",
            cwe_id=89,
            solution="Use parameterised queries.",
        ),
    ]


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="test-finding-001",
        scan_id="scan-001",
        correlation_key="abc123",
        title="SQL Injection",
        description="SQL injection found in login form",
        host="example.com",
        port=80,
        path="/login",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        sources=[ToolName.ZAP],
        cwe_ids=[89],
        owasp_category="A03:2021-Injection",
    )
