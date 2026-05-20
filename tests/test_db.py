"""Tests for the database layer: repositories and models."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
import pytest_asyncio

from core.schemas import (
    Confidence,
    Finding,
    Priority,
    Severity,
    ToolName,
)
from db.database import reset_db_for_testing, get_session
from db.repositories import (
    FindingRepository,
    OrgRepository,
    ScanRepository,
    TargetRepository,
    _hash_api_key,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(autouse=True)
async def fresh_db():
    """Reset in-memory DB before every test."""
    await reset_db_for_testing(TEST_DB_URL)
    yield


async def _session():
    """Context manager shortcut for tests."""
    return get_session()


def _make_finding(
    scan_id: str = "scan-001",
    correlation_key: str = "abc123",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=f"finding-{correlation_key}",
        scan_id=scan_id,
        correlation_key=correlation_key,
        endpoint_fingerprint="ep-001",
        title="SQL Injection",
        description="SQL injection in login form",
        host="example.com",
        port=443,
        path="/login",
        method="POST",
        severity=severity,
        priority=Priority.HIGH,
        confidence=Confidence.HIGH,
        sources=[ToolName.ZAP],
        cwe_ids=[89],
        owasp_category="A03:2021-Injection",
    )


# ── OrgRepository tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_org_returns_org_and_raw_key():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, raw_key = await repo.create_org("Acme Corp", plan="pro")

    assert org.id
    assert org.name == "Acme Corp"
    assert org.plan == "pro"
    assert raw_key
    assert len(raw_key) == 32  # UUID without dashes


@pytest.mark.asyncio
async def test_get_by_api_key_returns_org():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, raw_key = await repo.create_org("Test Org")

    async with get_session() as session:
        repo = OrgRepository(session)
        found = await repo.get_by_api_key(raw_key)

    assert found is not None
    assert found.id == org.id
    assert found.name == "Test Org"


@pytest.mark.asyncio
async def test_get_by_api_key_wrong_key_returns_none():
    async with get_session() as session:
        repo = OrgRepository(session)
        await repo.create_org("Test Org")

    async with get_session() as session:
        repo = OrgRepository(session)
        found = await repo.get_by_api_key("completely-wrong-key")

    assert found is None


@pytest.mark.asyncio
async def test_api_key_hashed_in_db():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, raw_key = await repo.create_org("Hash Test Org")

    # Stored hash should not equal raw key
    assert org.api_key_hash != raw_key
    # Should match expected hash
    assert org.api_key_hash == _hash_api_key(raw_key)


@pytest.mark.asyncio
async def test_increment_scan_count():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, _ = await repo.create_org("Quota Org")
        org_id = org.id

    async with get_session() as session:
        repo = OrgRepository(session)
        await repo.increment_scan_count(org_id)
        await repo.increment_scan_count(org_id)

    async with get_session() as session:
        repo = OrgRepository(session)
        updated = await repo.get_by_id(org_id)
        assert updated.scans_this_month == 2


@pytest.mark.asyncio
async def test_check_quota_within_limit():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, _ = await repo.create_org("Quota Org", quota=5)
        org_id = org.id

    async with get_session() as session:
        repo = OrgRepository(session)
        assert await repo.check_quota(org_id) is True


@pytest.mark.asyncio
async def test_check_quota_exceeded():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, _ = await repo.create_org("Quota Org", quota=2)
        org_id = org.id
        await repo.increment_scan_count(org_id)
        await repo.increment_scan_count(org_id)

    async with get_session() as session:
        repo = OrgRepository(session)
        assert await repo.check_quota(org_id) is False


@pytest.mark.asyncio
async def test_check_quota_unlimited():
    async with get_session() as session:
        repo = OrgRepository(session)
        org, _ = await repo.create_org("Enterprise Org", quota=-1)
        org_id = org.id
        # Simulate many scans
        for _ in range(100):
            await repo.increment_scan_count(org_id)

    async with get_session() as session:
        repo = OrgRepository(session)
        assert await repo.check_quota(org_id) is True


# ── TargetRepository tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_or_create_creates_new_target():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Target Org")
        org_id = org.id

    async with get_session() as session:
        repo = TargetRepository(session)
        target = await repo.get_or_create(org_id, "https://example.com", "Example")

    assert target.id
    assert target.url == "https://example.com"
    assert target.name == "Example"
    assert target.org_id == org_id


@pytest.mark.asyncio
async def test_get_or_create_is_idempotent():
    """Calling get_or_create twice returns the same target."""
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Idem Org")
        org_id = org.id

    async with get_session() as session:
        repo = TargetRepository(session)
        t1 = await repo.get_or_create(org_id, "https://example.com", "Example")

    async with get_session() as session:
        repo = TargetRepository(session)
        t2 = await repo.get_or_create(org_id, "https://example.com", "Different Name")

    assert t1.id == t2.id


@pytest.mark.asyncio
async def test_list_for_org():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("List Org")
        org_id = org.id

    async with get_session() as session:
        repo = TargetRepository(session)
        await repo.get_or_create(org_id, "https://a.com", "A")
        await repo.get_or_create(org_id, "https://b.com", "B")

    async with get_session() as session:
        repo = TargetRepository(session)
        targets = await repo.list_for_org(org_id)

    assert len(targets) == 2
    urls = {t.url for t in targets}
    assert "https://a.com" in urls
    assert "https://b.com" in urls


@pytest.mark.asyncio
async def test_update_last_scan():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Scan Org")
        org_id = org.id

    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org_id, "https://example.com", "Example")
        target_id = target.id

    # Create a scan first (needed for FK)
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        await scan_repo.create("scan-001", org_id, target_id, ["nmap"])

    async with get_session() as session:
        target_repo = TargetRepository(session)
        await target_repo.update_last_scan(target_id, "scan-001")

    async with get_session() as session:
        target_repo = TargetRepository(session)
        updated = await target_repo.get(org_id, target_id)
        assert updated.last_scan_at is not None
        assert updated.scan_count == 1


# ── ScanRepository tests ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_create_and_get():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Scan Org")
        org_id = org.id
        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org_id, "https://example.com", "Example")
        target_id = target.id

    async with get_session() as session:
        repo = ScanRepository(session)
        scan = await repo.create("scan-001", org_id, target_id, ["nmap", "nikto"], "full")

    assert scan.id == "scan-001"
    assert scan.status == "pending"
    assert scan.scan_mode == "full"

    async with get_session() as session:
        repo = ScanRepository(session)
        fetched = await repo.get("scan-001")
        assert fetched is not None
        assert fetched.org_id == org_id


@pytest.mark.asyncio
async def test_scan_update_status():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Status Org")
        org_id = org.id
        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org_id, "https://example.com", "Example")
        target_id = target.id

    async with get_session() as session:
        repo = ScanRepository(session)
        await repo.create("scan-002", org_id, target_id, ["nmap"])

    async with get_session() as session:
        repo = ScanRepository(session)
        await repo.update_status(
            "scan-002",
            "done",
            finding_count=5,
            duration_seconds=42.0,
        )

    async with get_session() as session:
        repo = ScanRepository(session)
        fetched = await repo.get("scan-002")
        assert fetched.status == "done"
        assert fetched.finding_count == 5
        assert fetched.duration_seconds == 42.0


@pytest.mark.asyncio
async def test_list_scans_for_target():
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("List Scans Org")
        org_id = org.id
        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org_id, "https://example.com", "Example")
        target_id = target.id

    async with get_session() as session:
        repo = ScanRepository(session)
        await repo.create("scan-a", org_id, target_id, ["nmap"])
        await repo.create("scan-b", org_id, target_id, ["nikto"])

    async with get_session() as session:
        repo = ScanRepository(session)
        scans = await repo.list_for_target(target_id)
        assert len(scans) == 2


# ── FindingRepository tests ────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def org_and_target():
    """Helper: create an org and target, return (org_id, target_id, scan_id)."""
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, _ = await org_repo.create_org("Finding Org")
        org_id = org.id

        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org_id, "https://example.com", "Example")
        target_id = target.id

        scan_repo = ScanRepository(session)
        await scan_repo.create("scan-f1", org_id, target_id, ["zap"])

    return org_id, target_id, "scan-f1"


@pytest.mark.asyncio
async def test_upsert_finding_new(org_and_target):
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record, is_new, is_regressed = await repo.upsert_finding(
            finding, scan_id, org_id, target_id
        )

    assert is_new is True
    assert is_regressed is False
    assert record.id
    assert record.title == "SQL Injection"
    assert record.severity == "high"
    assert record.status == "open"


@pytest.mark.asyncio
async def test_upsert_finding_same_finding_updates_last_seen(org_and_target):
    """Same finding in a new scan updates last_seen but stays non-new."""
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record1, _, _ = await repo.upsert_finding(finding, scan_id, org_id, target_id)

    # Create a second scan
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        await scan_repo.create("scan-f2", org_id, target_id, ["zap"])

    finding2 = _make_finding(scan_id="scan-f2")

    async with get_session() as session:
        repo = FindingRepository(session)
        record2, is_new, is_regressed = await repo.upsert_finding(
            finding2, "scan-f2", org_id, target_id
        )

    assert is_new is False
    assert is_regressed is False
    assert record2.id == record1.id
    assert record2.last_seen_scan_id == "scan-f2"
    assert record2.first_seen_scan_id == scan_id


@pytest.mark.asyncio
async def test_upsert_finding_regression(org_and_target):
    """Finding resolved in scan 1, reappears in scan 2 — should be regressed."""
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record, _, _ = await repo.upsert_finding(finding, scan_id, org_id, target_id)
        # Manually mark as resolved
        await repo.update_status(record.id, org_id, "resolved", "Fixed in v2")

    # Create a second scan
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        await scan_repo.create("scan-f3", org_id, target_id, ["zap"])

    finding2 = _make_finding(scan_id="scan-f3")

    async with get_session() as session:
        repo = FindingRepository(session)
        record2, is_new, is_regressed = await repo.upsert_finding(
            finding2, "scan-f3", org_id, target_id
        )

    assert is_new is False
    assert is_regressed is True
    assert record2.status == "open"


@pytest.mark.asyncio
async def test_update_status_records_history(org_and_target):
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record, _, _ = await repo.upsert_finding(finding, scan_id, org_id, target_id)
        finding_id = record.id

    async with get_session() as session:
        repo = FindingRepository(session)
        await repo.update_status(finding_id, org_id, "acknowledged", "Reviewing this")

    async with get_session() as session:
        repo = FindingRepository(session)
        history = await repo.get_status_history(finding_id)

    assert len(history) == 1
    assert history[0].status_from == "open"
    assert history[0].status_to == "acknowledged"
    assert history[0].note == "Reviewing this"
    assert history[0].scan_id is None  # Manual change


@pytest.mark.asyncio
async def test_update_status_to_resolved_sets_resolved_at(org_and_target):
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record, _, _ = await repo.upsert_finding(finding, scan_id, org_id, target_id)
        finding_id = record.id

    async with get_session() as session:
        repo = FindingRepository(session)
        updated = await repo.update_status(finding_id, org_id, "resolved")
        assert updated.resolved_at is not None
        assert updated.status == "resolved"


@pytest.mark.asyncio
async def test_link_to_scan_and_get_for_scan(org_and_target):
    org_id, target_id, scan_id = org_and_target
    finding = _make_finding(scan_id=scan_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        record, is_new, is_regressed = await repo.upsert_finding(
            finding, scan_id, org_id, target_id
        )
        await repo.link_to_scan(
            record.id,
            scan_id,
            is_new,
            is_regressed,
            {"severity": "high", "confidence": "high", "evidence": None},
        )

    async with get_session() as session:
        repo = FindingRepository(session)
        findings_for_scan = await repo.get_for_scan(scan_id)
        assert len(findings_for_scan) == 1
        assert findings_for_scan[0].id == record.id


@pytest.mark.asyncio
async def test_get_open_count_by_severity(org_and_target):
    org_id, target_id, scan_id = org_and_target

    async with get_session() as session:
        repo = FindingRepository(session)
        f1 = _make_finding(scan_id=scan_id, correlation_key="key1", severity=Severity.HIGH)
        f2 = _make_finding(scan_id=scan_id, correlation_key="key2", severity=Severity.CRITICAL)
        f3 = _make_finding(scan_id=scan_id, correlation_key="key3", severity=Severity.HIGH)
        await repo.upsert_finding(f1, scan_id, org_id, target_id)
        await repo.upsert_finding(f2, scan_id, org_id, target_id)
        await repo.upsert_finding(f3, scan_id, org_id, target_id)

    async with get_session() as session:
        repo = FindingRepository(session)
        counts = await repo.get_open_count_by_severity(org_id)

    assert counts["high"] == 2
    assert counts["critical"] == 1
    assert counts["medium"] == 0
