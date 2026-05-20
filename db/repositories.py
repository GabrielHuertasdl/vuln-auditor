"""Repository classes for all database operations."""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from core.schemas import Finding
from db.models import (
    APIKeyRecord,
    AssetDiscovery,
    AuditLog,
    FindingRecord,
    FindingStatusHistory,
    InviteToken,
    Membership,
    OIDCAccount,
    Organization,
    PostureScore,
    RefreshTokenRecord,
    ScanFinding,
    ScanRecord,
    SecurityControl,
    Target,
    User,
    VerificationDomain,
    VerificationRecord,
    WebhookDelivery,
    WebhookEndpoint,
)

log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _first_of_next_month() -> datetime:
    now = _now()
    if now.month == 12:
        return now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)


def _global_fingerprint(org_id: str, target_id: str, correlation_key: str) -> str:
    return hashlib.sha256(f"{org_id}:{target_id}:{correlation_key}".encode()).hexdigest()[:24]


def _j(value: Any) -> str:
    """Serialize to JSON string."""
    return json.dumps(value)


def _jl(value: str) -> Any:
    """Deserialize from JSON string."""
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


# ── OrgRepository ─────────────────────────────────────────────────────────────

class OrgRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_org(
        self, name: str, plan: str = "free", quota: int = 10
    ) -> tuple[Organization, str]:
        """Create a new organization. Returns (org, raw_api_key)."""
        raw_key = str(uuid.uuid4()).replace("-", "")  # 32-char hex key
        org = Organization(
            id=_new_id(),
            name=name,
            api_key_hash=_hash_api_key(raw_key),
            plan=plan,
            scan_quota=quota,
            scans_this_month=0,
            quota_reset_at=_first_of_next_month(),
            created_at=_now(),
        )
        self.session.add(org)
        await self.session.flush()
        return org, raw_key

    async def get_by_api_key(self, raw_key: str) -> Organization | None:
        key_hash = _hash_api_key(raw_key)
        result = await self.session.execute(
            select(Organization).where(Organization.api_key_hash == key_hash)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, org_id: str) -> Organization | None:
        result = await self.session.execute(
            select(Organization).where(Organization.id == org_id)
        )
        return result.scalar_one_or_none()

    async def get_first(self) -> Organization | None:
        result = await self.session.execute(select(Organization).limit(1))
        return result.scalar_one_or_none()

    async def increment_scan_count(self, org_id: str) -> None:
        await self.session.execute(
            update(Organization)
            .where(Organization.id == org_id)
            .values(scans_this_month=Organization.scans_this_month + 1)
        )

    async def check_quota(self, org_id: str) -> bool:
        """Return True if the org is within its scan quota."""
        await self.reset_monthly_quota_if_needed(org_id)
        org = await self.get_by_id(org_id)
        if org is None:
            return False
        if org.scan_quota == -1:
            return True
        return org.scans_this_month < org.scan_quota

    async def reset_monthly_quota_if_needed(self, org_id: str) -> None:
        org = await self.get_by_id(org_id)
        if org is None:
            return
        # SQLite stores datetimes as naive; normalize both sides for comparison
        now = _now()
        reset_at = org.quota_reset_at
        if reset_at is not None:
            # Strip timezone if SQLite returned naive datetime
            if reset_at.tzinfo is None:
                now_cmp = now.replace(tzinfo=None)
            else:
                now_cmp = now
            if now_cmp >= reset_at:
                await self.session.execute(
                    update(Organization)
                    .where(Organization.id == org_id)
                    .values(
                        scans_this_month=0,
                        quota_reset_at=_first_of_next_month(),
                    )
                )


# ── TargetRepository ──────────────────────────────────────────────────────────

class TargetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create(self, org_id: str, url: str, name: str, schedule: str | None = None) -> Target:
        """Upsert a target by (org_id, url)."""
        result = await self.session.execute(
            select(Target).where(Target.org_id == org_id, Target.url == url)
        )
        target = result.scalar_one_or_none()
        if target is not None:
            if schedule and target.schedule != schedule:
                target.schedule = schedule
                await self.session.flush()
            return target

        target = Target(
            id=_new_id(),
            org_id=org_id,
            url=url,
            name=name,
            tags=_j([]),
            schedule=schedule,
            created_at=_now(),
            last_scan_at=None,
            scan_count=0,
        )
        self.session.add(target)
        await self.session.flush()
        return target

    async def list_for_org(self, org_id: str) -> list[Target]:
        result = await self.session.execute(
            select(Target).where(Target.org_id == org_id)
        )
        return list(result.scalars().all())

    async def get(self, org_id: str, target_id: str) -> Target | None:
        result = await self.session.execute(
            select(Target).where(Target.id == target_id, Target.org_id == org_id)
        )
        return result.scalar_one_or_none()

    async def update_last_scan(self, target_id: str, scan_id: str) -> None:
        await self.session.execute(
            update(Target)
            .where(Target.id == target_id)
            .values(
                last_scan_at=_now(),
                scan_count=Target.scan_count + 1,
            )
        )


# ── ScanRepository ────────────────────────────────────────────────────────────

class ScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        scan_id: str,
        org_id: str,
        target_id: str | None,
        tools: list[str],
        mode: str = "full",
    ) -> ScanRecord:
        record = ScanRecord(
            id=scan_id,
            org_id=org_id,
            target_id=target_id,
            status="pending",
            scan_mode=mode,
            tools_requested=_j(tools),
            tools_succeeded=_j([]),
            tools_failed=_j({}),
            detected_stack=_j([]),
            severity_summary=_j({}),
            priority_summary=_j({}),
            finding_count=0,
            new_finding_count=0,
            regressed_finding_count=0,
            ai_generated=False,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def update_status(self, scan_id: str, status: str, **kwargs: Any) -> None:
        values: dict[str, Any] = {"status": status}
        # Serialize list/dict fields that need JSON storage
        json_fields = {
            "tools_succeeded", "tools_failed", "detected_stack",
            "severity_summary", "priority_summary",
        }
        for k, v in kwargs.items():
            if k in json_fields and not isinstance(v, str):
                values[k] = _j(v)
            else:
                values[k] = v
        await self.session.execute(
            update(ScanRecord).where(ScanRecord.id == scan_id).values(**values)
        )

    async def get(self, scan_id: str) -> ScanRecord | None:
        result = await self.session.execute(
            select(ScanRecord).where(ScanRecord.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def list_for_target(self, target_id: str, limit: int = 20) -> list[ScanRecord]:
        result = await self.session.execute(
            select(ScanRecord)
            .where(ScanRecord.target_id == target_id)
            .order_by(ScanRecord.started_at.desc().nullslast())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_for_org(self, org_id: str, limit: int = 50) -> list[ScanRecord]:
        result = await self.session.execute(
            select(ScanRecord)
            .where(ScanRecord.org_id == org_id)
            .order_by(ScanRecord.started_at.desc().nullslast())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_previous_scan(
        self, target_id: str, before_scan_id: str
    ) -> ScanRecord | None:
        """Return the last completed scan for this target before the given scan."""
        # First get the started_at of the reference scan
        ref = await self.get(before_scan_id)
        if ref is None:
            return None
        ref_time = ref.started_at

        query = (
            select(ScanRecord)
            .where(
                ScanRecord.target_id == target_id,
                ScanRecord.id != before_scan_id,
                ScanRecord.status == "done",
            )
            .order_by(ScanRecord.started_at.desc().nullslast())
            .limit(1)
        )
        if ref_time is not None:
            query = (
                select(ScanRecord)
                .where(
                    ScanRecord.target_id == target_id,
                    ScanRecord.id != before_scan_id,
                    ScanRecord.status == "done",
                    ScanRecord.started_at < ref_time,
                )
                .order_by(ScanRecord.started_at.desc())
                .limit(1)
            )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()


# ── FindingRepository ─────────────────────────────────────────────────────────

class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert_finding(
        self,
        finding: Finding,
        scan_id: str,
        org_id: str,
        target_id: str,
    ) -> tuple[FindingRecord, bool, bool]:
        """
        Insert or update a finding.
        Returns (record, is_new, is_regressed).
        - is_new: finding not seen in any previous scan for this target
        - is_regressed: finding was resolved but has reappeared
        """
        now = _now()
        fp = _global_fingerprint(org_id, target_id, finding.correlation_key)

        result = await self.session.execute(
            select(FindingRecord).where(
                FindingRecord.org_id == org_id,
                FindingRecord.target_id == target_id,
                FindingRecord.global_fingerprint == fp,
            )
        )
        existing = result.scalar_one_or_none()

        if existing is None:
            # New finding — insert
            record = FindingRecord(
                id=_new_id(),
                org_id=org_id,
                target_id=target_id,
                global_fingerprint=fp,
                correlation_key=finding.correlation_key,
                endpoint_fingerprint=finding.endpoint_fingerprint,
                title=finding.title,
                description=finding.description,
                host=finding.host,
                port=finding.port,
                protocol=finding.protocol,
                path=finding.path,
                method=finding.method,
                parameter=finding.parameter,
                severity=finding.severity.value,
                priority=finding.priority.value,
                confidence=finding.confidence.value,
                exploitability=finding.exploitability.value,
                remediation_effort=finding.remediation_effort.value,
                owasp_category=finding.owasp_category,
                owasp_api_category=finding.owasp_api_category,
                cwe_ids=_j(finding.cwe_ids),
                status="open",
                is_noise=finding.is_noise,
                duplicate_of=finding.duplicate_of,
                related_findings=_j(finding.related_findings),
                tags=_j(finding.tags),
                detected_stack=_j(finding.detected_stack),
                sources=_j([s.value for s in finding.sources]),
                source_count=finding.source_count,
                evidence=finding.evidence,
                normalized_evidence=finding.normalized_evidence,
                solution=finding.solution,
                references=_j(finding.references),
                ai_mitigation=finding.ai_mitigation,
                first_seen_scan_id=scan_id,
                last_seen_scan_id=scan_id,
                first_seen_at=now,
                last_seen_at=now,
            )
            self.session.add(record)
            await self.session.flush()
            return record, True, False

        # Existing finding — check for regression and update
        was_resolved = existing.status in ("resolved", "false_positive")
        is_regressed = was_resolved

        prev_severity = existing.severity
        new_severity = finding.severity.value

        # Record history if severity changed
        if prev_severity != new_severity:
            history = FindingStatusHistory(
                id=_new_id(),
                finding_id=existing.id,
                scan_id=scan_id,
                status_from=existing.status,
                status_to=existing.status,  # status unchanged, only severity
                severity_from=prev_severity,
                severity_to=new_severity,
                changed_at=now,
                note="Severity updated by new scan",
            )
            self.session.add(history)

        # If regressed, reopen and record history
        if is_regressed:
            history = FindingStatusHistory(
                id=_new_id(),
                finding_id=existing.id,
                scan_id=scan_id,
                status_from=existing.status,
                status_to="open",
                severity_from=prev_severity,
                severity_to=new_severity,
                changed_at=now,
                note="Finding regressed — reappeared after being resolved",
            )
            self.session.add(history)

        # Update existing record
        new_status = "open" if is_regressed else existing.status
        await self.session.execute(
            update(FindingRecord)
            .where(FindingRecord.id == existing.id)
            .values(
                last_seen_scan_id=scan_id,
                last_seen_at=now,
                severity=new_severity,
                priority=finding.priority.value,
                confidence=finding.confidence.value,
                status=new_status,
                resolved_at=None if is_regressed else existing.resolved_at,
                source_count=finding.source_count,
                sources=_j([s.value for s in finding.sources]),
                evidence=finding.evidence,
                normalized_evidence=finding.normalized_evidence,
                ai_mitigation=finding.ai_mitigation or existing.ai_mitigation,
            )
        )
        # Refresh to get latest state
        await self.session.refresh(existing)
        return existing, False, is_regressed

    async def link_to_scan(
        self,
        finding_id: str,
        scan_id: str,
        is_new: bool,
        is_regressed: bool,
        snapshot_data: dict[str, Any],
    ) -> ScanFinding:
        scan_finding = ScanFinding(
            id=_new_id(),
            scan_id=scan_id,
            finding_id=finding_id,
            is_new=is_new,
            is_regressed=is_regressed,
            severity_snapshot=snapshot_data.get("severity", ""),
            confidence_snapshot=snapshot_data.get("confidence", ""),
            evidence_snapshot=snapshot_data.get("evidence"),
        )
        self.session.add(scan_finding)
        await self.session.flush()
        return scan_finding

    async def get_for_scan(self, scan_id: str) -> list[FindingRecord]:
        result = await self.session.execute(
            select(FindingRecord)
            .join(ScanFinding, ScanFinding.finding_id == FindingRecord.id)
            .where(ScanFinding.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_scan_finding_links(self, scan_id: str) -> list[ScanFinding]:
        result = await self.session.execute(
            select(ScanFinding).where(ScanFinding.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_for_target(
        self, target_id: str, status: str | None = None
    ) -> list[FindingRecord]:
        query = select(FindingRecord).where(FindingRecord.target_id == target_id)
        if status:
            query = query.where(FindingRecord.status == status)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_for_org(
        self,
        org_id: str,
        status: str | None = None,
        severity: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[FindingRecord]:
        query = select(FindingRecord).where(FindingRecord.org_id == org_id)
        if status:
            query = query.where(FindingRecord.status == status)
        if severity:
            query = query.where(FindingRecord.severity == severity)
        if target_id:
            query = query.where(FindingRecord.target_id == target_id)
        query = query.order_by(FindingRecord.last_seen_at.desc()).limit(limit).offset(offset)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get(self, finding_id: str, org_id: str) -> FindingRecord | None:
        result = await self.session.execute(
            select(FindingRecord).where(
                FindingRecord.id == finding_id,
                FindingRecord.org_id == org_id,
            )
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        finding_id: str,
        org_id: str,
        new_status: str,
        note: str | None = None,
    ) -> FindingRecord | None:
        record = await self.get(finding_id, org_id)
        if record is None:
            return None
        now = _now()
        old_status = record.status
        resolved_at = now if new_status == "resolved" else record.resolved_at

        history = FindingStatusHistory(
            id=_new_id(),
            finding_id=finding_id,
            scan_id=None,  # Manual change via API
            status_from=old_status,
            status_to=new_status,
            severity_from=record.severity,
            severity_to=record.severity,
            changed_at=now,
            note=note,
        )
        self.session.add(history)

        await self.session.execute(
            update(FindingRecord)
            .where(FindingRecord.id == finding_id)
            .values(
                status=new_status,
                resolved_at=resolved_at,
                resolution_note=note if new_status == "resolved" else record.resolution_note,
            )
        )
        await self.session.refresh(record)
        return record

    async def get_status_history(self, finding_id: str) -> list[FindingStatusHistory]:
        result = await self.session.execute(
            select(FindingStatusHistory)
            .where(FindingStatusHistory.finding_id == finding_id)
            .order_by(FindingStatusHistory.changed_at.asc())
        )
        return list(result.scalars().all())

    async def get_open_count_by_severity(self, org_id: str) -> dict[str, int]:
        findings = await self.get_for_org(org_id, status="open", limit=10000)
        counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
        }
        for f in findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts


class PostureRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save_discovery_items(self, items: list[AssetDiscovery]) -> None:
        for item in items:
            self.session.add(item)
        await self.session.flush()

    async def save_verifications(self, records: list[VerificationRecord]) -> None:
        for record in records:
            self.session.add(record)
        await self.session.flush()

    async def save_posture_score(self, score: PostureScore) -> None:
        self.session.add(score)
        await self.session.flush()

    async def get_verifications(self, scan_id: str) -> list[VerificationRecord]:
        result = await self.session.execute(
            select(VerificationRecord).where(VerificationRecord.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_discovery(self, scan_id: str) -> list[AssetDiscovery]:
        result = await self.session.execute(
            select(AssetDiscovery).where(AssetDiscovery.scan_id == scan_id)
        )
        return list(result.scalars().all())

    async def get_score(self, scan_id: str) -> PostureScore | None:
        result = await self.session.execute(
            select(PostureScore).where(PostureScore.scan_id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_trend_for_target(self, target_id: str, limit: int = 30) -> list[dict]:
        """Return posture scores over time for a target, ordered oldest → newest."""
        result = await self.session.execute(
            select(PostureScore, ScanRecord.completed_at, ScanRecord.target_id)
            .join(ScanRecord, ScanRecord.id == PostureScore.scan_id)
            .where(ScanRecord.target_id == target_id, ScanRecord.status == "done")
            .order_by(ScanRecord.completed_at.asc())
            .limit(limit)
        )
        rows = result.all()
        return [
            {
                "date": completed_at.isoformat() if completed_at else None,
                "overall_score": ps.overall_score,
                "coverage_score": ps.coverage_score,
                "confidence_score": ps.confidence_score,
                "exposure_score": ps.exposure_score,
                "domain_scores": ps.domain_scores,
                "scan_id": ps.scan_id,
            }
            for ps, completed_at, _ in rows
        ]

    async def get_trend_for_org(self, org_id: str, limit: int = 30) -> list[dict]:
        """Return aggregated posture trend for an entire org."""
        result = await self.session.execute(
            select(PostureScore, ScanRecord.completed_at)
            .join(ScanRecord, ScanRecord.id == PostureScore.scan_id)
            .where(ScanRecord.org_id == org_id, ScanRecord.status == "done")
            .order_by(ScanRecord.completed_at.asc())
            .limit(limit)
        )
        rows = result.all()
        return [
            {
                "date": completed_at.isoformat() if completed_at else None,
                "overall_score": ps.overall_score,
                "coverage_score": ps.coverage_score,
                "confidence_score": ps.confidence_score,
                "exposure_score": ps.exposure_score,
                "scan_id": ps.scan_id,
            }
            for ps, completed_at in rows
        ]

    async def get_previous_score(self, target_id: str, before_scan_id: str) -> PostureScore | None:
        # We need to join with ScanRecord to filter by target_id
        result = await self.session.execute(
            select(PostureScore)
            .join(ScanRecord, ScanRecord.id == PostureScore.scan_id)
            .where(
                ScanRecord.target_id == target_id,
                ScanRecord.id != before_scan_id,
                ScanRecord.status == "done"
            )
            .order_by(ScanRecord.completed_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


# ── UserRepository ────────────────────────────────────────────────────────────

class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self, email: str, password_hash: str, name: str, org_id: str, role: str = "admin"
    ) -> User:
        user = User(
            id=_new_id(),
            email=email.lower().strip(),
            password_hash=password_hash,
            name=name,
            org_id=org_id,
            role=role,
            is_active=True,
            created_at=_now(),
        )
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_email(self, email: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def list_for_org(self, org_id: str) -> list[User]:
        result = await self.session.execute(
            select(User).where(User.org_id == org_id).order_by(User.created_at.asc())
        )
        return list(result.scalars().all())

    async def update_role(self, user_id: str, role: str) -> None:
        await self.session.execute(
            update(User).where(User.id == user_id).values(role=role)
        )

    async def deactivate(self, user_id: str) -> None:
        await self.session.execute(
            update(User).where(User.id == user_id).values(is_active=False)
        )

    async def record_login(self, user_id: str, success: bool) -> None:
        if success:
            await self.session.execute(
                update(User)
                .where(User.id == user_id)
                .values(last_login_at=_now(), failed_login_count=0)
            )
        else:
            await self.session.execute(
                update(User)
                .where(User.id == user_id)
                .values(failed_login_count=User.failed_login_count + 1)
            )


# ── MembershipRepository ──────────────────────────────────────────────────────

class MembershipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self, user_id: str, org_id: str, role: str, invited_by: str | None = None
    ) -> Membership:
        m = Membership(
            id=_new_id(),
            user_id=user_id,
            org_id=org_id,
            role=role,
            invited_by=invited_by,
            invited_at=_now() if invited_by else None,
            accepted_at=_now(),
            is_active=True,
            created_at=_now(),
        )
        self.session.add(m)
        await self.session.flush()
        return m

    async def get(self, user_id: str, org_id: str) -> Membership | None:
        result = await self.session.execute(
            select(Membership).where(
                Membership.user_id == user_id, Membership.org_id == org_id
            )
        )
        return result.scalar_one_or_none()

    async def list_for_org(self, org_id: str) -> list[Membership]:
        result = await self.session.execute(
            select(Membership).where(
                Membership.org_id == org_id, Membership.is_active == True
            )
        )
        return list(result.scalars().all())

    async def update_role(self, user_id: str, org_id: str, role: str) -> None:
        await self.session.execute(
            update(Membership)
            .where(Membership.user_id == user_id, Membership.org_id == org_id)
            .values(role=role)
        )


# ── APIKeyRepository ──────────────────────────────────────────────────────────

class APIKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _gen_key() -> tuple[str, str, str]:
        """Return (raw_key, key_hash, key_prefix)."""
        raw = "vak_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, key_hash, raw[:12]

    async def create(
        self,
        org_id: str,
        name: str,
        created_by: str | None = None,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[APIKeyRecord, str]:
        """Create a new API key. Returns (record, raw_key). raw_key is shown ONCE."""
        raw, key_hash, prefix = self._gen_key()
        record = APIKeyRecord(
            id=_new_id(),
            org_id=org_id,
            name=name,
            key_hash=key_hash,
            key_prefix=prefix,
            scopes=_j(scopes or ["read", "write"]),
            created_by=created_by,
            expires_at=expires_at,
            is_active=True,
            created_at=_now(),
        )
        self.session.add(record)
        await self.session.flush()
        return record, raw

    async def get_by_raw_key(self, raw_key: str) -> APIKeyRecord | None:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        result = await self.session.execute(
            select(APIKeyRecord).where(
                APIKeyRecord.key_hash == key_hash,
                APIKeyRecord.is_active == True,
            )
        )
        record = result.scalar_one_or_none()
        if record and record.expires_at and record.expires_at < _now():
            return None
        return record

    async def list_for_org(self, org_id: str) -> list[APIKeyRecord]:
        result = await self.session.execute(
            select(APIKeyRecord)
            .where(APIKeyRecord.org_id == org_id, APIKeyRecord.is_active == True)
            .order_by(APIKeyRecord.created_at.desc())
        )
        return list(result.scalars().all())

    async def revoke(self, key_id: str, org_id: str) -> bool:
        result = await self.session.execute(
            update(APIKeyRecord)
            .where(APIKeyRecord.id == key_id, APIKeyRecord.org_id == org_id)
            .values(is_active=False)
        )
        return result.rowcount > 0  # type: ignore[return-value]

    async def touch(self, key_id: str) -> None:
        await self.session.execute(
            update(APIKeyRecord).where(APIKeyRecord.id == key_id).values(last_used_at=_now())
        )


# ── RefreshTokenRepository ────────────────────────────────────────────────────

class RefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    async def store(
        self, user_id: str, raw_token: str, expire_days: int, device_hint: str | None = None
    ) -> RefreshTokenRecord:
        record = RefreshTokenRecord(
            id=_new_id(),
            user_id=user_id,
            token_hash=self._hash(raw_token),
            expires_at=_now() + timedelta(days=expire_days),
            device_hint=device_hint,
            created_at=_now(),
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def get_valid(self, raw_token: str) -> RefreshTokenRecord | None:
        token_hash = self._hash(raw_token)
        result = await self.session.execute(
            select(RefreshTokenRecord).where(
                RefreshTokenRecord.token_hash == token_hash,
                RefreshTokenRecord.revoked_at.is_(None),
                RefreshTokenRecord.expires_at > _now(),
            )
        )
        return result.scalar_one_or_none()

    async def revoke(self, raw_token: str) -> bool:
        token_hash = self._hash(raw_token)
        result = await self.session.execute(
            update(RefreshTokenRecord)
            .where(RefreshTokenRecord.token_hash == token_hash)
            .values(revoked_at=_now())
        )
        return result.rowcount > 0  # type: ignore[return-value]

    async def revoke_all_for_user(self, user_id: str) -> None:
        await self.session.execute(
            update(RefreshTokenRecord)
            .where(RefreshTokenRecord.user_id == user_id, RefreshTokenRecord.revoked_at.is_(None))
            .values(revoked_at=_now())
        )

    async def cleanup_expired(self) -> int:
        result = await self.session.execute(
            delete(RefreshTokenRecord).where(RefreshTokenRecord.expires_at < _now())
        )
        return result.rowcount  # type: ignore[return-value]


# ── InviteTokenRepository ─────────────────────────────────────────────────────

class InviteTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _gen() -> tuple[str, str]:
        """Returns (raw_token, token_hash)."""
        raw = secrets.token_urlsafe(32)
        return raw, hashlib.sha256(raw.encode()).hexdigest()

    async def create(
        self, org_id: str, email: str, role: str, invited_by: str, expire_hours: int = 72
    ) -> tuple[InviteToken, str]:
        raw, token_hash = self._gen()
        record = InviteToken(
            id=_new_id(),
            org_id=org_id,
            email=email.lower().strip(),
            role=role,
            token_hash=token_hash,
            invited_by=invited_by,
            expires_at=_now() + timedelta(hours=expire_hours),
            created_at=_now(),
        )
        self.session.add(record)
        await self.session.flush()
        return record, raw

    async def get_valid(self, raw_token: str) -> InviteToken | None:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        result = await self.session.execute(
            select(InviteToken).where(
                InviteToken.token_hash == token_hash,
                InviteToken.accepted_at.is_(None),
                InviteToken.expires_at > _now(),
            )
        )
        return result.scalar_one_or_none()

    async def accept(self, token_id: str) -> None:
        await self.session.execute(
            update(InviteToken).where(InviteToken.id == token_id).values(accepted_at=_now())
        )

    async def list_pending_for_org(self, org_id: str) -> list[InviteToken]:
        result = await self.session.execute(
            select(InviteToken).where(
                InviteToken.org_id == org_id,
                InviteToken.accepted_at.is_(None),
                InviteToken.expires_at > _now(),
            )
        )
        return list(result.scalars().all())


# ── OIDCRepository ────────────────────────────────────────────────────────────

class OIDCRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def link(
        self, user_id: str, provider: str, provider_sub: str, provider_email: str | None
    ) -> OIDCAccount:
        account = OIDCAccount(
            id=_new_id(),
            user_id=user_id,
            provider=provider,
            provider_sub=provider_sub,
            provider_email=provider_email,
            linked_at=_now(),
        )
        self.session.add(account)
        await self.session.flush()
        return account

    async def get_by_sub(self, provider: str, provider_sub: str) -> OIDCAccount | None:
        result = await self.session.execute(
            select(OIDCAccount).where(
                OIDCAccount.provider == provider,
                OIDCAccount.provider_sub == provider_sub,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: str) -> list[OIDCAccount]:
        result = await self.session.execute(
            select(OIDCAccount).where(OIDCAccount.user_id == user_id)
        )
        return list(result.scalars().all())


# ── WebhookRepository ─────────────────────────────────────────────────────────

class WebhookRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        org_id: str,
        name: str,
        url: str,
        events: list[str],
        created_by: str | None = None,
        secret: str | None = None,
    ) -> WebhookEndpoint:
        secret_hash = hashlib.sha256(secret.encode()).hexdigest() if secret else None
        endpoint = WebhookEndpoint(
            id=_new_id(),
            org_id=org_id,
            name=name,
            url=url,
            secret_hash=secret_hash,
            events=_j(events),
            is_active=True,
            created_by=created_by,
            created_at=_now(),
        )
        self.session.add(endpoint)
        await self.session.flush()
        return endpoint

    async def get(self, endpoint_id: str, org_id: str) -> WebhookEndpoint | None:
        result = await self.session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.id == endpoint_id, WebhookEndpoint.org_id == org_id
            )
        )
        return result.scalar_one_or_none()

    async def list_for_org(self, org_id: str) -> list[WebhookEndpoint]:
        result = await self.session.execute(
            select(WebhookEndpoint)
            .where(WebhookEndpoint.org_id == org_id, WebhookEndpoint.is_active == True)
            .order_by(WebhookEndpoint.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_active_for_event(self, org_id: str, event: str) -> list[WebhookEndpoint]:
        """Return all active endpoints for the org subscribed to the given event."""
        endpoints = await self.list_for_org(org_id)
        matching = []
        for ep in endpoints:
            events = _jl(ep.events)
            if event in events or "*" in events:
                matching.append(ep)
        return matching

    async def deactivate(self, endpoint_id: str, org_id: str) -> bool:
        result = await self.session.execute(
            update(WebhookEndpoint)
            .where(WebhookEndpoint.id == endpoint_id, WebhookEndpoint.org_id == org_id)
            .values(is_active=False)
        )
        return result.rowcount > 0  # type: ignore[return-value]

    async def log_delivery(
        self,
        endpoint_id: str,
        event: str,
        payload: dict,
        status_code: int | None,
        response_body: str | None,
        succeeded: bool,
    ) -> WebhookDelivery:
        delivery = WebhookDelivery(
            id=_new_id(),
            endpoint_id=endpoint_id,
            event=event,
            payload=payload,
            status_code=status_code,
            response_body=response_body[:1000] if response_body else None,
            succeeded=succeeded,
            created_at=_now(),
            delivered_at=_now() if succeeded else None,
        )
        self.session.add(delivery)
        await self.session.flush()
        # Update last_triggered_at on endpoint
        await self.session.execute(
            update(WebhookEndpoint)
            .where(WebhookEndpoint.id == endpoint_id)
            .values(last_triggered_at=_now())
        )
        return delivery


# ── AuditRepository ───────────────────────────────────────────────────────────

class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_org(
        self,
        org_id: str,
        limit: int = 100,
        offset: int = 0,
        action_filter: str | None = None,
        actor_id: str | None = None,
    ) -> list[AuditLog]:
        query = (
            select(AuditLog)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if action_filter:
            query = query.where(AuditLog.action.like(f"{action_filter}%"))
        if actor_id:
            query = query.where(AuditLog.actor_id == actor_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())
