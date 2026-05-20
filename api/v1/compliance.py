"""Compliance report endpoints — /api/v1/compliance.

Provides structured compliance evidence based on scan findings.
Supported frameworks: OWASP ASVS, SOC 2, PCI-DSS.

Reports include:
  - Control status (PASS / FAIL / PARTIAL / NOT_COVERED)
  - Relevant findings per control
  - Evidence trail from scan data
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.rbac import Permission, require_permission
from core.compliance import (
    ComplianceFramework,
    generate_compliance_report,
    SUPPORTED_FRAMEWORKS,
)
from core.entitlements import Feature, check_entitlement, plan_upgrade_message
from db.database import get_session
from db.models import User
from db.repositories import FindingRepository, OrgRepository

router = APIRouter(prefix="/compliance", tags=["compliance"])


class ComplianceControlResult(BaseModel):
    control_id: str
    control_name: str
    status: str  # PASS | FAIL | PARTIAL | NOT_COVERED
    finding_count: int
    critical_count: int
    high_count: int
    findings: list[dict]


class ComplianceReportResponse(BaseModel):
    framework: str
    framework_name: str
    org_id: str
    generated_at: str
    summary: dict
    controls: list[ComplianceControlResult]


@router.get("/frameworks")
async def list_frameworks() -> list[dict]:
    """Return supported compliance frameworks."""
    return [
        {"id": fw.value, "name": fw.label, "description": fw.description}
        for fw in SUPPORTED_FRAMEWORKS
    ]


@router.get("/{framework}", response_model=ComplianceReportResponse)
async def get_compliance_report(
    framework: str,
    target_id: str | None = Query(default=None, description="Filter by target"),
    current_user: User = Depends(require_permission(Permission.REPORTS_READ)),
) -> ComplianceReportResponse:
    """
    Generate a compliance report for the organization's open findings.
    Requires Pro or Enterprise plan.
    """
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org = await org_repo.get_by_id(current_user.org_id)

    if org and not check_entitlement(org.plan, Feature.COMPLIANCE_REPORTS):
        raise HTTPException(
            status_code=402, detail=plan_upgrade_message(org.plan, Feature.COMPLIANCE_REPORTS)
        )

    try:
        fw = ComplianceFramework(framework)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework '{framework}'. Supported: {[fw.value for fw in SUPPORTED_FRAMEWORKS]}",
        )

    # Fetch findings
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        findings = await finding_repo.get_for_org(
            current_user.org_id,
            status="open",
            target_id=target_id,
            limit=5000,
        )

    report = generate_compliance_report(fw, findings, current_user.org_id)
    return report
