"""API routes: scan management, findings, targets, dashboard."""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from uuid import uuid4

import anthropic
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from ai.analyzer import get_executive_summary
from ai.fixer import apply_ai_results, get_mitigations
from api.auth import get_current_org
from core.classifier import classify
from core.config import settings
from db.audit import AuditAction, emit_audit
from core.correlator import annotate_related, correlate
from core.diff import DiffEngine
from core.discovery import DiscoveryEngine
from core.parser import parse_raw
from core.schemas import (
    Finding,
    ScanCreated,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ToolName,
)
from core.scorer import PostureScorer, score_finding_extended
from core.stack_detector import detect_stack, is_api_target
from core.storage import ScanStore
from core.verification import VerificationEngine
from db.database import get_session
from db.models import (
    AssetDiscovery,
    Organization,
    PostureScore,
    VerificationRecord,
)
from db.repositories import (
    FindingRepository,
    OrgRepository,
    PostureRepository,
    ScanRepository,
    TargetRepository,
)
from reports.pdf_report import generate_pdf_report
from reports.markdown_report import generate_report
from core.reachability import ReachabilityEngine
from core.remediation import (
    get_remediation_for_finding,
    get_all_templates,
    get_template_by_id,
    filter_snippets_for_stack,
)
from scanner.exceptions import ToolUnavailableError
from scanner.nmap_runner import run_nmap
from scanner.nikto_runner import run_nikto
from scanner.zap_runner import run_zap
from scanner.semgrep_runner import run_semgrep
from scanner.sca_runner import run_trivy_fs, run_npm_audit, run_pip_audit
from scanner.iac_runner import run_checkov
from core.epss import get_epss_scores, epss_risk_level
from core.kev_cache import refresh_kev, is_in_kev, kev_due_date

from core.validator import TargetValidator

log = logging.getLogger(__name__)
router = APIRouter()

# Shared limiter — app.state.limiter must be set in app.py
limiter = Limiter(key_func=get_remote_address)

# Global validator instance configured from settings
target_validator = TargetValidator(
    allowed_hosts=settings.allowed_targets,
    blocked_hosts=settings.blocked_targets,
    allow_private_ips=settings.allow_private_scanning,
)

def get_store() -> ScanStore:
    return ScanStore(settings.data_dir)


_RUNNERS = {
    ToolName.ZAP: run_zap,
    ToolName.NMAP: run_nmap,
    ToolName.NIKTO: run_nikto,
}


async def _run_tool_safe(
    tool: ToolName, target: str, scan_dir: Path, scan_mode: str = "full"
) -> tuple[ToolName, str | None, Exception | None]:
    try:
        if tool == ToolName.NMAP:
            raw_output, _ = await run_nmap(target, scan_dir, scan_mode)
        else:
            raw_output, _ = await _RUNNERS[tool](target, scan_dir)
        return tool, raw_output, None
    except ToolUnavailableError as e:
        log.info("Tool %s unavailable: %s", tool.value, e)
        return tool, None, e
    except Exception as e:
        log.warning("Tool %s failed: %s", tool.value, e)
        return tool, None, e


def _extract_cve_ids(findings: list[Finding]) -> list[str]:
    """Collect CVE IDs from finding references (SCA tools embed them there)."""
    cves: set[str] = set()
    for f in findings:
        for ref in f.references:
            if ref.upper().startswith("CVE-"):
                cves.add(ref.upper())
    return list(cves)


async def _enrich_epss_kev(findings: list[Finding]) -> None:
    """Attach EPSS/KEV risk tags to findings that have CVE references (in-place)."""
    try:
        await refresh_kev()
    except Exception:
        pass

    cve_ids = _extract_cve_ids(findings)
    if not cve_ids:
        return

    epss_map = await get_epss_scores(cve_ids)

    for finding in findings:
        cves_in_finding = [r.upper() for r in finding.references if r.upper().startswith("CVE-")]
        if not cves_in_finding:
            continue
        # Use the highest EPSS score among all CVEs in this finding
        best_score = 0.0
        in_kev = False
        for cve in cves_in_finding:
            score, _ = epss_map.get(cve, (0.0, 0.0))
            if score > best_score:
                best_score = score
            if is_in_kev(cve):
                in_kev = True

        new_tags = list(finding.tags)
        if in_kev and "kev" not in new_tags:
            new_tags.append("kev")
        risk = epss_risk_level(best_score)
        epss_tag = f"epss:{risk}"
        new_tags = [t for t in new_tags if not t.startswith("epss:")] + [epss_tag]
        # Store EPSS score for later retrieval via API
        new_tags = [t for t in new_tags if not t.startswith("epss_score:")] + [f"epss_score:{best_score:.4f}"]
        finding.tags = new_tags


async def run_scan(
    scan_id: str,
    target: str,
    tools: list[ToolName],
    store: ScanStore,
    scan_mode: str = "full",
    org_id: str | None = None,
    target_id: str | None = None,
) -> None:
    """
    Main scan execution. Stores raw files in ScanStore and
    metadata + findings in the database.
    """
    scan_dir = store.create_scan_dir(scan_id)

    def _update_file(status: ScanStatus, **kwargs) -> ScanResult:
        result = store.load_scan_meta(scan_id)
        result.status = status
        for k, v in kwargs.items():
            setattr(result, k, v)
        store.save_scan_meta(result)
        return result

    async def _update_db(status: str, **kwargs) -> None:
        if org_id is None:
            return
        async with get_session() as session:
            scan_repo = ScanRepository(session)
            await scan_repo.update_status(scan_id, status, **kwargs)

    _update_file(ScanStatus.RUNNING, started_at=datetime.now(UTC))
    await _update_db("running", started_at=datetime.now(UTC))

    # ── Phase 1a: Run DAST tools concurrently ─────────────────────────────────
    dast_tools = [t for t in tools if t in (ToolName.ZAP, ToolName.NMAP, ToolName.NIKTO)]
    tasks = [_run_tool_safe(tool, target, scan_dir, scan_mode) for tool in dast_tools]
    tool_results = await asyncio.gather(*tasks)

    tools_succeeded: list[ToolName] = []
    tools_failed: dict[str, str] = {}
    raw_findings = []

    for tool, raw_output, error in tool_results:
        if error is not None:
            tools_failed[tool.value] = str(error)
        else:
            tools_succeeded.append(tool)
            raw_findings.extend(parse_raw(tool, raw_output, scan_id))  # type: ignore[arg-type]

    # ── Phase 1b: Run SAST/SCA/IaC tools (return findings directly) ──────────
    sast_sca_iac_tools = [t for t in tools if t in (
        ToolName.SEMGREP, ToolName.TRIVY, ToolName.NPM_AUDIT,
        ToolName.PIP_AUDIT, ToolName.CHECKOV,
    )]
    if sast_sca_iac_tools:
        # Use target URL host as a path proxy; real FS scanning would need a cloned repo
        sast_tasks = []
        for tool in sast_sca_iac_tools:
            if tool == ToolName.SEMGREP:
                sast_tasks.append((tool, run_semgrep(scan_dir, scan_id)))
            elif tool == ToolName.TRIVY:
                sast_tasks.append((tool, run_trivy_fs(scan_dir, scan_id)))
            elif tool == ToolName.NPM_AUDIT:
                sast_tasks.append((tool, run_npm_audit(scan_dir, scan_id)))
            elif tool == ToolName.PIP_AUDIT:
                sast_tasks.append((tool, run_pip_audit(scan_dir, scan_id)))
            elif tool == ToolName.CHECKOV:
                sast_tasks.append((tool, run_checkov(scan_dir, scan_id)))

        for tool, coro in sast_tasks:
            try:
                findings_direct = await coro
                if findings_direct:
                    tools_succeeded.append(tool)
                    raw_findings.extend(findings_direct)
                else:
                    tools_failed[tool.value] = "no findings or tool unavailable"
            except Exception as e:
                log.warning("Tool %s failed: %s", tool.value, e)
                tools_failed[tool.value] = str(e)

    if not tools_succeeded and not raw_findings:
        _update_file(
            ScanStatus.FAILED,
            error="All tools failed or were unavailable",
            tools_failed=tools_failed,
        )
        await _update_db(
            "failed",
            error="All tools failed or were unavailable",
            tools_failed=tools_failed,
        )
        return

    # ── Phase 2: Stack detection ───────────────────────────────────────────────
    detected_stack = detect_stack(raw_findings, target)
    target_is_api = is_api_target(raw_findings, target)
    log.info("Detected stack: %s | API target: %s", detected_stack, target_is_api)

    # ── Phase 3: Correlate → Classify → Annotate → Score ──────────────────────
    findings = correlate(raw_findings, scan_id)
    findings = [classify(f) for f in findings]
    findings = annotate_related(findings)
    findings = [score_finding_extended(f) for f in findings]

    # ── Phase 3.4: Reachability Analysis ─────────────────────────────────────
    reachability_engine = ReachabilityEngine()
    reachability_results = reachability_engine.analyze(findings)
    findings = reachability_engine.apply_multipliers(findings, reachability_results)

    if detected_stack:
        findings = [f.model_copy(update={"detected_stack": detected_stack}) for f in findings]

    # ── Phase 3.45: EPSS/KEV enrichment ──────────────────────────────────────
    await _enrich_epss_kev(findings)

    # ── Phase 3.5: Posture Intelligence ──────────────────────────────────────
    discovery_engine = DiscoveryEngine()
    verification_engine = VerificationEngine()
    posture_scorer = PostureScorer()
    diff_engine = DiffEngine()

    discovery_items = discovery_engine.extract(scan_id, raw_findings)
    verifications = verification_engine.process(scan_id, findings, discovery_items)
    posture_score = posture_scorer.calculate(scan_id, verifications, findings)

    # ── Historical Diff ───────────────────────────────────────────────────────
    posture_diff = None
    if org_id and target_id:
        try:
            async with get_session() as session:
                posture_repo = PostureRepository(session)
                prev_score = await posture_repo.get_previous_score(target_id, scan_id)
                if prev_score:
                    # Map db.models.PostureScore back to core.schemas.PostureScore for the engine
                    prev_score_schema = PostureScore(
                        scan_id=prev_score.scan_id,
                        overall_score=prev_score.overall_score,
                        domain_scores=prev_score.domain_scores,
                        coverage_score=prev_score.coverage_score,
                        confidence_score=prev_score.confidence_score,
                        exposure_score=prev_score.exposure_score,
                        created_at=prev_score.created_at,
                    )
                    prev_verifs_db = await posture_repo.get_verifications(prev_score.scan_id)
                    # Convert to schema
                    prev_verifs = [
                        VerificationRecord(
                            id=v.id,
                            scan_id=v.scan_id,
                            control_id=v.control_id,
                            status=v.status,  # Enum will handle string automatically in Pydantic
                            evidence_summary=v.evidence_summary,
                            metadata=v.metadata_json or {},
                        )
                        for v in prev_verifs_db
                    ]
                    posture_diff = diff_engine.calculate(
                        scan_id,
                        posture_score,
                        verifications,
                        prev_score.scan_id,
                        prev_score_schema,
                        prev_verifs
                    )
        except Exception as e:
            log.warning("Failed to calculate historical diff: %s", e)

    log.info(
        "Posture Intelligence: %d discovery items, %d verifications, Overall Score: %.1f (Diff: %s)",
        len(discovery_items),
        len(verifications),
        posture_score.overall_score,
        f"{posture_diff.score_trend.overall_change:+.1f}" if posture_diff and posture_diff.score_trend else "Baseline",
    )

    result = store.load_scan_meta(scan_id)
    result.tools_succeeded = tools_succeeded
    result.tools_failed = tools_failed
    result.findings = findings
    result.detected_stack = detected_stack
    result.verifications = verifications
    result.discovery_items = discovery_items
    result.posture_score = posture_score
    result.posture_diff = posture_diff
    result.scan_mode = scan_mode
    result.compute_severity_summary()
    store.save_findings(scan_id, findings)

    # ── Phase 4: AI analysis (optional) ───────────────────────────────────────
    ai_summary = ""
    if settings.anthropic_api_key or settings.gemini_api_key:
        _update_file(ScanStatus.ANALYZING)
        try:
            mitigations = await get_mitigations(findings, settings)
            ai_summary = await get_executive_summary(findings, settings)
            findings = apply_ai_results(findings, mitigations, ai_summary)
            store.save_findings(scan_id, findings)
        except Exception as e:
            log.warning("AI analysis failed (non-fatal): %s", e)

    # ── Phase 5: Report ────────────────────────────────────────────────────────
    result.findings = findings
    result.compute_severity_summary()
    result.ai_executive_summary = ai_summary or None
    result.ai_generated = bool(ai_summary)

    report_content = generate_report(result)
    report_path = store.save_report(scan_id, report_content)

    completed_at = datetime.now(UTC)
    started_at = result.started_at or completed_at
    duration = (completed_at - started_at).total_seconds()

    result.status = ScanStatus.DONE
    result.completed_at = completed_at
    result.duration_seconds = duration
    result.report_path = str(report_path)
    store.save_scan_meta(result)

    # ── Phase 6: Persist to DB ─────────────────────────────────────────────────
    new_count = 0
    regressed_count = 0
    if org_id and target_id:
        try:
            async with get_session() as session:
                finding_repo = FindingRepository(session)
                for finding in findings:
                    if finding.is_noise or finding.duplicate_of:
                        continue
                    record, is_new, is_regressed = await finding_repo.upsert_finding(
                        finding, scan_id, org_id, target_id
                    )
                    await finding_repo.link_to_scan(
                        record.id,
                        scan_id,
                        is_new,
                        is_regressed,
                        {
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value,
                            "evidence": finding.evidence,
                        },
                    )
                    if is_new:
                        new_count += 1
                    if is_regressed:
                        regressed_count += 1

            async with get_session() as session:
                target_repo = TargetRepository(session)
                await target_repo.update_last_scan(target_id, scan_id)

                org_repo = OrgRepository(session)
                await org_repo.increment_scan_count(org_id)

                posture_repo = PostureRepository(session)
                # Save Discovery Items
                db_discovery = [
                    AssetDiscovery(
                        id=d.id,
                        scan_id=scan_id,
                        type=d.type.value,
                        data=d.data,
                        confidence=d.confidence.value,
                        discovered_at=d.discovered_at,
                    )
                    for d in discovery_items
                ]
                await posture_repo.save_discovery_items(db_discovery)

                # Save Verifications
                db_verifications = [
                    VerificationRecord(
                        id=v.id,
                        scan_id=scan_id,
                        control_id=v.control_id,
                        status=v.status.value,
                        evidence_summary=v.evidence_summary,
                        metadata_json=v.metadata,
                    )
                    for v in verifications
                ]
                await posture_repo.save_verifications(db_verifications)

                # Save Posture Score
                db_score = PostureScore(
                    id=str(uuid4()),
                    scan_id=scan_id,
                    overall_score=posture_score.overall_score,
                    domain_scores=posture_score.domain_scores,
                    coverage_score=posture_score.coverage_score,
                    confidence_score=posture_score.confidence_score,
                    exposure_score=posture_score.exposure_score,
                    created_at=posture_score.created_at,
                )
                await posture_repo.save_posture_score(db_score)

        except Exception as e:
            log.warning("DB persistence failed (non-fatal): %s", e)

    await _update_db(
        "done",
        tools_succeeded=[t.value for t in tools_succeeded],
        tools_failed=tools_failed,
        detected_stack=detected_stack,
        severity_summary=result.severity_summary,
        priority_summary=result.priority_summary,
        finding_count=len([f for f in findings if not f.is_noise and not f.duplicate_of]),
        new_finding_count=new_count,
        regressed_finding_count=regressed_count,
        ai_executive_summary=ai_summary or None,
        ai_generated=bool(ai_summary),
        report_path=str(report_path),
        completed_at=completed_at,
        duration_seconds=duration,
    )

    log.info(
        "Scan %s completed in %.1fs — %d findings (%d new, %d regressed, stack: %s)",
        scan_id,
        duration,
        len(findings),
        new_count,
        regressed_count,
        detected_stack or "unknown",
    )


# ── Pydantic request/response models ──────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str
    name: str
    tags: list[str] = []
    schedule: str | None = None


class TargetResponse(BaseModel):
    id: str
    org_id: str
    url: str
    name: str
    tags: list[str]
    schedule: str | None
    created_at: datetime
    last_scan_at: datetime | None
    scan_count: int

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: str
    org_id: str
    target_id: str | None
    status: str
    scan_mode: str
    finding_count: int
    new_finding_count: int
    regressed_finding_count: int
    severity_summary: dict[str, Any]
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    ai_generated: bool


class FindingResponse(BaseModel):
    id: str
    org_id: str
    target_id: str
    global_fingerprint: str
    title: str
    description: str
    host: str
    port: int | None
    path: str
    severity: str
    priority: str
    confidence: str
    status: str
    owasp_category: str | None
    cwe_ids: list[int]
    sources: list[str]
    evidence: str | None
    solution: str | None
    ai_mitigation: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_noise: bool


class FindingStatusUpdate(BaseModel):
    status: str
    note: str | None = None


class OrgCreate(BaseModel):
    name: str
    plan: str = "free"


class OrgResponse(BaseModel):
    id: str
    name: str
    plan: str
    scan_quota: int
    scans_this_month: int
    quota_reset_at: datetime
    created_at: datetime


def _serialize_scan(record) -> ScanSummary:
    return ScanSummary(
        id=record.id,
        org_id=record.org_id,
        target_id=record.target_id,
        status=record.status,
        scan_mode=record.scan_mode,
        finding_count=record.finding_count,
        new_finding_count=record.new_finding_count,
        regressed_finding_count=record.regressed_finding_count,
        severity_summary=_parse_json(record.severity_summary, {}),
        started_at=record.started_at,
        completed_at=record.completed_at,
        duration_seconds=record.duration_seconds,
        ai_generated=record.ai_generated,
    )


def _serialize_finding(record) -> FindingResponse:
    return FindingResponse(
        id=record.id,
        org_id=record.org_id,
        target_id=record.target_id,
        global_fingerprint=record.global_fingerprint,
        title=record.title,
        description=record.description,
        host=record.host,
        port=record.port,
        path=record.path,
        severity=record.severity,
        priority=record.priority,
        confidence=record.confidence,
        status=record.status,
        owasp_category=record.owasp_category,
        cwe_ids=_parse_json(record.cwe_ids, []),
        sources=_parse_json(record.sources, []),
        evidence=record.evidence,
        solution=record.solution,
        ai_mitigation=record.ai_mitigation,
        first_seen_at=record.first_seen_at,
        last_seen_at=record.last_seen_at,
        is_noise=record.is_noise,
    )


def _serialize_target(record, open_count: int = 0) -> dict:
    return {
        "id": record.id,
        "org_id": record.org_id,
        "url": record.url,
        "name": record.name,
        "tags": _parse_json(record.tags, []),
        "schedule": record.schedule,
        "created_at": record.created_at,
        "last_scan_at": record.last_scan_at,
        "scan_count": record.scan_count,
        "open_finding_count": open_count,
    }


def _parse_json(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


@router.post("/scans/api", status_code=202)
async def create_api_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    org: Organization = Depends(get_current_org),
) -> ScanCreated:
    """Specialized endpoint for API auditing via OpenAPI/Swagger specs."""
    if not body.openapi_spec_url:
        raise HTTPException(status_code=400, detail="openapi_spec_url is required for API scans")
    
    # Logic to import OpenAPI into ZAP or specialized tools...
    # For now, we reuse the existing engine but flag it as API target
    return await create_scan(request=None, body=body, background_tasks=background_tasks, org=org)


# ── Legacy / existing endpoints ────────────────────────────────────────────────

@router.post("/scan", response_model=ScanCreated, status_code=202)
@limiter.limit(settings.rate_limit_scan_create)
async def create_scan(
    request: Request,
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    store: ScanStore = Depends(get_store),
    org: Organization = Depends(get_current_org),
) -> ScanCreated:
    # Check quota
    async with get_session() as session:
        org_repo = OrgRepository(session)
        within_quota = await org_repo.check_quota(org.id)
    if not within_quota:
        raise HTTPException(
            status_code=429,
            detail="Monthly scan quota exceeded. Upgrade your plan or wait for quota reset.",
        )

    scan_id = str(uuid4())
    target_url = str(body.target_url)

    # ── Target Validation ──────────────────────────────────────────────────────
    val_result = target_validator.validate_url(target_url)
    if not val_result.is_valid:
        log.warning("Scan rejected for invalid target %s: %s", target_url, val_result.reason)
        raise HTTPException(
            status_code=400,
            detail=f"Target validation failed: {val_result.reason}"
        )

    # Get or create target in DB
    # Get or create target in DB
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target_name = getattr(body, "target_name", None) or target_url
        target = await target_repo.get_or_create(org.id, target_url, target_name)
        target_id = target.id


    # Create scan record in DB
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        await scan_repo.create(
            scan_id,
            org.id,
            target_id,
            [t.value for t in body.tools],
            body.scan_mode,
        )

    # Create file-based scan record for backward compat
    store.create_scan_dir(scan_id)
    result = ScanResult(
        scan_id=scan_id,
        target=target_url,
        status=ScanStatus.PENDING,
        tools_requested=body.tools,
        scan_mode=body.scan_mode,
    )
    store.save_scan_meta(result)

    # ── Job Enqueue ────────────────────────────────────────────────────────────
    # For Enterprise: Enqueue in a persistent distributed queue (arq/Redis)
    # We fallback to BackgroundTasks if Redis is unavailable.
    try:
        from core.worker import get_redis_pool
        redis = await get_redis_pool()
        await redis.enqueue_job(
            "run_scan_task",
            scan_id=scan_id,
            target_url=target_url,
            tools=body.tools,
            scan_mode=body.scan_mode,
            org_id=org.id,
            target_id=target_id
        )
        log.info("Scan %s enqueued in distributed queue (arq)", scan_id)
    except Exception as e:
        log.warning("Distributed queue unavailable, using fallback BackgroundTasks: %s", e)
        background_tasks.add_task(
            run_scan,
            scan_id,
            target_url,
            body.tools,
            store,
            body.scan_mode,
            org.id,
            target_id,
        )

    log.info(
        "Scan %s created — org=%s target=%s tools=%s mode=%s",
        scan_id,
        org.id,
        target_url,
        [t.value for t in body.tools],
        body.scan_mode,
    )

    await emit_audit(
        action=AuditAction.SCAN_CREATED,
        org_id=org.id,
        resource_type="scan",
        resource_id=scan_id,
        request=request,
        details={"target": target_url, "tools": [t.value for t in body.tools], "mode": body.scan_mode},
    )

    return ScanCreated(
        scan_id=scan_id,
        target=target_url,
        poll_url=f"/scan/{scan_id}",
    )


@router.get("/scan", response_model=list[ScanSummary])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=500),
    org: Organization = Depends(get_current_org),
) -> list[ScanSummary]:
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        scans = await scan_repo.list_for_org(org.id, limit=limit)
        return [_serialize_scan(s) for s in scans]


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, store: ScanStore = Depends(get_store)) -> ScanResult:
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return store.load_full_scan(scan_id)


@router.get("/posture/trend")
async def get_posture_trend(
    target_id: str | None = Query(default=None),
    limit: int = Query(default=30, ge=1, le=90),
    org: Organization = Depends(get_current_org),
) -> list[dict]:
    """Return posture score trend for a target or the whole org."""
    async with get_session() as session:
        posture_repo = PostureRepository(session)
        if target_id:
            target_repo = TargetRepository(session)
            target = await target_repo.get(org.id, target_id)
            if target is None:
                raise HTTPException(status_code=404, detail="Target not found")
            return await posture_repo.get_trend_for_target(target_id, limit=limit)
        return await posture_repo.get_trend_for_org(org.id, limit=limit)


@router.get("/report/{scan_id}/pdf")
@limiter.limit(settings.rate_limit_report_export)
async def get_pdf_report(scan_id: str, request: Request, store: ScanStore = Depends(get_store)) -> Response:
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    meta = store.load_scan_meta(scan_id)
    if meta.status not in (ScanStatus.DONE, ScanStatus.PARTIAL):
        raise HTTPException(status_code=425, detail=f"Scan not complete yet: {meta.status.value}")

    result = store.load_full_scan(scan_id)
    pdf_bytes = generate_pdf_report(result)

    await emit_audit(
        action=AuditAction.REPORT_EXPORTED,
        resource_type="scan",
        resource_id=scan_id,
        request=request,
        details={"format": "pdf"},
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id[:8]}.pdf"'},
    )


@router.get("/report/{scan_id}")
async def get_report(scan_id: str, store: ScanStore = Depends(get_store)) -> Response:
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    meta = store.load_scan_meta(scan_id)
    if meta.status not in (ScanStatus.DONE, ScanStatus.PARTIAL):
        raise HTTPException(status_code=425, detail=f"Scan not complete yet: {meta.status.value}")

    try:
        content = store.load_report(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    return Response(content=content, media_type="text/markdown")


@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": "0.3.0",
        "tools_available": {
            "zap": bool(shutil.which("zap.sh") or shutil.which("zaproxy") or settings.zap_api_url),
            "nmap": bool(shutil.which("nmap")),
            "nikto": bool(shutil.which("nikto")),
        },
        "ai_enabled": bool(settings.anthropic_api_key or settings.gemini_api_key),
        "ci_threshold": settings.ci_fail_threshold or "disabled",
    }


# ── Target endpoints ───────────────────────────────────────────────────────────

@router.get("/targets")
async def list_targets(org: Organization = Depends(get_current_org)) -> list[dict]:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        finding_repo = FindingRepository(session)
        targets = await target_repo.list_for_org(org.id)

        result = []
        for t in targets:
            open_findings = await finding_repo.get_for_target(t.id, status="open")
            result.append(_serialize_target(t, len(open_findings)))
        return result


@router.post("/targets", status_code=201)
async def create_target(
    body: TargetCreate,
    org: Organization = Depends(get_current_org),
) -> dict:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get_or_create(org.id, body.url, body.name)
        return _serialize_target(target)


@router.delete("/targets/{target_id}", status_code=204)
async def delete_target(
    target_id: str,
    request: Request,
    org: Organization = Depends(get_current_org),
) -> None:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get(org.id, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")
        target_name = target.name
        await session.delete(target)

    await emit_audit(
        action=AuditAction.TARGET_DELETED,
        org_id=org.id,
        resource_type="target",
        resource_id=target_id,
        request=request,
        details={"name": target_name},
    )


@router.put("/targets/{target_id}")
async def update_target(
    target_id: str,
    body: TargetCreate,
    org: Organization = Depends(get_current_org),
) -> dict:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get(org.id, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")
        target.name = body.name
        target.schedule = body.schedule
        import json as _json
        target.tags = _json.dumps(body.tags)
        await session.flush()
        return _serialize_target(target)


@router.get("/targets/{target_id}")
async def get_target(
    target_id: str,
    org: Organization = Depends(get_current_org),
) -> dict:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get(org.id, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        finding_repo = FindingRepository(session)
        open_findings = await finding_repo.get_for_target(target_id, status="open")
        return _serialize_target(target, len(open_findings))


@router.get("/targets/{target_id}/scans")
async def list_target_scans(
    target_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    org: Organization = Depends(get_current_org),
) -> list[ScanSummary]:
    # Verify ownership
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get(org.id, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        scan_repo = ScanRepository(session)
        scans = await scan_repo.list_for_target(target_id, limit=limit)
        return [_serialize_scan(s) for s in scans]


@router.get("/targets/{target_id}/findings")
async def list_target_findings(
    target_id: str,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    org: Organization = Depends(get_current_org),
) -> list[FindingResponse]:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        target = await target_repo.get(org.id, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")

        finding_repo = FindingRepository(session)
        findings = await finding_repo.get_for_target(target_id, status=status)
        if severity:
            findings = [f for f in findings if f.severity == severity]
        return [_serialize_finding(f) for f in findings]


# ── Finding endpoints ──────────────────────────────────────────────────────────

@router.get("/findings")
async def list_findings(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    target_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    org: Organization = Depends(get_current_org),
) -> list[FindingResponse]:
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        findings = await finding_repo.get_for_org(
            org.id,
            status=status,
            severity=severity,
            target_id=target_id,
            limit=limit,
            offset=offset,
        )
        return [_serialize_finding(f) for f in findings]


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    org: Organization = Depends(get_current_org),
) -> FindingResponse:
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        record = await finding_repo.get(finding_id, org.id)
        if record is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return _serialize_finding(record)


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    request: Request,
    org: Organization = Depends(get_current_org),
) -> FindingResponse:
    valid_statuses = {"open", "acknowledged", "resolved", "false_positive", "retest_needed"}
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}",
        )
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        record = await finding_repo.update_status(finding_id, org.id, body.status, body.note)
        if record is None:
            raise HTTPException(status_code=404, detail="Finding not found")

    await emit_audit(
        action=AuditAction.FINDING_STATUS_CHANGED,
        org_id=org.id,
        resource_type="finding",
        resource_id=finding_id,
        request=request,
        details={"new_status": body.status},
    )

    return _serialize_finding(record)


@router.get("/findings/{finding_id}/history")
async def get_finding_history(
    finding_id: str,
    org: Organization = Depends(get_current_org),
) -> list[dict]:
    async with get_session() as session:
        # Verify ownership first
        finding_repo = FindingRepository(session)
        record = await finding_repo.get(finding_id, org.id)
        if record is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        history = await finding_repo.get_status_history(finding_id)
        return [
            {
                "id": h.id,
                "finding_id": h.finding_id,
                "scan_id": h.scan_id,
                "status_from": h.status_from,
                "status_to": h.status_to,
                "severity_from": h.severity_from,
                "severity_to": h.severity_to,
                "changed_at": h.changed_at,
                "note": h.note,
            }
            for h in history
        ]


# ── Scan diff endpoint ─────────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/diff")
async def get_scan_diff(
    scan_id: str,
    org: Organization = Depends(get_current_org),
) -> dict:
    """
    Compare this scan with the previous scan for the same target.
    Returns new, resolved, and regressed findings, plus unchanged count.
    """
    async with get_session() as session:
        scan_repo = ScanRepository(session)
        scan = await scan_repo.get(scan_id)
        if scan is None or scan.org_id != org.id:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.target_id is None:
            return {
                "message": "No target associated with this scan — diff not available",
                "new_findings": [],
                "resolved_findings": [],
                "regressed_findings": [],
                "unchanged_count": 0,
            }

        prev_scan = await scan_repo.get_previous_scan(scan.target_id, scan_id)
        if prev_scan is None:
            return {
                "message": "No previous scan found for this target",
                "new_findings": [],
                "resolved_findings": [],
                "regressed_findings": [],
                "unchanged_count": 0,
            }

        finding_repo = FindingRepository(session)

        # Findings in current scan
        current_links = await finding_repo.get_scan_finding_links(scan_id)
        current_finding_ids = {lnk.finding_id for lnk in current_links}
        new_links = [lnk for lnk in current_links if lnk.is_new]
        regressed_links = [lnk for lnk in current_links if lnk.is_regressed]

        # Findings in previous scan but not in current
        prev_links = await finding_repo.get_scan_finding_links(prev_scan.id)
        prev_finding_ids = {lnk.finding_id for lnk in prev_links}
        resolved_ids = prev_finding_ids - current_finding_ids

        async def _fetch_findings(ids):
            results = []
            for fid in ids:
                f = await finding_repo.get(fid, org.id)
                if f:
                    results.append(_serialize_finding(f))
            return results

        new_findings = await _fetch_findings({lnk.finding_id for lnk in new_links})
        regressed_findings = await _fetch_findings({lnk.finding_id for lnk in regressed_links})
        resolved_findings = await _fetch_findings(resolved_ids)
        unchanged_count = len(current_finding_ids) - len(new_links) - len(regressed_links)

        return {
            "scan_id": scan_id,
            "previous_scan_id": prev_scan.id,
            "new_findings": [f.model_dump() for f in new_findings],
            "resolved_findings": [f.model_dump() for f in resolved_findings],
            "regressed_findings": [f.model_dump() for f in regressed_findings],
            "unchanged_count": max(0, unchanged_count),
        }


# ── Dashboard endpoint ─────────────────────────────────────────────────────────

@router.get("/dashboard")
async def get_dashboard(org: Organization = Depends(get_current_org)) -> dict:
    async with get_session() as session:
        target_repo = TargetRepository(session)
        scan_repo = ScanRepository(session)
        finding_repo = FindingRepository(session)

        targets = await target_repo.list_for_org(org.id)
        scans = await scan_repo.list_for_org(org.id, limit=5)
        open_by_severity = await finding_repo.get_open_count_by_severity(org.id)

        # Top 3 targets by open finding count
        target_risk = []
        for t in targets:
            open_findings = await finding_repo.get_for_target(t.id, status="open")
            critical_high = sum(
                1 for f in open_findings if f.severity in ("critical", "high")
            )
            target_risk.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "url": t.url,
                    "open_findings": len(open_findings),
                    "critical_high": critical_high,
                }
            )
        target_risk.sort(key=lambda x: (-x["critical_high"], -x["open_findings"]))
        top_targets = target_risk[:3]

        total_scans_all = await scan_repo.list_for_org(org.id, limit=10000)

        return {
            "org": {
                "id": org.id,
                "name": org.name,
                "plan": org.plan,
                "scans_this_month": org.scans_this_month,
                "scan_quota": org.scan_quota,
            },
            "total_targets": len(targets),
            "total_scans": len(total_scans_all),
            "open_findings_by_severity": open_by_severity,
            "recent_scans": [_serialize_scan(s).model_dump() for s in scans],
            "top_targets_by_risk": top_targets,
        }


# ── Org endpoints ──────────────────────────────────────────────────────────────

@router.post("/orgs", status_code=201)
async def create_org(body: OrgCreate) -> dict:
    """Create a new organization. Returns the raw API key ONCE."""
    async with get_session() as session:
        org_repo = OrgRepository(session)
        org, raw_key = await org_repo.create_org(body.name, body.plan)
        return {
            "id": org.id,
            "name": org.name,
            "plan": org.plan,
            "scan_quota": org.scan_quota,
            "api_key": raw_key,
            "warning": "Store this API key securely — it will not be shown again.",
        }


# ── Reachability endpoint ──────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/reachability")
async def get_scan_reachability(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> list[dict]:
    """Return reachability analysis for all findings in a scan."""
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    result = store.load_full_scan(scan_id)
    engine = ReachabilityEngine()
    reach_results = engine.analyze(result.findings or [])
    return [
        {
            "finding_id": r.finding_id,
            "path": r.path,
            "method": r.method,
            "exposure_level": r.exposure_level.value,
            "requires_auth": r.requires_auth,
            "is_api_endpoint": r.is_api_endpoint,
            "is_public": r.is_public,
            "risk_multiplier": r.risk_multiplier,
            "rationale": r.rationale,
        }
        for r in reach_results
    ]


# ── Remediation endpoints ──────────────────────────────────────────────────────

@router.get("/remediation/templates")
async def list_remediation_templates() -> list[dict]:
    """List all available remediation templates."""
    return [
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "effort": t.effort,
            "owasp_refs": t.owasp_refs,
            "cwe_refs": t.cwe_refs,
            "stacks": [s.stack for s in t.stacks],
        }
        for t in get_all_templates()
    ]


@router.get("/findings/{finding_id}/remediation")
async def get_finding_remediation(
    finding_id: str,
    org: Organization = Depends(get_current_org),
) -> list[dict]:
    """Return stack-specific remediation snippets for a finding."""
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        record = await finding_repo.get(finding_id, org.id)
        if record is None:
            raise HTTPException(status_code=404, detail="Finding not found")

    import json as _json

    class _FakeFinding:
        id = record.id
        owasp_category = record.owasp_category
        cwe_ids = _json.loads(record.cwe_ids) if isinstance(record.cwe_ids, str) else (record.cwe_ids or [])
        detected_stack = _json.loads(record.detected_stack) if isinstance(record.detected_stack, str) else (record.detected_stack or [])

    templates = get_remediation_for_finding(_FakeFinding())  # type: ignore[arg-type]
    result = []
    for t in templates:
        snippets = filter_snippets_for_stack(t, _FakeFinding.detected_stack)
        result.append({
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "effort": t.effort,
            "owasp_refs": t.owasp_refs,
            "cwe_refs": t.cwe_refs,
            "snippets": [
                {
                    "stack": s.stack,
                    "language": s.language,
                    "label": s.label,
                    "code": s.code,
                }
                for s in snippets
            ],
        })
    return result


# ── CI/CD Templates endpoint ───────────────────────────────────────────────────

@router.get("/ci/templates")
async def list_ci_templates() -> list[dict]:
    """List available CI/CD integration templates."""
    return [
        {"provider": "github-actions", "label": "GitHub Actions", "file": "github-actions.yml"},
        {"provider": "gitlab-ci",      "label": "GitLab CI",      "file": "gitlab-ci.yml"},
        {"provider": "jenkins",        "label": "Jenkins",         "file": "Jenkinsfile"},
        {"provider": "circleci",       "label": "CircleCI",        "file": "circleci-config.yml"},
    ]


@router.get("/ci/templates/{provider}")
async def get_ci_template(provider: str) -> dict:
    """Return the raw template content for a CI/CD provider."""
    valid = {
        "github-actions": "github-actions.yml",
        "gitlab-ci":      "gitlab-ci.yml",
        "jenkins":        "Jenkinsfile",
        "circleci":       "circleci-config.yml",
    }
    if provider not in valid:
        raise HTTPException(status_code=404, detail=f"Unknown provider '{provider}'. Valid: {list(valid)}")

    template_path = Path(__file__).parent.parent / "ci-templates" / valid[provider]
    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Template file not found")

    return {
        "provider": provider,
        "label": {"github-actions": "GitHub Actions", "gitlab-ci": "GitLab CI",
                  "jenkins": "Jenkins", "circleci": "CircleCI"}[provider],
        "filename": valid[provider],
        "content": template_path.read_text(),
    }


# ── EPSS / KEV endpoints ──────────────────────────────────────────────────────

def _epss_result_for_finding(record) -> dict:
    import json as _json
    cwe_ids = _json.loads(record.cwe_ids) if isinstance(record.cwe_ids, str) else (record.cwe_ids or [])
    references = _json.loads(record.references) if isinstance(record.references, str) else (record.references or [])
    # Extract CVEs from references
    cves = [r for r in references if str(r).upper().startswith("CVE-")]
    return {"cves": cves, "finding_id": record.id}


@router.get("/findings/{finding_id}/epss")
async def get_finding_epss(
    finding_id: str,
    org: Organization = Depends(get_current_org),
) -> dict:
    async with get_session() as session:
        finding_repo = FindingRepository(session)
        record = await finding_repo.get(finding_id, org.id)
        if record is None:
            raise HTTPException(status_code=404, detail="Finding not found")

    import json as _json
    references = _json.loads(record.references) if isinstance(record.references, str) else (record.references or [])
    cves = [r.upper() for r in references if str(r).upper().startswith("CVE-")]

    if not cves:
        return {
            "finding_id": finding_id,
            "cve_id": None,
            "epss_score": None,
            "percentile": None,
            "in_kev": False,
            "kev_due_date": None,
            "risk_level": "none",
        }

    await refresh_kev()
    epss_map = await get_epss_scores(cves)

    best_cve = None
    best_score = -1.0
    best_pct = 0.0
    for cve in cves:
        score, pct = epss_map.get(cve, (0.0, 0.0))
        if score > best_score:
            best_score = score
            best_pct = pct
            best_cve = cve

    in_kev_flag = any(is_in_kev(c) for c in cves)
    due = next((kev_due_date(c) for c in cves if is_in_kev(c)), None)

    return {
        "finding_id": finding_id,
        "cve_id": best_cve,
        "epss_score": best_score if best_score >= 0 else None,
        "percentile": best_pct if best_pct > 0 else None,
        "in_kev": in_kev_flag,
        "kev_due_date": due,
        "risk_level": epss_risk_level(max(best_score, 0.0)),
    }


@router.get("/scan/{scan_id}/epss")
async def get_scan_epss(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> list[dict]:
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    result = store.load_full_scan(scan_id)
    await refresh_kev()

    all_cves = _extract_cve_ids(result.findings or [])
    epss_map = await get_epss_scores(all_cves) if all_cves else {}

    output = []
    for finding in result.findings or []:
        cves = [r.upper() for r in finding.references if r.upper().startswith("CVE-")]
        if not cves:
            continue
        best_cve = None
        best_score = -1.0
        best_pct = 0.0
        for cve in cves:
            score, pct = epss_map.get(cve, (0.0, 0.0))
            if score > best_score:
                best_score = score
                best_pct = pct
                best_cve = cve
        in_kev_flag = any(is_in_kev(c) for c in cves)
        due = next((kev_due_date(c) for c in cves if is_in_kev(c)), None)
        output.append({
            "finding_id": finding.id,
            "cve_id": best_cve,
            "epss_score": best_score if best_score >= 0 else None,
            "percentile": best_pct if best_pct > 0 else None,
            "in_kev": in_kev_flag,
            "kev_due_date": due,
            "risk_level": epss_risk_level(max(best_score, 0.0)),
        })
    return output


# ── ASPM Coverage endpoint ────────────────────────────────────────────────────

@router.get("/scan/{scan_id}/aspm-coverage")
async def get_aspm_coverage(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> dict:
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    result = store.load_full_scan(scan_id)
    succeeded = set(result.tools_succeeded or [])

    dast_tools = {ToolName.ZAP, ToolName.NMAP, ToolName.NIKTO}
    sast_tools = {ToolName.SEMGREP}
    sca_tools = {ToolName.TRIVY, ToolName.NPM_AUDIT, ToolName.PIP_AUDIT}
    iac_tools = {ToolName.CHECKOV}

    return {
        "dast": bool(succeeded & dast_tools),
        "sast": bool(succeeded & sast_tools),
        "sca": bool(succeeded & sca_tools),
        "iac": bool(succeeded & iac_tools),
        "tools_used": [t.value for t in succeeded],
    }


@router.get("/orgs/me")
async def get_current_org_info(org: Organization = Depends(get_current_org)) -> OrgResponse:
    return OrgResponse(
        id=org.id,
        name=org.name,
        plan=org.plan,
        scan_quota=org.scan_quota,
        scans_this_month=org.scans_this_month,
        quota_reset_at=org.quota_reset_at,
        created_at=org.created_at,
    )
