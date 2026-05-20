#!/usr/bin/env python
"""
CLI entrypoint for headless / CI scanning.

Usage:
  python cli.py --target https://example.com --tools nmap,nikto --mode quick
  python cli.py --target https://example.com --format json --output report.json
  python cli.py --target https://example.com --threshold high

Exit codes:
  0  — scan complete, no findings at or above threshold
  1  — scan complete, findings at or above threshold (useful in CI pipelines)
  2  — scan failed (all tools failed or critical error)
  3  — invalid arguments or configuration

The --threshold flag maps to Severity: critical | high | medium | low
If not set, always exits 0 on scan completion.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from uuid import uuid4

from core.classifier import classify
from core.config import settings
from core.correlator import annotate_related, correlate
from core.discovery import DiscoveryEngine
from core.parser import parse_raw
from core.schemas import (
    Finding,
    Priority,
    ScanResult,
    ScanStatus,
    Severity,
    ToolName,
)
from core.scorer import PostureScorer, score_finding_extended
from core.stack_detector import detect_stack, is_api_target
from core.storage import ScanStore
from core.verification import VerificationEngine
from reports.markdown_report import generate_report
from scanner.exceptions import ToolUnavailableError
from scanner.nmap_runner import run_nmap
from scanner.nikto_runner import run_nikto
from scanner.zap_runner import run_zap

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}

_RUNNERS = {
    ToolName.ZAP: run_zap,
    ToolName.NMAP: run_nmap,
    ToolName.NIKTO: run_nikto,
}


def _parse_tools(tools_str: str) -> list[ToolName]:
    names = [t.strip().lower() for t in tools_str.split(",") if t.strip()]
    result = []
    for name in names:
        try:
            result.append(ToolName(name))
        except ValueError:
            log.error("Unknown tool: %s. Valid tools: zap, nmap, nikto", name)
            sys.exit(3)
    return result or list(ToolName)


def _threshold_breached(findings: list[Finding], threshold: str) -> bool:
    """Return True if any non-noise, non-duplicate finding meets or exceeds the threshold severity."""
    if not threshold:
        return False
    try:
        threshold_sev = Severity(threshold.lower())
    except ValueError:
        log.error("Invalid threshold: %s. Valid values: critical, high, medium, low", threshold)
        sys.exit(3)

    threshold_rank = _SEVERITY_RANK[threshold_sev]
    for f in findings:
        if f.is_noise or f.duplicate_of:
            continue
        if _SEVERITY_RANK.get(f.severity, 0) >= threshold_rank:
            return True
    return False


def _findings_to_export(scan: ScanResult) -> dict:
    """Structured JSON output for CI/CD integration."""
    active = [f for f in scan.findings if not f.is_noise and not f.duplicate_of]
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "status": scan.status.value,
        "scan_mode": scan.scan_mode,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "detected_stack": scan.detected_stack,
        "summary": {
            "total": len(active),
            "by_severity": scan.severity_summary,
            "by_priority": scan.priority_summary,
            "posture_score": scan.posture_score.model_dump() if scan.posture_score else None,
        },
        "tools": {
            "succeeded": [t.value for t in scan.tools_succeeded],
            "failed": scan.tools_failed,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "host": f.host,
                "port": f.port,
                "path": f.path,
                "severity": f.severity.value,
                "priority": f.priority.value,
                "confidence": f.confidence.value,
                "exploitability": f.exploitability.value,
                "remediation_effort": f.remediation_effort.value,
                "owasp_category": f.owasp_category,
                "owasp_api_category": f.owasp_api_category,
                "cwe_ids": f.cwe_ids,
                "sources": [t.value for t in f.sources],
                "solution": f.solution,
                "tags": f.tags,
                "detected_stack": f.detected_stack,
                "related_findings": f.related_findings,
            }
            for f in active
        ],
    }


async def _run_tool_safe(
    tool: ToolName, target: str, scan_dir: Path, scan_mode: str = "full"
) -> tuple[ToolName, str | None, Exception | None]:
    try:
        if tool == ToolName.NMAP:
            raw_output, _ = await _RUNNERS[tool](target, scan_dir, scan_mode)
        else:
            raw_output, _ = await _RUNNERS[tool](target, scan_dir)
        return tool, raw_output, None
    except ToolUnavailableError as e:
        log.warning("Tool %s not available: %s", tool.value, e)
        return tool, None, e
    except Exception as e:
        log.warning("Tool %s failed: %s", tool.value, e)
        return tool, None, e


async def _scan(
    target: str,
    tools: list[ToolName],
    scan_mode: str,
    store: ScanStore,
) -> ScanResult:
    from datetime import datetime, UTC

    scan_id = str(uuid4())
    scan_dir = store.create_scan_dir(scan_id)

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        status=ScanStatus.RUNNING,
        tools_requested=tools,
        scan_mode=scan_mode,
        started_at=datetime.now(UTC),
    )
    store.save_scan_meta(result)

    log.info("Starting scan %s on %s (mode=%s, tools=%s)", scan_id, target, scan_mode, [t.value for t in tools])

    tasks = [_run_tool_safe(tool, target, scan_dir, scan_mode) for tool in tools]
    tool_results = await asyncio.gather(*tasks)

    tools_succeeded: list[ToolName] = []
    tools_failed: dict[str, str] = {}
    raw_findings = []

    for tool, raw_output, error in tool_results:
        if error:
            tools_failed[tool.value] = str(error)
        else:
            tools_succeeded.append(tool)
            raw_findings.extend(parse_raw(tool, raw_output, scan_id))  # type: ignore[arg-type]

    if not tools_succeeded:
        result.status = ScanStatus.FAILED
        result.error = "All tools failed or were unavailable"
        result.tools_failed = tools_failed
        store.save_scan_meta(result)
        log.error("Scan failed: all tools unavailable")
        return result

    detected_stack = detect_stack(raw_findings, target)
    if detected_stack:
        log.info("Detected stack: %s", detected_stack)

    findings = correlate(raw_findings, scan_id)
    findings = [classify(f) for f in findings]
    findings = annotate_related(findings)
    findings = [score_finding_extended(f) for f in findings]
    if detected_stack:
        findings = [f.model_copy(update={"detected_stack": detected_stack}) for f in findings]

    # ── Posture Intelligence ────────────────────────────────────────────────
    discovery_engine = DiscoveryEngine()
    verification_engine = VerificationEngine()
    posture_scorer = PostureScorer()

    discovery_items = discovery_engine.extract(scan_id, raw_findings)
    verifications = verification_engine.process(scan_id, findings, discovery_items)
    posture_score = posture_scorer.calculate(scan_id, verifications, findings)

    log.info(
        "Posture Intelligence: %d discovery items, %d verifications, Overall Score: %.1f",
        len(discovery_items),
        len(verifications),
        posture_score.overall_score,
    )

    from datetime import datetime, UTC
    completed_at = datetime.now(UTC)

    result.status = ScanStatus.DONE
    result.tools_succeeded = tools_succeeded
    result.tools_failed = tools_failed
    result.findings = findings
    result.detected_stack = detected_stack
    result.verifications = verifications
    result.discovery_items = discovery_items
    result.posture_score = posture_score
    result.completed_at = completed_at
    result.duration_seconds = (completed_at - result.started_at).total_seconds() if result.started_at else None
    result.compute_severity_summary()

    store.save_findings(scan_id, findings)
    store.save_scan_meta(result)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vulnerability Auditor CLI — authorized targets only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--tools", default="nmap,nikto,zap", help="Comma-separated tools (default: all)")
    parser.add_argument("--mode", choices=["quick", "full"], default="full", help="Scan mode")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", dest="fmt")
    parser.add_argument("--output", help="Output file path (default: stdout)")
    parser.add_argument(
        "--threshold",
        choices=["critical", "high", "medium", "low"],
        default=settings.ci_fail_threshold or "",
        help="Exit code 1 if any finding meets or exceeds this severity (CI/CD)",
    )
    parser.add_argument("--data-dir", default=str(settings.data_dir), help="Data directory")
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for authenticating against the VulnAudit API (optional, for API mode)",
    )

    args = parser.parse_args()

    tools = _parse_tools(args.tools)
    store = ScanStore(Path(args.data_dir))

    try:
        scan = asyncio.run(_scan(args.target, tools, args.mode, store))
    except KeyboardInterrupt:
        log.info("Scan interrupted by user")
        sys.exit(2)
    except Exception as e:
        log.error("Scan error: %s", e)
        sys.exit(2)

    if scan.status == ScanStatus.FAILED:
        log.error("Scan failed: %s", scan.error)
        sys.exit(2)

    print(f"\nScan ID: {scan.scan_id}", file=sys.stderr)

    # Generate output
    if args.fmt == "json":
        output = json.dumps(_findings_to_export(scan), indent=2, default=str)
    else:
        output = generate_report(scan)
        report_path = store.save_report(scan.scan_id, output)
        log.info("Report saved to %s", report_path)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        log.info("Output written to %s", args.output)
    else:
        print(output)

    # CI/CD threshold check
    if args.threshold and _threshold_breached(scan.findings, args.threshold):
        log.warning(
            "CI threshold breached: findings at or above '%s' severity detected.", args.threshold
        )
        sys.exit(1)

    # Print summary to stderr so it doesn't pollute piped output
    active = [f for f in scan.findings if not f.is_noise and not f.duplicate_of]
    print(
        f"\nScan complete: {len(active)} finding(s) "
        f"[critical={scan.severity_summary.get('critical', 0)}, "
        f"high={scan.severity_summary.get('high', 0)}, "
        f"medium={scan.severity_summary.get('medium', 0)}]",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
