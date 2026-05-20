"""
Webhook and integration engine for external notifications.
Supports Slack, Generic Webhooks, and prepares for Jira.
"""
from __future__ import annotations

import json
import logging
import httpx
from typing import Any

from core.config import settings
from core.schemas import Finding, ScanResult, Severity

log = logging.getLogger(__name__)

async def notify_finding_critical(finding: Finding, target_name: str) -> None:
    """Sends immediate notification for Critical/High findings."""
    if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
        return

    payload = {
        "event": "finding.critical",
        "severity": finding.severity.value,
        "title": finding.title,
        "target": target_name,
        "path": finding.path,
        "risk_score": getattr(finding, "business_risk_score", "N/A"),
        "url": f"{settings.project_name} finding check"
    }
    
    # Generic Webhook
    webhook_url = getattr(settings, "notification_webhook_url", None)
    if webhook_url:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(webhook_url, json=payload, timeout=5.0)
        except Exception as e:
            log.warning("Failed to send generic webhook: %s", e)

    # Slack Integration (Specialized payload)
    slack_url = getattr(settings, "slack_webhook_url", None)
    if slack_url:
        slack_payload = {
            "text": f"🚨 *Critical Finding Detected on {target_name}*",
            "attachments": [{
                "color": "#eb4034" if finding.severity == Severity.CRITICAL else "#eb9234",
                "fields": [
                    {"title": "Finding", "value": finding.title, "short": True},
                    {"title": "Severity", "value": finding.severity.value.upper(), "short": True},
                    {"title": "Path", "value": f"`{finding.path or '/'}`", "short": False},
                ]
            }]
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(slack_url, json=slack_payload, timeout=5.0)
        except Exception as e:
            log.warning("Failed to send Slack notification: %s", e)

async def notify_scan_completed(scan: ScanResult) -> None:
    """Summary notification when a scan finishes."""
    # Implementation similar to above...
    pass
