"""
IaC security scanner — Checkov — Phase 3.

Scans Infrastructure-as-Code files (Terraform, CloudFormation, Kubernetes
YAML, Dockerfile, Helm charts) for misconfigurations.

Requires: pip install checkov
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path

from core.schemas import RawFinding, ToolName

log = logging.getLogger(__name__)


async def run_checkov(target_path: str | Path, scan_id: str) -> list[RawFinding]:
    """
    Run Checkov against a directory. Returns RawFindings, [] on failure/absence.
    """
    if not shutil.which("checkov"):
        log.warning("checkov not found — skipping IaC scan")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    cmd = [
        "checkov",
        "--directory", str(target_path),
        "--output", "json",
        "--output-file-path", os.path.dirname(out_path),
        "--quiet",
        "--compact",
        "--skip-download",
    ]

    # Checkov writes results_{framework}.json files, so we use stdout instead
    cmd_stdout = [
        "checkov",
        "--directory", str(target_path),
        "--output", "json",
        "--quiet",
        "--compact",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_stdout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        raw = stdout.decode().strip()
        if not raw:
            return []
        # Checkov may output multiple JSON objects (one per framework) — take all
        data = _parse_jsonlines(raw)
    except Exception as e:
        log.warning("checkov failed: %s", e)
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    return _parse_checkov(data, scan_id)


def _parse_jsonlines(raw: str) -> list[dict]:
    """Parse one or multiple JSON objects from stdout."""
    results = []
    decoder = json.JSONDecoder()
    pos = 0
    raw = raw.strip()
    while pos < len(raw):
        try:
            obj, end = decoder.raw_decode(raw, pos)
            results.append(obj)
            pos = end
            while pos < len(raw) and raw[pos] in (" ", "\n", "\r", "\t"):
                pos += 1
        except json.JSONDecodeError:
            break
    return results


def _parse_checkov(data_list: list[dict], scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    idx = 0

    for data in data_list:
        # data may be a single framework result or a list
        if isinstance(data, list):
            items = data
        else:
            items = [data]

        for framework_result in items:
            failed = framework_result.get("results", {}).get("failed_checks", [])
            for check in failed:
                check_id = check.get("check_id", "")
                check_type = check.get("check_type", "")
                resource = check.get("resource", "")
                file_path = check.get("file_path", "")
                file_line = check.get("file_line_range", [0, 0])
                description = check.get("check", {}).get("name", check_id)
                guideline = check.get("check", {}).get("guideline", "")
                bc_id = check.get("bc_check_id", "")

                # Severity: Checkov doesn't always provide it — map by check_id prefix
                severity = _checkov_severity(check_id)

                refs: list[str] = []
                if guideline:
                    refs.append(guideline)

                location = f"{file_path}:{file_line[0]}" if file_path else resource

                findings.append(
                    RawFinding(
                        id=f"checkov-{scan_id}-{idx}",
                        tool=ToolName.CHECKOV,
                        host="localhost",
                        path=location,
                        title=description,
                        description=f"[{check_id}] {description}",
                        evidence=resource,
                        raw_severity=severity,
                        raw_confidence="high",
                        references=refs,
                    )
                )
                idx += 1

    return findings


def _checkov_severity(check_id: str) -> str:
    """Heuristic severity based on Checkov check ID prefixes."""
    high_prefixes = {"CKV_AWS_1", "CKV_AWS_2", "CKV_K8S_1", "CKV_DOCKER_2"}
    if check_id in high_prefixes:
        return "high"
    # Broad rules: encryption/auth/network = high, exposure = medium, rest = low
    keywords_high = ("secret", "encrypt", "public_access", "root", "admin", "auth")
    keywords_medium = ("logging", "monitor", "rotation", "versioning", "backup")
    lower = check_id.lower()
    if any(k in lower for k in keywords_high):
        return "high"
    if any(k in lower for k in keywords_medium):
        return "medium"
    return "medium"
