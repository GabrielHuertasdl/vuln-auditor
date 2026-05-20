"""
SAST scanner — Semgrep.

Runs `semgrep scan` against a local repository path or a remote URL that was
previously cloned. Requires semgrep to be installed (`pip install semgrep`).

Output format: JSON via --json flag, parsed into RawFindings.
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

_DEFAULT_RULESETS = ["p/owasp-top-ten", "p/security-audit", "p/secrets"]


async def run_semgrep(
    target_path: str | Path,
    scan_id: str,
    rulesets: list[str] | None = None,
) -> list[RawFinding]:
    """
    Run Semgrep on a local path. Returns RawFindings on success, [] on failure.
    """
    if not shutil.which("semgrep"):
        log.warning("semgrep not found in PATH — skipping SAST")
        return []

    rules = rulesets or _DEFAULT_RULESETS
    config_args = []
    for r in rules:
        config_args += ["--config", r]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    cmd = [
        "semgrep", "scan",
        "--json",
        "--output", out_path,
        "--no-git-ignore",
        "--quiet",
        *config_args,
        str(target_path),
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        if proc.returncode not in (0, 1):  # 1 = findings found
            log.warning("semgrep exited %d: %s", proc.returncode, stderr.decode()[:500])
            return []

        with open(out_path) as f:
            data = json.load(f)
    except (asyncio.TimeoutError, Exception) as e:
        log.warning("semgrep failed: %s", e)
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    return _parse_semgrep(data, scan_id)


def _parse_semgrep(data: dict, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for idx, result in enumerate(data.get("results", [])):
        meta = result.get("extra", {}).get("metadata", {})
        check_id = result.get("check_id", "")
        path = result.get("path", "")
        line = result.get("start", {}).get("line", 0)
        message = result.get("extra", {}).get("message", check_id)
        fix = result.get("extra", {}).get("fix", None)

        # Severity mapping
        severity_raw = result.get("extra", {}).get("severity", "WARNING").upper()
        severity_map = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "informational",
            "CRITICAL": "critical",
        }
        severity = severity_map.get(severity_raw, "medium")

        # CWE extraction
        cwe_raw = meta.get("cwe", [])
        cwe_id: int | None = None
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe_raw = cwe_raw[0]
        if isinstance(cwe_raw, str) and "CWE-" in cwe_raw:
            try:
                cwe_id = int(cwe_raw.split("CWE-")[-1].split()[0])
            except ValueError:
                pass

        refs: list[str] = []
        if isinstance(meta.get("references"), list):
            refs = [r for r in meta["references"] if isinstance(r, str)]

        findings.append(
            RawFinding(
                id=f"semgrep-{scan_id}-{idx}",
                tool=ToolName.SEMGREP,
                host="localhost",
                path=f"{path}:{line}",
                title=check_id.split(".")[-1].replace("-", " ").title(),
                description=message,
                evidence=result.get("extra", {}).get("lines", ""),
                raw_severity=severity,
                raw_confidence="high",
                cwe_id=cwe_id,
                solution=fix,
                references=refs,
            )
        )
    return findings
