"""
SCA (Software Composition Analysis) runner — Phase 3.

Supports three backends:
  - Trivy (filesystem scan): works on any repo with a lockfile
  - npm audit (Node.js projects)
  - pip-audit (Python projects)

Each returns a list of RawFinding objects with CVE IDs embedded in the
`references` list so downstream EPSS/KEV enrichment can pick them up.
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


# ── Trivy ─────────────────────────────────────────────────────────────────────

async def run_trivy_fs(target_path: str | Path, scan_id: str) -> list[RawFinding]:
    """Trivy filesystem scan — finds vulns in package manifests/lockfiles."""
    if not shutil.which("trivy"):
        log.warning("trivy not found — skipping SCA (trivy)")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--output", out_path,
        "--quiet",
        str(target_path),
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=180)
        with open(out_path) as f:
            data = json.load(f)
    except Exception as e:
        log.warning("trivy fs failed: %s", e)
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    return _parse_trivy(data, scan_id)


async def run_trivy_image(image: str, scan_id: str) -> list[RawFinding]:
    """Trivy container image scan."""
    if not shutil.which("trivy"):
        log.warning("trivy not found — skipping container scan")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name

    cmd = [
        "trivy", "image",
        "--format", "json",
        "--output", out_path,
        "--quiet",
        image,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=300)
        with open(out_path) as f:
            data = json.load(f)
    except Exception as e:
        log.warning("trivy image failed: %s", e)
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    return _parse_trivy(data, scan_id)


def _parse_trivy(data: dict, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    idx = 0
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion", "")
            severity_raw = vuln.get("Severity", "UNKNOWN").lower()
            description = vuln.get("Description", vuln.get("Title", cve_id))
            title = vuln.get("Title") or f"{pkg} {cve_id}"

            refs: list[str] = []
            if cve_id:
                refs.append(cve_id)
            refs += [r.get("URL", "") for r in vuln.get("References", []) if r.get("URL")]

            solution = f"Upgrade {pkg} from {installed} to {fixed}" if fixed else None

            # CWE extraction
            cwe_id: int | None = None
            for cwe_str in vuln.get("CweIDs", []):
                try:
                    cwe_id = int(cwe_str.replace("CWE-", ""))
                    break
                except ValueError:
                    pass

            findings.append(
                RawFinding(
                    id=f"trivy-{scan_id}-{idx}",
                    tool=ToolName.TRIVY,
                    host="localhost",
                    path=result.get("Target", "/"),
                    title=title,
                    description=description,
                    evidence=f"{pkg}@{installed}",
                    raw_severity=severity_raw if severity_raw in ("critical", "high", "medium", "low") else "informational",
                    raw_confidence="high",
                    cwe_id=cwe_id,
                    solution=solution,
                    references=refs,
                )
            )
            idx += 1
    return findings


# ── npm audit ─────────────────────────────────────────────────────────────────

async def run_npm_audit(project_path: str | Path, scan_id: str) -> list[RawFinding]:
    if not shutil.which("npm"):
        log.warning("npm not found — skipping npm audit")
        return []

    pkg_json = Path(project_path) / "package.json"
    if not pkg_json.exists():
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "npm", "audit", "--json",
            cwd=str(project_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        data = json.loads(stdout)
    except Exception as e:
        log.warning("npm audit failed: %s", e)
        return []

    return _parse_npm_audit(data, scan_id)


def _parse_npm_audit(data: dict, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    vulns = data.get("vulnerabilities", {})
    for idx, (pkg, info) in enumerate(vulns.items()):
        severity = info.get("severity", "moderate")
        via = info.get("via", [])
        # via may be a list of dicts (direct) or strings (transitive)
        for v_idx, via_item in enumerate(via if isinstance(via, list) else []):
            if not isinstance(via_item, dict):
                continue
            cve_ids = via_item.get("cve", [])
            refs = list(cve_ids) + ([via_item.get("url")] if via_item.get("url") else [])
            sev_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}
            findings.append(
                RawFinding(
                    id=f"npm_audit-{scan_id}-{idx}-{v_idx}",
                    tool=ToolName.NPM_AUDIT,
                    host="localhost",
                    path="package.json",
                    title=via_item.get("title", f"{pkg} vulnerability"),
                    description=via_item.get("overview", via_item.get("title", "")),
                    evidence=f"{pkg}@{info.get('range', '?')}",
                    raw_severity=sev_map.get(severity, "medium"),
                    raw_confidence="high",
                    solution=f"Run `npm audit fix` or upgrade {pkg}",
                    references=refs,
                )
            )
    return findings


# ── pip-audit ─────────────────────────────────────────────────────────────────

async def run_pip_audit(project_path: str | Path, scan_id: str) -> list[RawFinding]:
    if not shutil.which("pip-audit"):
        log.warning("pip-audit not found — skipping pip audit")
        return []

    req_file = Path(project_path) / "requirements.txt"
    pyproject = Path(project_path) / "pyproject.toml"
    if not req_file.exists() and not pyproject.exists():
        return []

    cmd = ["pip-audit", "--format", "json"]
    if req_file.exists():
        cmd += ["-r", str(req_file)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(project_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        data = json.loads(stdout)
    except Exception as e:
        log.warning("pip-audit failed: %s", e)
        return []

    return _parse_pip_audit(data, scan_id)


def _parse_pip_audit(data: dict | list, scan_id: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    # pip-audit JSON: list of {name, version, vulns: [{id, fix_versions, description}]}
    items = data if isinstance(data, list) else data.get("dependencies", [])
    idx = 0
    for pkg_info in items:
        pkg = pkg_info.get("name", "unknown")
        version = pkg_info.get("version", "?")
        for vuln in pkg_info.get("vulns", []):
            vuln_id = vuln.get("id", "")
            fix = vuln.get("fix_versions", [])
            fix_str = ", ".join(fix) if fix else None
            refs = [vuln_id] if vuln_id.startswith("CVE-") else []
            if vuln.get("aliases"):
                refs += [a for a in vuln["aliases"] if a.startswith("CVE-")]
            findings.append(
                RawFinding(
                    id=f"pip_audit-{scan_id}-{idx}",
                    tool=ToolName.PIP_AUDIT,
                    host="localhost",
                    path="requirements.txt",
                    title=f"{pkg} {vuln_id}",
                    description=vuln.get("description", vuln_id),
                    evidence=f"{pkg}=={version}",
                    raw_severity="medium",
                    raw_confidence="high",
                    solution=f"Upgrade {pkg} to {fix_str}" if fix_str else None,
                    references=refs,
                )
            )
            idx += 1
    return findings
