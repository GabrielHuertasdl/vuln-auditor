"""Compliance framework mappings and report generation.

Maps security findings (CWE IDs + OWASP categories) to compliance controls
for OWASP ASVS, SOC 2, and PCI-DSS.

This is evidence mapping — not certification.
Results should be reviewed by a qualified security professional.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class ComplianceFramework(str, Enum):
    ASVS = "asvs"
    SOC2 = "soc2"
    PCI_DSS = "pci-dss"


@dataclass
class FrameworkMeta:
    value: str
    label: str
    description: str


SUPPORTED_FRAMEWORKS = [
    FrameworkMeta("asvs", "OWASP ASVS v4.0", "Application Security Verification Standard"),
    FrameworkMeta("soc2", "SOC 2 Type II", "Service Organization Control 2 — Security Trust Criteria"),
    FrameworkMeta("pci-dss", "PCI DSS v4.0", "Payment Card Industry Data Security Standard"),
]


# ── CWE → Compliance control mapping ─────────────────────────────────────────

# Format: { control_id: { "name": ..., "cwes": [...], "owasp_cats": [...] } }

_ASVS_CONTROLS: dict[str, dict[str, Any]] = {
    "V2.1": {
        "name": "Password Security",
        "cwes": [521, 916, 307],
        "owasp_cats": ["A07:2021-Identification and Authentication Failures"],
    },
    "V3.1": {
        "name": "Session Management",
        "cwes": [384, 613, 330],
        "owasp_cats": ["A07:2021-Identification and Authentication Failures"],
    },
    "V5.1": {
        "name": "Input Validation",
        "cwes": [89, 79, 88, 94, 643],
        "owasp_cats": ["A03:2021-Injection", "A01:2021-Broken Access Control"],
    },
    "V5.2": {
        "name": "Sanitization and Sandboxing",
        "cwes": [79, 80, 116],
        "owasp_cats": ["A03:2021-Injection"],
    },
    "V6.1": {
        "name": "Data Classification",
        "cwes": [312, 313, 315, 359],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "V6.2": {
        "name": "Algorithms",
        "cwes": [327, 326, 780],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "V8.1": {
        "name": "General Data Protection",
        "cwes": [200, 209, 532],
        "owasp_cats": ["A04:2021-Insecure Design"],
    },
    "V9.1": {
        "name": "Communications Security",
        "cwes": [295, 296, 297, 298, 599],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "V10.1": {
        "name": "Code Integrity",
        "cwes": [829, 494, 502],
        "owasp_cats": ["A08:2021-Software and Data Integrity Failures"],
    },
    "V13.1": {
        "name": "Generic Web Service Security",
        "cwes": [918, 611, 776],
        "owasp_cats": ["A10:2021-Server-Side Request Forgery"],
    },
    "V14.2": {
        "name": "Dependency",
        "cwes": [1104, 829],
        "owasp_cats": ["A06:2021-Vulnerable and Outdated Components"],
    },
}

_SOC2_CONTROLS: dict[str, dict[str, Any]] = {
    "CC6.1": {
        "name": "Logical and Physical Access Controls",
        "cwes": [284, 285, 287, 288, 306, 307, 521],
        "owasp_cats": ["A01:2021-Broken Access Control", "A07:2021-Identification and Authentication Failures"],
    },
    "CC6.2": {
        "name": "Authentication and Credentials",
        "cwes": [521, 307, 798, 255, 259],
        "owasp_cats": ["A07:2021-Identification and Authentication Failures"],
    },
    "CC6.6": {
        "name": "Transmission Encryption",
        "cwes": [319, 295, 326, 327],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "CC6.7": {
        "name": "Data at Rest Protection",
        "cwes": [312, 313, 327],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "CC7.1": {
        "name": "Vulnerability Detection",
        "cwes": [89, 79, 78, 22, 94],
        "owasp_cats": ["A03:2021-Injection"],
    },
    "CC8.1": {
        "name": "Change Management",
        "cwes": [829, 494, 1104],
        "owasp_cats": ["A06:2021-Vulnerable and Outdated Components", "A08:2021-Software and Data Integrity Failures"],
    },
    "CC9.2": {
        "name": "Risk Mitigation — Third Party",
        "cwes": [1104, 829],
        "owasp_cats": ["A06:2021-Vulnerable and Outdated Components"],
    },
}

_PCI_DSS_CONTROLS: dict[str, dict[str, Any]] = {
    "Req-2.2": {
        "name": "Secure System Components",
        "cwes": [1104, 16, 521],
        "owasp_cats": ["A06:2021-Vulnerable and Outdated Components", "A05:2021-Security Misconfiguration"],
    },
    "Req-4.2": {
        "name": "Strong Cryptography in Transit",
        "cwes": [319, 295, 326, 327],
        "owasp_cats": ["A02:2021-Cryptographic Failures"],
    },
    "Req-6.2": {
        "name": "Secure Software Development",
        "cwes": [89, 79, 78, 22, 94, 352],
        "owasp_cats": ["A03:2021-Injection", "A01:2021-Broken Access Control"],
    },
    "Req-6.3": {
        "name": "Security Vulnerabilities Identified",
        "cwes": [1104, 829],
        "owasp_cats": ["A06:2021-Vulnerable and Outdated Components"],
    },
    "Req-6.4": {
        "name": "Public-Facing Web Applications Protected",
        "cwes": [89, 79, 78, 352, 22],
        "owasp_cats": ["A03:2021-Injection"],
    },
    "Req-7.1": {
        "name": "Access Restricted on Need to Know",
        "cwes": [284, 285, 862, 863],
        "owasp_cats": ["A01:2021-Broken Access Control"],
    },
    "Req-8.2": {
        "name": "User Identification and Authentication",
        "cwes": [287, 521, 307, 798],
        "owasp_cats": ["A07:2021-Identification and Authentication Failures"],
    },
    "Req-10.2": {
        "name": "Audit Logs",
        "cwes": [778, 532, 223],
        "owasp_cats": ["A09:2021-Security Logging and Monitoring Failures"],
    },
}

_FRAMEWORK_MAP: dict[str, dict[str, dict[str, Any]]] = {
    ComplianceFramework.ASVS: _ASVS_CONTROLS,
    ComplianceFramework.SOC2: _SOC2_CONTROLS,
    ComplianceFramework.PCI_DSS: _PCI_DSS_CONTROLS,
}


# ── Report generation ──────────────────────────────────────────────────────────

def _get_finding_cwes(finding) -> set[int]:
    cwes = finding.cwe_ids
    if isinstance(cwes, str):
        try:
            cwes = json.loads(cwes)
        except Exception:
            cwes = []
    return {int(c) for c in (cwes or []) if str(c).isdigit()}


def generate_compliance_report(
    framework: ComplianceFramework,
    findings: list,
    org_id: str,
) -> dict:
    controls_map = _FRAMEWORK_MAP.get(framework, {})
    control_results = []

    total_pass = total_fail = total_partial = total_not_covered = 0

    for control_id, control_info in controls_map.items():
        control_cwes = set(control_info["cwes"])
        control_owasp_cats = set(control_info.get("owasp_cats", []))

        relevant_findings = []
        for f in findings:
            finding_cwes = _get_finding_cwes(f)
            owasp_cat = getattr(f, "owasp_category", None) or ""

            cwe_match = bool(finding_cwes & control_cwes)
            owasp_match = any(owasp_cat.startswith(cat) for cat in control_owasp_cats)

            if cwe_match or owasp_match:
                relevant_findings.append(f)

        critical_count = sum(1 for f in relevant_findings if getattr(f, "severity", "") == "critical")
        high_count = sum(1 for f in relevant_findings if getattr(f, "severity", "") == "high")
        finding_count = len(relevant_findings)

        if finding_count == 0:
            status = "NOT_COVERED"
            total_not_covered += 1
        elif critical_count > 0 or high_count > 0:
            status = "FAIL"
            total_fail += 1
        elif finding_count > 0:
            status = "PARTIAL"
            total_partial += 1
        else:
            status = "PASS"
            total_pass += 1

        finding_summaries = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "cwe_ids": _get_finding_cwes(f),
            }
            for f in relevant_findings[:10]
        ]

        control_results.append({
            "control_id": control_id,
            "control_name": control_info["name"],
            "status": status,
            "finding_count": finding_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "findings": finding_summaries,
        })

    fw_meta = next((f for f in SUPPORTED_FRAMEWORKS if f.value == framework.value), None)

    return {
        "framework": framework.value,
        "framework_name": fw_meta.label if fw_meta else framework.value,
        "org_id": org_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_controls": len(controls_map),
            "pass": total_pass,
            "fail": total_fail,
            "partial": total_partial,
            "not_covered": total_not_covered,
            "compliance_score": round(
                (total_pass / len(controls_map)) * 100 if controls_map else 0, 1
            ),
        },
        "controls": control_results,
        "disclaimer": (
            "This report maps detected findings to compliance controls based on CWE and OWASP categories. "
            "It is not a certification and should be reviewed by a qualified security professional."
        ),
    }
