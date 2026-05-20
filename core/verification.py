"""
Verification Engine — maps findings and discovery signals to security controls.

Aligned with OWASP Web Security Testing Guide (WSTG) and ASVS.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from core.schemas import (
    AssetDiscovery,
    Confidence,
    DiscoveryType,
    Finding,
    VerificationRecord,
    VerificationStatus,
)

# ── Baseline Taxonomy ─────────────────────────────────────────────────────────

WSTG_DOMAINS = {
    "CONF": "Configuration Management",
    "IDNT": "Identity Management",
    "AUTH": "Authentication Testing",
    "ATHZ": "Authorization Testing",
    "SESS": "Session Management",
    "INPV": "Input Validation Testing",
    "CRYP": "Cryptography",
    "ERRH": "Error Handling",
    "CLNT": "Client Side Testing",
    "API": "API Security",
}

WSTG_CONTROLS = {
    "WSTG-CONF-01": ("Secure HTTP Headers", "CONF"),
    "WSTG-CONF-02": ("TLS/SSL Configuration", "CONF"),
    "WSTG-IDNT-01": ("Role-based Access Control", "IDNT"),
    "WSTG-AUTH-01": ("Authentication Bypass", "AUTH"),
    "WSTG-ATHZ-01": ("Insecure Direct Object References", "ATHZ"),
    "WSTG-SESS-01": ("Session Management Schema", "SESS"),
    "WSTG-INPV-01": ("Injection (SQL, OS, etc.)", "INPV"),
    "WSTG-INPV-02": ("Cross-Site Scripting (XSS)", "INPV"),
    "WSTG-CRYP-01": ("Strong Cryptography", "CRYP"),
    "WSTG-API-01": ("API Inventory and Authentication", "API"),
}

# Mapping OWASP Categories to WSTG Controls
OWASP_TO_WSTG = {
    "A01:2021-Broken Access Control": "WSTG-ATHZ-01",
    "A02:2021-Cryptographic Failures": "WSTG-CRYP-01",
    "A03:2021-Injection": "WSTG-INPV-01",
    "A05:2021-Security Misconfiguration": "WSTG-CONF-01",
    "A07:2021-Identification and Authentication Failures": "WSTG-AUTH-01",
    "API1:2023-Broken Object Level Authorization": "WSTG-ATHZ-01",
    "API2:2023-Broken Authentication": "WSTG-AUTH-01",
}

# CWE-specific overrides for more granular control mapping
CWE_TO_WSTG = {
    79: "WSTG-INPV-02",  # XSS
    22: "WSTG-ATHZ-01",  # Path Traversal (often related to authorization)
    326: "WSTG-CONF-02", # Weak Encryption (TLS)
}


class VerificationEngine:
    """
    Orchestrates the verification of security controls based on findings
    and discovery evidence.
    """

    def process(
        self,
        scan_id: str,
        findings: list[Finding],
        discovery_items: list[AssetDiscovery],
    ) -> list[VerificationRecord]:
        """
        Generates verification records for all baseline controls.
        """
        records: list[VerificationRecord] = []
        
        # Determine if target is API (based on discovery or stack)
        is_api = any(d.type == DiscoveryType.ENDPOINT and "/api" in d.data.get("path", "") for d in discovery_items)
        # fallback: if we have API findings
        if not is_api:
            is_api = any(f.owasp_api_category is not None for f in findings)

        # Group findings by control
        control_to_findings: dict[str, list[Finding]] = {k: [] for k in WSTG_CONTROLS}
        for f in findings:
            if f.is_noise or f.duplicate_of:
                continue
            
            # 1. Check CWE override
            mapped = False
            for cwe in f.cwe_ids:
                if cwe in CWE_TO_WSTG:
                    control_to_findings[CWE_TO_WSTG[cwe]].append(f)
                    mapped = True
                    break
            
            # 2. Check OWASP mapping
            if not mapped and f.owasp_category in OWASP_TO_WSTG:
                control_to_findings[OWASP_TO_WSTG[f.owasp_category]].append(f)
            elif not mapped and f.owasp_api_category in OWASP_TO_WSTG:
                control_to_findings[OWASP_TO_WSTG[f.owasp_api_category]].append(f)

        # Process each control
        for control_code, (name, domain) in WSTG_CONTROLS.items():
            # Handle N/A
            if domain == "API" and not is_api:
                records.append(
                    VerificationRecord(
                        id=str(uuid.uuid4()),
                        scan_id=scan_id,
                        control_id=control_code,
                        status=VerificationStatus.NOT_APPLICABLE,
                        evidence_summary="Target does not appear to be an API.",
                        metadata={},
                    )
                )
                continue

            control_findings = control_to_findings.get(control_code, [])
            
            status = VerificationStatus.INSUFFICIENT_EVIDENCE
            evidence_parts = []
            metadata = {}

            if control_findings:
                # If all findings are LOW confidence, it might be SUSPECTED instead of FAIL
                if all(f.confidence == Confidence.LOW for f in control_findings):
                    status = VerificationStatus.SUSPECTED
                    evidence_parts.append(f"Found {len(control_findings)} potential issues (Low Confidence).")
                else:
                    status = VerificationStatus.FAIL
                    evidence_parts.append(f"Found {len(control_findings)} issues violating this control.")
                
                # Summarize highest severity finding
                top_f = max(control_findings, key=lambda x: x.severity)
                evidence_parts.append(f"Highest severity: {top_f.severity.value} ({top_f.title})")
            else:
                # Try to find positive evidence from discovery
                status, positive_evidence, meta = self._verify_positive_evidence(
                    control_code, discovery_items
                )
                if status == VerificationStatus.PASS:
                    evidence_parts.append(positive_evidence)
                    metadata.update(meta)
                elif positive_evidence: # Partial evidence (INSUFFICIENT but with notes)
                    evidence_parts.append(positive_evidence)
                    metadata.update(meta)

            records.append(
                VerificationRecord(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    control_id=control_code,
                    status=status,
                    evidence_summary=" | ".join(evidence_parts) if evidence_parts else "No specific evidence for PASS or FAIL.",
                    metadata=metadata,
                )
            )

        return records

    def _verify_positive_evidence(
        self, control_code: str, discovery_items: list[AssetDiscovery]
    ) -> tuple[VerificationStatus, str | None, dict[str, Any]]:
        """
        Looks for signals in discovery data that confirm a control is PASSED.
        Rigor check: We need STRICTOR evidence for a PASS.
        """
        if control_code == "WSTG-CONF-01": # Secure Headers
            # We look for "present" headers in discovery
            headers = [d for d in discovery_items if d.type == DiscoveryType.HEADER and d.data.get("status") == "present"]
            if headers:
                # We require at least 3 critical security headers for a full PASS
                critical_headers = {"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"}
                found = {h.data.get("name") for h in headers if h.data.get("name") in critical_headers}
                
                if len(found) >= 3:
                    return VerificationStatus.PASS, f"Verified strong header posture (found {', '.join(found)})", {"headers_found": list(found)}
                elif len(found) >= 1:
                    # Not enough for a full PASS in our strict model, remain INSUFFICIENT but with a note
                    return VerificationStatus.INSUFFICIENT_EVIDENCE, f"Partial header posture (found {', '.join(found)}), but missing others for full verification.", {"headers_found": list(found)}

        if control_code == "WSTG-CONF-02": # TLS/SSL
            tls_items = [d for d in discovery_items if d.type == DiscoveryType.TLS]
            if tls_items:
                protocols = [t.data.get("protocol") for t in tls_items if t.data.get("protocol")]
                # PASS only if we ONLY see strong protocols
                if protocols and all(p in ("TLSv1.2", "TLSv1.3") for p in protocols):
                    return VerificationStatus.PASS, f"Verified strong TLS protocols: {', '.join(set(protocols))}", {"protocols": list(set(protocols))}
                elif any(p in ("SSLv3", "TLSv1.0", "TLSv1.1") for p in protocols):
                    # Scanners should catch this, but discovery also flags it as SUSPECTED if findings missed it
                    return VerificationStatus.SUSPECTED, f"Discovery found weak TLS protocols: {[p for p in protocols if p in ('SSLv3', 'TLSv1.0', 'TLSv1.1')]}", {"protocols": protocols}

        return VerificationStatus.INSUFFICIENT_EVIDENCE, None, {}
