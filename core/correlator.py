"""
Merges duplicate findings across tools, boosts confidence for corroborated
issues, and annotates relationships between findings.

Pipeline:
  1. correlate()         — group by correlation_key, merge each group
  2. annotate_related()  — cross-reference findings by CWE/OWASP (call AFTER classify)
"""
from __future__ import annotations

import re
import uuid
from collections import defaultdict

from core.schemas import (
    DuplicateType,
    Finding,
    Priority,
    RawFinding,
    Severity,
    make_correlation_key,
    make_endpoint_fingerprint,
)
from core.scorer import (
    boost_confidence,
    maybe_elevate_to_critical,
    pick_highest_severity,
    score_raw_finding,
)

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]


def correlate(raw_findings: list[RawFinding], scan_id: str) -> list[Finding]:
    """
    Merge raw tool outputs into correlated Finding objects.

    Deduplication strategy:
      - Group by correlation_key (broad: host+port+path+normalized_title).
      - Within a group, findings from different tools are merged into one Finding.
      - Confidence is boosted when ≥2 tools independently report the same issue.
      - endpoint_fingerprint (includes method+parameter) is stored separately
        for finer-grained duplicate detection in future cross-scan comparisons.

    Note: annotate_related() must be called AFTER classify() to populate
    related_findings, since OWASP category is not available at this stage.
    """
    groups: dict[str, list[RawFinding]] = defaultdict(list)
    for raw in raw_findings:
        key = make_correlation_key(raw.host, raw.port, raw.path, raw.title)
        groups[key].append(raw)

    return [_merge_group(key, group, scan_id) for key, group in groups.items()]


def annotate_related(findings: list[Finding]) -> list[Finding]:
    """
    After classification, cross-reference findings that share CWE IDs or
    OWASP categories but are at different locations.

    Mutates finding objects via model_copy (immutable update).
    Returns the updated list.

    A finding is 'related' to another if they share at least one CWE ID
    or the same OWASP category, but have different correlation keys.
    related_findings contains IDs only — not full objects, to avoid cycles.
    """
    by_cwe: dict[int, list[str]] = defaultdict(list)
    by_owasp: dict[str, list[str]] = defaultdict(list)

    for f in findings:
        for cwe in f.cwe_ids:
            by_cwe[cwe].append(f.id)
        if f.owasp_category:
            by_owasp[f.owasp_category].append(f.id)

    id_to_idx = {f.id: i for i, f in enumerate(findings)}
    result = list(findings)

    for f in findings:
        related: set[str] = set()
        for cwe in f.cwe_ids:
            related.update(by_cwe[cwe])
        if f.owasp_category:
            related.update(by_owasp[f.owasp_category])
        related.discard(f.id)

        if related:
            idx = id_to_idx[f.id]
            result[idx] = f.model_copy(update={"related_findings": sorted(related)})

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _merge_group(key: str, group: list[RawFinding], scan_id: str) -> Finding:
    """Merge a group of raw findings (same correlation key) into one Finding."""
    scored = [(raw, *score_raw_finding(raw)) for raw in group]  # (raw, severity, confidence)

    severity = pick_highest_severity([s for _, s, _ in scored])

    # Primary raw finding = the one with the highest severity
    primary_raw = max(group, key=lambda r: _severity_rank(score_raw_finding(r)[0]))
    _, _, base_confidence = next(
        (sv, s, c) for sv, s, c in scored if sv is primary_raw
    )

    sources = list({raw.tool for raw in group})
    source_count = len(sources)
    final_confidence = boost_confidence(base_confidence, source_count)

    evidence_parts = [r.evidence for r in group if r.evidence]
    evidence = "\n---\n".join(dict.fromkeys(evidence_parts)) if evidence_parts else None
    normalized_evidence = _normalize_evidence(evidence) if evidence else None

    refs: list[str] = []
    seen_refs: set[str] = set()
    for raw in group:
        for ref in raw.references:
            if ref not in seen_refs:
                seen_refs.add(ref)
                refs.append(ref)

    cwe_ids = list({raw.cwe_id for raw in group if raw.cwe_id})

    # Use richest description (longest), but title from primary (highest severity)
    primary_desc = max(group, key=lambda r: len(r.description))

    endpoint_fp = make_endpoint_fingerprint(
        host=primary_raw.host,
        port=primary_raw.port,
        method=primary_raw.method,
        path=primary_raw.path,
        parameter=primary_raw.parameter,
    )

    finding = Finding(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        correlation_key=key,
        endpoint_fingerprint=endpoint_fp,
        title=primary_raw.title,
        description=primary_desc.description,
        host=primary_raw.host,
        port=primary_raw.port,
        protocol=primary_raw.protocol,
        path=primary_raw.path,
        method=primary_raw.method,
        parameter=primary_raw.parameter,
        evidence=evidence,
        normalized_evidence=normalized_evidence,
        severity=severity,
        confidence=final_confidence,
        cwe_ids=cwe_ids,
        sources=sources,
        source_count=source_count,
        raw_finding_ids=[r.id for r in group],
        solution=next((r.solution for r in group if r.solution), None),
        references=refs,
    )

    return maybe_elevate_to_critical(finding)


def _normalize_evidence(raw: str) -> str:
    """
    Strip dynamic values from evidence to produce stable, comparable strings.

    Removed patterns:
      - Session tokens and hex strings (≥32 hex chars)
      - ISO timestamps
      - UUID v4 patterns
    """
    normalized = re.sub(r"[0-9a-fA-F]{32,}", "<TOKEN>", raw)
    normalized = re.sub(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
        "<TIMESTAMP>",
        normalized,
    )
    normalized = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        "<UUID>",
        normalized,
        flags=re.IGNORECASE,
    )
    return normalized.strip()[:1000]


def _severity_rank(s: Severity) -> int:
    try:
        return len(_SEVERITY_ORDER) - _SEVERITY_ORDER.index(s)
    except ValueError:
        return 0
