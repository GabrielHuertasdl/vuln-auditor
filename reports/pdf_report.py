"""PDF report generation using ReportLab."""
from __future__ import annotations

import io
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.schemas import ScanResult

# Severity color map (RGB 0-1)
_SEV_COLORS = {
    "critical": (0.78, 0.08, 0.08),
    "high": (0.90, 0.45, 0.05),
    "medium": (0.93, 0.75, 0.05),
    "low": (0.25, 0.55, 0.90),
    "informational": (0.40, 0.70, 0.40),
}


def generate_pdf_report(result: "ScanResult") -> bytes:
    """Generate a PDF executive report for a completed scan. Returns raw bytes."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return _fallback_pdf(result)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Security Scan Report – {result.target}",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=20, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, spaceAfter=4, spaceBefore=12)
    body = styles["Normal"]
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey)

    story = []

    # ── Header ─────────────────────────────────────────────────────────────────
    story.append(Paragraph("Security Scan Report", h1))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e293b")))
    story.append(Spacer(1, 0.3 * cm))

    meta_rows = [
        ["Target", result.target],
        ["Scan ID", result.scan_id],
        ["Status", result.status.value.upper()],
        ["Scan Mode", result.scan_mode],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    if result.duration_seconds:
        meta_rows.append(["Duration", f"{result.duration_seconds:.1f}s"])

    meta_table = Table(meta_rows, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Posture Score ──────────────────────────────────────────────────────────
    if result.posture_score:
        ps = result.posture_score
        story.append(Paragraph("Security Posture", h2))
        score_color = (
            colors.HexColor("#16a34a") if ps.overall_score >= 70
            else colors.HexColor("#d97706") if ps.overall_score >= 40
            else colors.HexColor("#dc2626")
        )
        score_style = ParagraphStyle(
            "Score", parent=styles["Normal"], fontSize=36, textColor=score_color,
            spaceAfter=4
        )
        story.append(Paragraph(f"{ps.overall_score:.0f}/100", score_style))
        domain_rows = [["Domain", "Score"]]
        for domain, score in (ps.domain_scores or {}).items():
            domain_rows.append([domain.replace("_", " ").title(), f"{score:.0f}"])
        if len(domain_rows) > 1:
            dt = Table(domain_rows, colWidths=[10 * cm, 7 * cm])
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(dt)
        story.append(Spacer(1, 0.5 * cm))

    # ── Executive Summary ──────────────────────────────────────────────────────
    if result.ai_executive_summary:
        story.append(Paragraph("Executive Summary", h2))
        story.append(Paragraph(result.ai_executive_summary, body))
        story.append(Spacer(1, 0.5 * cm))

    # ── Severity Summary ───────────────────────────────────────────────────────
    story.append(Paragraph("Findings Overview", h2))
    sev = result.severity_summary or {}
    sev_rows = [["Severity", "Count"]]
    for level in ("critical", "high", "medium", "low", "informational"):
        count = sev.get(level, 0)
        sev_rows.append([level.capitalize(), str(count)])
    sev_table = Table(sev_rows, colWidths=[10 * cm, 7 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Top Findings ───────────────────────────────────────────────────────────
    findings = [f for f in (result.findings or []) if not f.is_noise and not f.duplicate_of]
    findings.sort(key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(
            f.severity.value, 5
        )
    ))

    if findings:
        story.append(Paragraph("Findings Detail", h2))
        find_rows = [["#", "Severity", "Title", "Host", "OWASP"]]
        for i, f in enumerate(findings[:50], 1):
            find_rows.append([
                str(i),
                f.severity.value.upper(),
                f.title[:60] + ("…" if len(f.title) > 60 else ""),
                f.host,
                f.owasp_category or "—",
            ])
        ft = Table(find_rows, colWidths=[1 * cm, 2.5 * cm, 8 * cm, 4 * cm, 2.5 * cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]))
        story.append(ft)
        story.append(Spacer(1, 0.5 * cm))

    # ── Footer note ────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "Generated by VulnAuditor ASPM · For authorized use only",
        small,
    ))

    doc.build(story)
    return buf.getvalue()


def _fallback_pdf(result: "ScanResult") -> bytes:
    """Minimal PDF without reportlab — returns a text/plain-encoded fake PDF notice."""
    content = f"PDF generation unavailable. Install reportlab.\n\nScan: {result.scan_id}\nTarget: {result.target}"
    return content.encode()
