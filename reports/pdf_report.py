"""PDF report generation using ReportLab."""
from __future__ import annotations

import io
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.schemas import ScanResult

_BRAND_DARK = "#0f1117"
_BRAND_BLUE = "#3b7cf5"
_BRAND_BLUE_LIGHT = "#dbeafe"
_GRAY_100 = "#f8fafc"
_GRAY_200 = "#e2e8f0"
_GRAY_500 = "#64748b"
_GRAY_800 = "#1e293b"

_SEV_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fefce8",
    "low":      "#eff6ff",
    "informational": "#f0fdf4",
}
_SEV_TEXT = {
    "critical": "#991b1b",
    "high":     "#9a3412",
    "medium":   "#854d0e",
    "low":      "#1e40af",
    "informational": "#166534",
}
_SEV_BORDER = {
    "critical": "#fca5a5",
    "high":     "#fdba74",
    "medium":   "#fde047",
    "low":      "#93c5fd",
    "informational": "#86efac",
}


def generate_pdf_report(result: "ScanResult") -> bytes:
    """Generate a professional PDF security report. Returns raw bytes."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
            KeepTogether,
        )
        from reportlab.pdfgen import canvas as pdfcanvas
    except ImportError:
        return _fallback_pdf(result)

    buf = io.BytesIO()

    # Custom first-page with colored header band
    def first_page(canv: pdfcanvas.Canvas, doc):  # type: ignore[type-arg]
        canv.saveState()
        # Header band
        canv.setFillColor(colors.HexColor(_BRAND_DARK))
        canv.rect(0, A4[1] - 3.8 * cm, A4[0], 3.8 * cm, fill=1, stroke=0)
        # Blue accent strip
        canv.setFillColor(colors.HexColor(_BRAND_BLUE))
        canv.rect(0, A4[1] - 3.8 * cm, 0.5 * cm, 3.8 * cm, fill=1, stroke=0)
        # Title text
        canv.setFillColor(colors.white)
        canv.setFont("Helvetica-Bold", 20)
        canv.drawString(1.2 * cm, A4[1] - 1.8 * cm, "Security Scan Report")
        canv.setFont("Helvetica", 10)
        canv.setFillColor(colors.HexColor("#94a3b8"))
        canv.drawString(1.2 * cm, A4[1] - 2.6 * cm, result.target)
        canv.setFont("Helvetica", 9)
        canv.drawString(1.2 * cm, A4[1] - 3.2 * cm,
                        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        # Footer
        canv.setFillColor(colors.HexColor(_GRAY_500))
        canv.setFont("Helvetica", 8)
        canv.drawString(2 * cm, 1.2 * cm, "VulnAuditor ASPM — Confidential · For authorized use only")
        canv.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page 1")
        canv.restoreState()

    def later_pages(canv: pdfcanvas.Canvas, doc):  # type: ignore[type-arg]
        canv.saveState()
        canv.setFillColor(colors.HexColor(_BRAND_DARK))
        canv.rect(0, A4[1] - 1.2 * cm, A4[0], 1.2 * cm, fill=1, stroke=0)
        canv.setFillColor(colors.HexColor(_BRAND_BLUE))
        canv.rect(0, A4[1] - 1.2 * cm, 0.3 * cm, 1.2 * cm, fill=1, stroke=0)
        canv.setFont("Helvetica-Bold", 8)
        canv.setFillColor(colors.white)
        canv.drawString(0.8 * cm, A4[1] - 0.8 * cm, "VulnAuditor — Security Scan Report")
        canv.setFillColor(colors.HexColor(_GRAY_500))
        canv.setFont("Helvetica", 8)
        canv.drawString(2 * cm, 1.2 * cm, "VulnAuditor ASPM — Confidential")
        canv.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
        canv.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=4.8 * cm,
        bottomMargin=2.2 * cm,
        title=f"Security Scan Report — {result.target}",
    )

    styles = getSampleStyleSheet()
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"], fontSize=13, spaceAfter=6, spaceBefore=16,
        textColor=colors.HexColor(_BRAND_DARK), fontName="Helvetica-Bold",
    )
    h3 = ParagraphStyle(
        "H3", parent=styles["Heading3"], fontSize=10, spaceAfter=4, spaceBefore=10,
        textColor=colors.HexColor(_GRAY_800), fontName="Helvetica-Bold",
    )
    body = ParagraphStyle(
        "Body", parent=styles["Normal"], fontSize=9, leading=14,
        textColor=colors.HexColor(_GRAY_800),
    )
    small = ParagraphStyle(
        "Small", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor(_GRAY_500),
    )

    def section_divider():
        return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor(_GRAY_200), spaceAfter=4)

    story: list = []

    # ── Meta table ────────────────────────────────────────────────────────────────
    story.append(Paragraph("Scan Overview", h2))
    story.append(section_divider())

    meta_rows = [
        ["Target", result.target],
        ["Scan ID", result.scan_id],
        ["Status", result.status.value.upper()],
        ["Mode", result.scan_mode.capitalize()],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    if result.duration_seconds:
        meta_rows.append(["Duration", f"{result.duration_seconds:.0f}s"])

    meta_table = Table(meta_rows, colWidths=[3.5 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(_BRAND_BLUE)),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor(_GRAY_800)),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor(_GRAY_100), colors.white]),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor(_GRAY_200)),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Posture Score ────────────────────────────────────────────────────────────
    if result.posture_score:
        ps = result.posture_score
        story.append(Paragraph("Security Posture", h2))
        story.append(section_divider())

        score = ps.overall_score
        if score >= 70:
            score_hex, label = "#16a34a", "GOOD"
        elif score >= 40:
            score_hex, label = "#d97706", "MODERATE"
        else:
            score_hex, label = "#dc2626", "CRITICAL"

        score_row = [
            [
                Paragraph(f'<font size="36" color="{score_hex}"><b>{score:.0f}</b></font>', styles["Normal"]),
                Paragraph(f'<font size="11" color="{score_hex}"><b>{label}</b></font><br/>'
                          f'<font size="8" color="{_GRAY_500}">Overall Security Score (0–100)</font>', styles["Normal"]),
            ]
        ]
        score_t = Table(score_row, colWidths=[3 * cm, 13.5 * cm])
        score_t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_GRAY_100)),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ]))
        story.append(score_t)
        story.append(Spacer(1, 0.3 * cm))

        if ps.domain_scores:
            domain_rows = [["Domain", "Score", "Rating"]]
            for domain, sc in ps.domain_scores.items():
                rating = "Good" if sc >= 70 else "Moderate" if sc >= 40 else "Critical"
                domain_rows.append([domain.replace("_", " ").title(), f"{sc:.0f}/100", rating])
            dt = Table(domain_rows, colWidths=[8 * cm, 3 * cm, 5.5 * cm])
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_GRAY_800)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor(_GRAY_100), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor(_GRAY_200)),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(dt)
        story.append(Spacer(1, 0.4 * cm))

    # ── Executive Summary ────────────────────────────────────────────────────────
    if result.ai_executive_summary:
        story.append(Paragraph("Executive Summary", h2))
        story.append(section_divider())
        summary_table = Table([[Paragraph(result.ai_executive_summary, body)]], colWidths=[16.5 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_BRAND_BLUE_LIGHT)),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(_BRAND_BLUE)),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.4 * cm))

    # ── Severity Summary ─────────────────────────────────────────────────────────
    story.append(Paragraph("Findings Overview", h2))
    story.append(section_divider())

    sev = result.severity_summary or {}
    total = sum(sev.get(k, 0) for k in ("critical", "high", "medium", "low", "informational"))

    sev_cells = []
    for level in ("critical", "high", "medium", "low", "informational"):
        count = sev.get(level, 0)
        sev_cells.append(
            Table(
                [[Paragraph(f'<font size="22" color="{_SEV_TEXT[level]}"><b>{count}</b></font>', styles["Normal"])],
                 [Paragraph(f'<font size="8" color="{_GRAY_500}">{level.upper()}</font>', styles["Normal"])]],
                colWidths=[3.2 * cm],
            )
        )

    sev_row_table = Table([sev_cells], colWidths=[3.2 * cm] * 5)
    sev_row_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(_SEV_BG["critical"])),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor(_SEV_BG["high"])),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor(_SEV_BG["medium"])),
        ("BACKGROUND", (3, 0), (3, -1), colors.HexColor(_SEV_BG["low"])),
        ("BACKGROUND", (4, 0), (4, -1), colors.HexColor(_SEV_BG["informational"])),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(_GRAY_200)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(_GRAY_200)),
    ]))
    story.append(sev_row_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── Findings Table ───────────────────────────────────────────────────────────
    findings = [f for f in (result.findings or []) if not f.is_noise and not f.duplicate_of]
    findings.sort(key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(f.severity.value, 5)
    ))

    if findings:
        story.append(Paragraph(f"Findings Detail ({len(findings)} total)", h2))
        story.append(section_divider())

        find_header = ["#", "Severity", "Title", "Host", "OWASP"]
        find_rows = [find_header]
        sev_col_colors = []

        for i, f in enumerate(findings[:50], 1):
            find_rows.append([
                str(i),
                f.severity.value.upper(),
                f.title[:72] + ("…" if len(f.title) > 72 else ""),
                (f.host or "—")[:30],
                f.owasp_category or "—",
            ])
            sev_col_colors.append(_SEV_BG.get(f.severity.value, _GRAY_100))

        ft = Table(find_rows, colWidths=[0.7 * cm, 2.2 * cm, 8.5 * cm, 3 * cm, 2.1 * cm])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_GRAY_800)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor(_GRAY_200)),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for row_idx, sev_level in enumerate(
            [f.severity.value for f in findings[:50]], start=1
        ):
            bg = colors.HexColor(_SEV_BG.get(sev_level, _GRAY_100))
            tc = colors.HexColor(_SEV_TEXT.get(sev_level, _GRAY_800))
            style_cmds.append(("BACKGROUND", (1, row_idx), (1, row_idx), bg))
            style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), tc))
            style_cmds.append(("FONTNAME", (1, row_idx), (1, row_idx), "Helvetica-Bold"))

        ft.setStyle(TableStyle(style_cmds))
        story.append(ft)

        if len(findings) > 50:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                f"… and {len(findings) - 50} additional findings not shown.",
                small,
            ))
        story.append(Spacer(1, 0.4 * cm))

    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)
    return buf.getvalue()


def _fallback_pdf(result: "ScanResult") -> bytes:
    content = f"PDF generation unavailable. Install reportlab.\n\nScan: {result.scan_id}\nTarget: {result.target}"
    return content.encode()
