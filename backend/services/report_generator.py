"""
ShieldIaC — Report Generator

Generates PDF compliance reports using the reportlab library.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Optional

from backend.models.compliance import ComplianceReport

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates PDF compliance reports."""

    async def generate_pdf(self, report: ComplianceReport) -> Optional[bytes]:
        """Generate a PDF report and return the bytes."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.colors import HexColor
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            logger.error("reportlab not installed — cannot generate PDF")
            return None

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle", parent=styles["Title"],
            fontSize=24, spaceAfter=20,
            textColor=HexColor("#1a1a2e"),
        )
        heading_style = ParagraphStyle(
            "CustomHeading", parent=styles["Heading2"],
            fontSize=16, spaceBefore=20, spaceAfter=10,
            textColor=HexColor("#16213e"),
        )
        body_style = styles["Normal"]

        story = []

        # ── Cover Page ──────────────────────────────────────────────
        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph("🛡️ ShieldIaC", title_style))
        story.append(Paragraph(f"{report.display_name} Compliance Report", heading_style))
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph(f"<b>Version:</b> {report.version}", body_style))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body_style))
        if report.repo_url:
            story.append(Paragraph(f"<b>Repository:</b> {report.repo_url}", body_style))
        story.append(PageBreak())

        # ── Executive Summary ───────────────────────────────────────
        story.append(Paragraph("Executive Summary", heading_style))
        s = report.summary
        story.append(Paragraph(
            f"This report evaluates compliance against {s.display_name} ({s.version}). "
            f"Out of {s.total_controls} controls evaluated, {s.passing} are passing "
            f"and {s.failing} require remediation. "
            f"<b>Overall compliance: {s.compliance_percentage:.1f}%</b>",
            body_style,
        ))
        story.append(Spacer(1, 0.3 * inch))

        # Summary table
        summary_data = [
            ["Metric", "Value"],
            ["Total Controls", str(s.total_controls)],
            ["Passing", str(s.passing)],
            ["Failing", str(s.failing)],
            ["Not Applicable", str(s.not_applicable)],
            ["Compliance %", f"{s.compliance_percentage:.1f}%"],
        ]
        t = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#f8f9fa"), HexColor("#ffffff")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5 * inch))

        # ── Control Details ─────────────────────────────────────────
        story.append(Paragraph("Control Details", heading_style))
        for control in report.controls:
            status_icon = "✅" if control.status == "pass" else "❌"
            story.append(Paragraph(
                f"{status_icon} <b>{control.control_id}</b> — {control.title}",
                body_style,
            ))
            story.append(Paragraph(f"<i>{control.description}</i>", body_style))
            if control.status == "fail":
                story.append(Paragraph(
                    f"  ⚠️ {control.finding_count} finding(s) — Rules: {', '.join(control.rule_ids[:5])}",
                    body_style,
                ))
            story.append(Spacer(1, 0.15 * inch))

        # ── Recommendations ─────────────────────────────────────────
        if report.recommendations:
            story.append(PageBreak())
            story.append(Paragraph("Recommendations", heading_style))
            for i, rec in enumerate(report.recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", body_style))
                story.append(Spacer(1, 0.1 * inch))

        # Build PDF
        doc.build(story)
        return buffer.getvalue()
