"""
ShieldIaC — Compliance Report API Endpoints
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from backend.rules.base import ComplianceFramework
from backend.services.compliance_mapper import ComplianceMapper
from backend.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])
mapper = ComplianceMapper()
generator = ReportGenerator()


@router.get("/compliance/{framework}")
async def get_compliance_report(
    framework: str,
    scan_id: str = Query(default=None),
    repo_url: str = Query(default=None),
):
    """Get a compliance report for a specific framework."""
    try:
        fw = ComplianceFramework(framework)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework: {framework}. Valid: {[f.value for f in ComplianceFramework]}",
        )

    # In production, fetch findings from database by scan_id
    findings = []  # TODO: query database
    report = mapper.generate_report(fw, findings, repo_url or "", scan_id or "")
    return report


@router.get("/compliance/{framework}/pdf")
async def download_compliance_pdf(
    framework: str,
    scan_id: str = Query(default=None),
    repo_url: str = Query(default=None),
):
    """Download a compliance report as PDF."""
    try:
        fw = ComplianceFramework(framework)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")

    findings = []  # TODO: query database
    report = mapper.generate_report(fw, findings, repo_url or "", scan_id or "")
    pdf_bytes = await generator.generate_pdf(report)

    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="PDF generation failed (reportlab may not be installed)")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=shieldiac-{framework}-report.pdf"},
    )


@router.get("/compliance")
async def get_compliance_dashboard():
    """Get aggregated compliance dashboard across all frameworks."""
    findings = []  # TODO: query database
    dashboard = mapper.generate_dashboard(findings)
    return dashboard
