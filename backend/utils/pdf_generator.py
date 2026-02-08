"""
ShieldIaC — PDF Report Generation Utility

Thin wrapper around report_generator service for direct PDF creation.
"""
from __future__ import annotations

import asyncio
from typing import List, Optional

from backend.models.compliance import ComplianceReport
from backend.rules.base import ComplianceFramework, Finding
from backend.services.compliance_mapper import ComplianceMapper
from backend.services.report_generator import ReportGenerator


async def generate_compliance_pdf(
    framework: ComplianceFramework,
    findings: List[Finding],
    repo_url: str = "",
    scan_id: str = "",
) -> Optional[bytes]:
    """Generate a compliance PDF report.

    Returns PDF bytes or None if generation fails.
    """
    mapper = ComplianceMapper()
    report = mapper.generate_report(framework, findings, repo_url, scan_id)

    generator = ReportGenerator()
    return await generator.generate_pdf(report)


def generate_compliance_pdf_sync(
    framework: ComplianceFramework,
    findings: List[Finding],
    repo_url: str = "",
    scan_id: str = "",
) -> Optional[bytes]:
    """Synchronous wrapper for PDF generation."""
    return asyncio.run(generate_compliance_pdf(framework, findings, repo_url, scan_id))
