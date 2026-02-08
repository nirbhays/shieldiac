"""
ShieldIaC — Compliance Framework Pydantic Models
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel


class ComplianceControl(BaseModel):
    control_id: str
    title: str
    description: str
    section: str
    status: str = "unknown"  # pass / fail / unknown / not_applicable
    finding_count: int = 0
    rule_ids: List[str] = []


class ComplianceFrameworkSummary(BaseModel):
    framework: str
    display_name: str
    version: str
    total_controls: int
    passing: int = 0
    failing: int = 0
    not_applicable: int = 0
    unknown: int = 0
    compliance_percentage: float = 0.0


class ComplianceReport(BaseModel):
    """Full compliance report for a single framework."""
    framework: str
    display_name: str
    version: str
    generated_at: str
    repo_url: Optional[str] = None
    scan_id: Optional[str] = None
    summary: ComplianceFrameworkSummary
    controls: List[ComplianceControl]
    recommendations: List[str] = []


class ComplianceDashboard(BaseModel):
    """Aggregated compliance status across all frameworks."""
    frameworks: List[ComplianceFrameworkSummary]
    overall_score: float = 0.0
    top_failing_controls: List[ComplianceControl] = []


class ComplianceControlMapping(BaseModel):
    """Mapping between a security rule and compliance controls."""
    rule_id: str
    mappings: Dict[str, List[str]]  # framework -> list of control IDs
