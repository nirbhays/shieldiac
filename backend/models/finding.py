"""
ShieldIaC — Security Finding Pydantic Models (API-facing)
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel


class FindingComplianceRef(BaseModel):
    framework: str
    control_id: str


class FindingResponse(BaseModel):
    id: str
    rule_id: str
    severity: str
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    ai_fix_suggestion: Optional[str] = None
    code_snippet: Optional[str] = None
    compliance: List[FindingComplianceRef] = []
    fingerprint: str
    scan_id: UUID
    created_at: datetime


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int


class FindingSeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class FindingsByRule(BaseModel):
    rule_id: str
    description: str
    severity: str
    count: int


class FindingsTrend(BaseModel):
    date: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
