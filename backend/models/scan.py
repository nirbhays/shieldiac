"""
ShieldIaC — Scan Request/Result Pydantic Models
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTrigger(str, Enum):
    WEBHOOK = "webhook"
    MANUAL = "manual"
    SCHEDULE = "schedule"
    API = "api"


class ScanType(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    PR = "pull_request"


class ScanRequest(BaseModel):
    """Incoming request to initiate a scan."""
    repo_url: str
    branch: str = "main"
    commit_sha: Optional[str] = None
    pr_number: Optional[int] = None
    scan_type: ScanType = ScanType.FULL
    trigger: ScanTrigger = ScanTrigger.API
    paths: List[str] = Field(default_factory=list, description="Specific paths to scan (empty = all)")
    org_id: Optional[str] = None
    user_id: Optional[str] = None


class ScanFileResult(BaseModel):
    """Findings for a single scanned file."""
    file_path: str
    file_type: str
    findings_count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummary(BaseModel):
    """High-level scan result summary."""
    total_files_scanned: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    security_score: float = Field(default=100.0, ge=0, le=100)
    grade: str = "A"
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    """Complete scan result."""
    id: UUID = Field(default_factory=uuid4)
    repo_url: str
    branch: str
    commit_sha: Optional[str] = None
    pr_number: Optional[int] = None
    status: ScanStatus = ScanStatus.QUEUED
    trigger: ScanTrigger = ScanTrigger.API
    scan_type: ScanType = ScanType.FULL
    summary: ScanSummary = Field(default_factory=ScanSummary)
    file_results: List[ScanFileResult] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    error_message: Optional[str] = None


class ScanListItem(BaseModel):
    """Lightweight scan item for list views."""
    id: UUID
    repo_url: str
    branch: str
    status: ScanStatus
    trigger: ScanTrigger
    summary: ScanSummary
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    items: List[ScanListItem]
    total: int
    page: int
    page_size: int
