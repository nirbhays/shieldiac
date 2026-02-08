"""
ShieldIaC — Scan Management API Endpoints
"""
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from backend.models.scan import (
    ScanListResponse, ScanRequest, ScanResult, ScanStatus,
)
from backend.services.queue_service import QueueService
from backend.services.scanner_engine import ScannerEngine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])
queue_service = QueueService()
scanner_engine = ScannerEngine()


@router.post("/", response_model=dict)
async def create_scan(request: ScanRequest):
    """Create a new scan job.

    The scan is enqueued and processed asynchronously.
    Returns the job ID for status polling.
    """
    job_id = await queue_service.enqueue_scan({
        "repo_url": request.repo_url,
        "branch": request.branch,
        "commit_sha": request.commit_sha,
        "pr_number": request.pr_number,
        "scan_type": request.scan_type.value,
        "trigger": request.trigger.value,
        "paths": request.paths,
        "org_id": request.org_id,
        "user_id": request.user_id,
    })

    return {"job_id": job_id, "status": "queued"}


@router.post("/inline", response_model=dict)
async def scan_inline(
    files: list[dict],
    repo_name: str = Query(default="inline-scan"),
):
    """Scan files inline (for testing or small scans).

    Accepts a list of files with `path` and `content` fields.
    Returns results synchronously.
    """
    if len(files) > 50:
        raise HTTPException(status_code=400, detail="Too many files (max 50 for inline scan)")

    result = await scanner_engine.scan_files(files, repo_name=repo_name)
    # Convert findings to dicts
    result["findings"] = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "description": f.description,
            "remediation": f.remediation,
            "ai_fix_suggestion": f.ai_fix_suggestion,
            "fingerprint": f.fingerprint,
        }
        for f in result["findings"]
    ]
    return result


@router.get("/{job_id}")
async def get_scan_status(job_id: str):
    """Get the status of a scan job."""
    status = await queue_service.get_job_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return status


@router.get("/")
async def list_scans(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = None,
    repo_url: Optional[str] = None,
):
    """List scans with pagination and filtering.

    Note: In production, this queries PostgreSQL.
    For now, returns a placeholder.
    """
    # TODO: Replace with database query
    return {
        "items": [],
        "total": 0,
        "page": page,
        "page_size": page_size,
    }
