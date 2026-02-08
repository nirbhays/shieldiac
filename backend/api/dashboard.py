"""
ShieldIaC — Dashboard API Endpoints
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from typing import Optional

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def get_overview(org_id: Optional[str] = None):
    """Get security overview dashboard data."""
    # In production, aggregates from PostgreSQL
    return {
        "security_score": 85.0,
        "grade": "B",
        "total_repos": 12,
        "total_scans_this_month": 156,
        "total_findings": 342,
        "severity_breakdown": {
            "critical": 5,
            "high": 28,
            "medium": 89,
            "low": 145,
            "info": 75,
        },
        "trend": "improving",
        "recent_scans": [],
        "top_failing_rules": [],
    }


@router.get("/repos")
async def get_repos(
    org_id: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort_by: str = Query(default="score", regex="^(score|name|last_scan)$"),
):
    """Get repository list with security scores."""
    return {
        "items": [],
        "total": 0,
        "page": page,
        "page_size": page_size,
    }


@router.get("/repos/{repo_id}")
async def get_repo_detail(repo_id: str):
    """Get detailed security info for a specific repo."""
    return {
        "id": repo_id,
        "name": "",
        "url": "",
        "security_score": 0,
        "grade": "?",
        "findings": [],
        "trend": [],
        "last_scan": None,
    }


@router.get("/trends")
async def get_trends(
    org_id: Optional[str] = None,
    days: int = Query(default=30, ge=7, le=365),
):
    """Get security score trends over time."""
    return {
        "data_points": [],
        "period_days": days,
    }
