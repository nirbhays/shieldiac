"""
ShieldIaC — GitHub/GitLab Webhook Endpoints
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from backend.config import get_settings
from backend.models.github import GitHubPREvent, GitHubPushEvent
from backend.models.scan import ScanRequest, ScanTrigger, ScanType
from backend.services.queue_service import QueueService
from backend.utils.security import verify_github_signature, verify_gitlab_token

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
queue_service = QueueService()


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    """Handle GitHub webhook events (push, pull_request, installation)."""
    body = await request.body()

    # Verify signature
    if settings.github_webhook_secret != "change-me-in-production":
        if not verify_github_signature(body, x_hub_signature_256 or "", settings.github_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()

    if x_github_event == "push":
        return await _handle_push(payload)
    elif x_github_event == "pull_request":
        return await _handle_pull_request(payload)
    elif x_github_event == "installation":
        return await _handle_installation(payload)
    elif x_github_event == "ping":
        return {"status": "pong"}
    else:
        logger.info("Ignoring GitHub event: %s", x_github_event)
        return {"status": "ignored", "event": x_github_event}


async def _handle_push(payload: dict) -> dict:
    """Handle a push event — trigger a full scan."""
    event = GitHubPushEvent(**payload)

    # Only scan default branch pushes
    if event.branch != event.repository.default_branch:
        return {"status": "skipped", "reason": "Not default branch"}

    job_id = await queue_service.enqueue_scan({
        "repo_url": event.repository.clone_url,
        "repo_full_name": event.repository.full_name,
        "branch": event.branch,
        "commit_sha": event.commit_sha,
        "trigger": ScanTrigger.WEBHOOK.value,
        "scan_type": ScanType.FULL.value,
    })

    return {"status": "queued", "job_id": job_id}


async def _handle_pull_request(payload: dict) -> dict:
    """Handle a PR event — trigger a PR scan with findings posted as comments."""
    event = GitHubPREvent(**payload)

    if event.action not in ("opened", "synchronize", "reopened"):
        return {"status": "skipped", "reason": f"PR action: {event.action}"}

    job_id = await queue_service.enqueue_scan({
        "repo_url": event.repository.clone_url,
        "repo_full_name": event.repository.full_name,
        "branch": event.pull_request.head.ref,
        "commit_sha": event.pull_request.head.sha,
        "pr_number": event.number,
        "trigger": ScanTrigger.WEBHOOK.value,
        "scan_type": ScanType.PR.value,
    })

    return {"status": "queued", "job_id": job_id, "pr": event.number}


async def _handle_installation(payload: dict) -> dict:
    """Handle a GitHub App installation event."""
    action = payload.get("action", "")
    installation_id = payload.get("installation", {}).get("id")
    logger.info("GitHub App installation %s: %s", action, installation_id)
    return {"status": "ok", "action": action}


@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: str = Header(None),
):
    """Handle GitLab webhook events."""
    if settings.gitlab_webhook_secret != "change-me-in-production":
        if not verify_gitlab_token(x_gitlab_token or "", settings.gitlab_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook token")

    payload = await request.json()
    event_type = payload.get("object_kind", "")

    if event_type == "push":
        project = payload.get("project", {})
        job_id = await queue_service.enqueue_scan({
            "repo_url": project.get("git_http_url", ""),
            "repo_full_name": project.get("path_with_namespace", ""),
            "branch": payload.get("ref", "").replace("refs/heads/", ""),
            "commit_sha": payload.get("after", ""),
            "trigger": ScanTrigger.WEBHOOK.value,
            "scan_type": ScanType.FULL.value,
            "source": "gitlab",
        })
        return {"status": "queued", "job_id": job_id}

    elif event_type == "merge_request":
        mr = payload.get("object_attributes", {})
        project = payload.get("project", {})
        job_id = await queue_service.enqueue_scan({
            "repo_url": project.get("git_http_url", ""),
            "repo_full_name": project.get("path_with_namespace", ""),
            "branch": mr.get("source_branch", ""),
            "commit_sha": mr.get("last_commit", {}).get("id", ""),
            "pr_number": mr.get("iid"),
            "trigger": ScanTrigger.WEBHOOK.value,
            "scan_type": ScanType.PR.value,
            "source": "gitlab",
        })
        return {"status": "queued", "job_id": job_id}

    return {"status": "ignored", "event": event_type}
