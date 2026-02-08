"""
ShieldIaC — GitHub Service

Handles all GitHub API interactions: cloning repos, posting PR comments,
creating check runs, and managing installations.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from backend.config import get_settings
from backend.rules.base import Finding
from backend.utils.formatting import format_pr_comment

logger = logging.getLogger(__name__)
settings = get_settings()


class GitHubService:
    """Interacts with the GitHub API for PR comments, checks, and file fetching."""

    def __init__(self, token: Optional[str] = None):
        self.base_url = settings.github_api_base
        self.token = token
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "ShieldIaC/1.0",
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=30.0,
            )
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── File Fetching ────────────────────────────────────────────────

    async def get_repo_files(
        self,
        owner: str,
        repo: str,
        ref: str = "main",
        path: str = "",
    ) -> List[Dict[str, str]]:
        """Recursively fetch all IaC files from a repository."""
        client = await self._get_client()
        files = []
        await self._fetch_tree(client, owner, repo, ref, path, files)
        return files

    async def _fetch_tree(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        ref: str,
        path: str,
        files: List[Dict[str, str]],
    ):
        """Recursively traverse the repo tree."""
        url = f"/repos/{owner}/{repo}/contents/{path}"
        resp = await client.get(url, params={"ref": ref})
        if resp.status_code != 200:
            logger.warning("GitHub API error %d fetching %s", resp.status_code, url)
            return

        items = resp.json()
        if isinstance(items, dict):
            items = [items]

        for item in items:
            if item["type"] == "file" and self._is_iac_file(item["name"]):
                content = await self._get_file_content(client, owner, repo, item["path"], ref)
                if content:
                    files.append({"path": item["path"], "content": content})
            elif item["type"] == "dir":
                await self._fetch_tree(client, owner, repo, ref, item["path"], files)

    async def _get_file_content(
        self, client: httpx.AsyncClient, owner: str, repo: str, path: str, ref: str
    ) -> Optional[str]:
        """Fetch raw file content."""
        url = f"/repos/{owner}/{repo}/contents/{path}"
        resp = await client.get(
            url,
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.v3.raw"},
        )
        if resp.status_code == 200:
            return resp.text
        return None

    @staticmethod
    def _is_iac_file(filename: str) -> bool:
        """Check if a file is an IaC file we should scan."""
        lower = filename.lower()
        return (
            lower.endswith(".tf")
            or lower.endswith(".tf.json")
            or lower.endswith(".yaml")
            or lower.endswith(".yml")
            or lower == "dockerfile"
            or lower.endswith(".dockerfile")
        )

    # ── PR Comments ──────────────────────────────────────────────────

    async def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        findings: List[Finding],
        scan_summary: Dict[str, Any],
    ) -> bool:
        """Post a formatted PR comment with scan results."""
        client = await self._get_client()
        comment_body = format_pr_comment(findings, scan_summary)

        # Check for existing ShieldIaC comment to update
        existing_id = await self._find_existing_comment(client, owner, repo, pr_number)

        if existing_id:
            resp = await client.patch(
                f"/repos/{owner}/{repo}/issues/comments/{existing_id}",
                json={"body": comment_body},
            )
        else:
            resp = await client.post(
                f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
                json={"body": comment_body},
            )

        if resp.status_code in (200, 201):
            logger.info("PR comment posted on %s/%s#%d", owner, repo, pr_number)
            return True
        else:
            logger.error("Failed to post PR comment: %d %s", resp.status_code, resp.text)
            return False

    async def _find_existing_comment(
        self, client: httpx.AsyncClient, owner: str, repo: str, pr_number: int
    ) -> Optional[int]:
        """Find an existing ShieldIaC comment to update."""
        resp = await client.get(f"/repos/{owner}/{repo}/issues/{pr_number}/comments")
        if resp.status_code != 200:
            return None
        for comment in resp.json():
            if "<!-- shieldiac-scan -->" in comment.get("body", ""):
                return comment["id"]
        return None

    # ── Check Runs ───────────────────────────────────────────────────

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        findings: List[Finding],
        scan_summary: Dict[str, Any],
    ) -> bool:
        """Create a GitHub Check Run with scan results."""
        client = await self._get_client()

        conclusion = "success"
        if scan_summary.get("critical", 0) > 0:
            conclusion = "failure"
        elif scan_summary.get("high", 0) > 0:
            conclusion = "failure"
        elif scan_summary.get("medium", 0) > 0:
            conclusion = "neutral"

        annotations = []
        for f in findings[:50]:  # GitHub limits annotations
            annotations.append({
                "path": f.file_path,
                "start_line": max(1, f.line_number),
                "end_line": max(1, f.line_number),
                "annotation_level": self._severity_to_level(f.severity.value),
                "message": f"{f.description}\n\nRemediation: {f.remediation}",
                "title": f"[{f.severity.value}] {f.rule_id}",
            })

        body = {
            "name": "ShieldIaC Security Scan",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": f"ShieldIaC: {scan_summary.get('total_findings', 0)} findings (Score: {scan_summary.get('security_score', 0):.0f}/100)",
                "summary": self._build_check_summary(scan_summary),
                "annotations": annotations,
            },
        }

        resp = await client.post(f"/repos/{owner}/{repo}/check-runs", json=body)
        return resp.status_code == 201

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        return {
            "CRITICAL": "failure",
            "HIGH": "failure",
            "MEDIUM": "warning",
            "LOW": "notice",
            "INFO": "notice",
        }.get(severity, "notice")

    @staticmethod
    def _build_check_summary(summary: Dict[str, Any]) -> str:
        return (
            f"**Security Score:** {summary.get('security_score', 0):.0f}/100 "
            f"(Grade: {summary.get('grade', 'N/A')})\n\n"
            f"| Severity | Count |\n|---|---|\n"
            f"| 🔴 Critical | {summary.get('critical', 0)} |\n"
            f"| 🟠 High | {summary.get('high', 0)} |\n"
            f"| 🟡 Medium | {summary.get('medium', 0)} |\n"
            f"| 🔵 Low | {summary.get('low', 0)} |\n"
            f"| ⚪ Info | {summary.get('info', 0)} |\n"
        )
