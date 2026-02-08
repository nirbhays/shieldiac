"""
ShieldIaC — GitHub Webhook Pydantic Models
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class GitHubUser(BaseModel):
    login: str
    id: int
    avatar_url: Optional[str] = None


class GitHubRepository(BaseModel):
    id: int
    name: str
    full_name: str
    private: bool = False
    html_url: str
    clone_url: str
    default_branch: str = "main"
    owner: GitHubUser


class GitHubCommit(BaseModel):
    id: str
    message: str
    author: Dict[str, Any] = {}
    added: List[str] = []
    removed: List[str] = []
    modified: List[str] = []


class GitHubPushEvent(BaseModel):
    ref: str
    before: str
    after: str
    repository: GitHubRepository
    sender: GitHubUser
    commits: List[GitHubCommit] = []
    head_commit: Optional[GitHubCommit] = None

    @property
    def branch(self) -> str:
        return self.ref.replace("refs/heads/", "")

    @property
    def commit_sha(self) -> str:
        return self.after


class GitHubPRHead(BaseModel):
    ref: str
    sha: str


class GitHubPullRequest(BaseModel):
    number: int
    title: str
    state: str
    html_url: str
    head: GitHubPRHead
    base: GitHubPRHead
    user: GitHubUser


class GitHubPREvent(BaseModel):
    action: str
    number: int
    pull_request: GitHubPullRequest
    repository: GitHubRepository
    sender: GitHubUser


class GitHubInstallationEvent(BaseModel):
    action: str
    installation: Dict[str, Any]
    repositories: List[Dict[str, Any]] = []
    sender: GitHubUser
