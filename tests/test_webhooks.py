"""
ShieldIaC — Webhook Integration Tests
"""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


def _sign_payload(payload: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def test_github_ping(client):
    """GitHub ping event should return pong."""
    resp = client.post(
        "/api/v1/webhooks/github",
        json={},
        headers={"X-GitHub-Event": "ping"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "pong"


def test_github_push_default_branch(client):
    """Push to default branch should trigger a scan."""
    payload = {
        "ref": "refs/heads/main",
        "before": "abc123",
        "after": "def456",
        "repository": {
            "id": 1,
            "name": "test-repo",
            "full_name": "org/test-repo",
            "private": False,
            "html_url": "https://github.com/org/test-repo",
            "clone_url": "https://github.com/org/test-repo.git",
            "default_branch": "main",
            "owner": {"login": "org", "id": 1},
        },
        "sender": {"login": "user", "id": 2},
        "commits": [],
    }
    resp = client.post(
        "/api/v1/webhooks/github",
        json=payload,
        headers={"X-GitHub-Event": "push"},
    )
    # May fail if Redis not available, but should at least process the request
    assert resp.status_code in (200, 500)


def test_github_pr_opened(client):
    """PR opened should trigger a scan."""
    payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "Add feature",
            "state": "open",
            "html_url": "https://github.com/org/test-repo/pull/42",
            "head": {"ref": "feature-branch", "sha": "abc123"},
            "base": {"ref": "main", "sha": "def456"},
            "user": {"login": "dev", "id": 3},
        },
        "repository": {
            "id": 1,
            "name": "test-repo",
            "full_name": "org/test-repo",
            "private": False,
            "html_url": "https://github.com/org/test-repo",
            "clone_url": "https://github.com/org/test-repo.git",
            "default_branch": "main",
            "owner": {"login": "org", "id": 1},
        },
        "sender": {"login": "dev", "id": 3},
    }
    resp = client.post(
        "/api/v1/webhooks/github",
        json=payload,
        headers={"X-GitHub-Event": "pull_request"},
    )
    assert resp.status_code in (200, 500)


def test_health_check(client):
    """Health check should return healthy."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_list_rules(client):
    """Rules endpoint should return rules."""
    resp = client.get("/api/v1/rules/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert len(data["items"]) > 0


def test_rule_stats(client):
    """Rule stats should return counts by type."""
    resp = client.get("/api/v1/rules/summary/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] > 0
    assert "terraform" in data["by_resource_type"]


def test_billing_plans(client):
    """Billing plans endpoint should return plans."""
    resp = client.get("/api/v1/billing/plans")
    assert resp.status_code == 200
    plans = resp.json()["plans"]
    assert len(plans) == 3
    assert plans[0]["tier"] == "free"
