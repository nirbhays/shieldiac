"""
ShieldIaC — Webhook Security Utilities

Verifies webhook signatures for GitHub, GitLab, and Stripe.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify a GitHub webhook signature (HMAC-SHA256).

    GitHub sends the signature in the `X-Hub-Signature-256` header as
    `sha256=<hex_digest>`.
    """
    if not signature or not secret:
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def verify_gitlab_token(token: str, expected: str) -> bool:
    """Verify a GitLab webhook token.

    GitLab sends the secret token in the `X-Gitlab-Token` header.
    """
    if not token or not expected:
        return False
    return hmac.compare_digest(token, expected)


def verify_stripe_signature(
    payload: bytes, signature: str, secret: str
) -> bool:
    """Verify a Stripe webhook signature.

    Uses the stripe library's built-in verification when available,
    falls back to manual HMAC verification.
    """
    try:
        import stripe
        stripe.Webhook.construct_event(payload, signature, secret)
        return True
    except ImportError:
        return _manual_stripe_verify(payload, signature, secret)
    except Exception as e:
        logger.warning("Stripe signature verification failed: %s", e)
        return False


def _manual_stripe_verify(payload: bytes, signature: str, secret: str) -> bool:
    """Manual Stripe signature verification (fallback)."""
    if not signature:
        return False

    # Parse the signature header
    elements = dict(
        item.split("=", 1) for item in signature.split(",")
        if "=" in item
    )
    timestamp = elements.get("t", "")
    v1_sig = elements.get("v1", "")

    if not timestamp or not v1_sig:
        return False

    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, v1_sig)


def sanitize_path(path: str) -> Optional[str]:
    """Sanitize a file path to prevent directory traversal attacks."""
    import os
    # Normalize the path
    normalized = os.path.normpath(path)
    # Reject paths that try to escape
    if normalized.startswith("..") or "/.." in normalized or "\\.." in normalized:
        return None
    # Reject absolute paths
    if os.path.isabs(normalized):
        return None
    return normalized
