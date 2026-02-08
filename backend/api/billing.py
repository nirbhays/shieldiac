"""
ShieldIaC — Billing API Endpoints
"""
from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException, Request

from backend.config import get_settings
from backend.models.billing import (
    PLANS, CheckoutRequest, CheckoutResponse, BillingPortalResponse, PlanTier,
)
from backend.services.billing_service import BillingService
from backend.utils.security import verify_stripe_signature

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/billing", tags=["Billing"])
billing = BillingService()


@router.get("/plans")
async def get_plans():
    """Get available pricing plans."""
    return {"plans": [p.dict() for p in PLANS]}


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(request: CheckoutRequest):
    """Create a Stripe Checkout session."""
    # In production, extract org_id and email from auth token
    result = await billing.create_checkout_session(
        request, org_id="demo-org", customer_email="user@example.com"
    )
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create checkout session")
    return result


@router.post("/portal", response_model=BillingPortalResponse)
async def create_portal(return_url: str):
    """Create a Stripe Billing Portal session."""
    # In production, look up customer_id from auth token
    result = await billing.create_billing_portal("cus_demo", return_url)
    if not result:
        raise HTTPException(status_code=500, detail="Failed to create portal session")
    return result


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    body = await request.body()
    sig = request.headers.get("stripe-signature", "")

    if settings.stripe_webhook_secret:
        if not verify_stripe_signature(body, sig, settings.stripe_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid Stripe signature")

    payload = await request.json()
    await billing.handle_webhook_event(payload)
    return {"status": "ok"}


@router.get("/usage")
async def get_usage():
    """Get current usage for the authenticated organization."""
    return {
        "plan": PlanTier.FREE.value,
        "scans_used": 12,
        "scans_limit": 50,
        "repos_used": 2,
        "repos_limit": 3,
    }
