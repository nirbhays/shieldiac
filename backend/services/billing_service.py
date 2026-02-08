"""
ShieldIaC — Stripe Billing Service
"""
from __future__ import annotations

import logging
from typing import Optional

from backend.config import get_settings
from backend.models.billing import (
    BillingPortalResponse, CheckoutRequest, CheckoutResponse,
    PlanTier, Subscription, UsageSummary,
)

logger = logging.getLogger(__name__)
settings = get_settings()


class BillingService:
    """Manages Stripe subscriptions and billing."""

    def __init__(self):
        self._stripe = None

    def _get_stripe(self):
        if self._stripe is None:
            try:
                import stripe
                stripe.api_key = settings.stripe_secret_key
                self._stripe = stripe
            except ImportError:
                logger.error("stripe package not installed")
                return None
        return self._stripe

    async def create_checkout_session(
        self, request: CheckoutRequest, org_id: str, customer_email: str
    ) -> Optional[CheckoutResponse]:
        """Create a Stripe Checkout session."""
        stripe = self._get_stripe()
        if not stripe:
            return None

        price_map = {
            (PlanTier.PRO, "monthly"): settings.stripe_price_pro_monthly,
            (PlanTier.PRO, "yearly"): settings.stripe_price_pro_yearly,
            (PlanTier.ENTERPRISE, "monthly"): settings.stripe_price_enterprise_monthly,
            (PlanTier.ENTERPRISE, "yearly"): settings.stripe_price_enterprise_yearly,
        }

        price_id = price_map.get((request.plan, request.billing_period))
        if not price_id:
            logger.error("No price ID for %s/%s", request.plan, request.billing_period)
            return None

        try:
            session = stripe.checkout.Session.create(
                mode="subscription",
                customer_email=customer_email,
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=request.success_url,
                cancel_url=request.cancel_url,
                metadata={"org_id": org_id, "plan": request.plan.value},
            )
            return CheckoutResponse(
                checkout_url=session.url,
                session_id=session.id,
            )
        except Exception:
            logger.exception("Stripe checkout creation failed")
            return None

    async def create_billing_portal(
        self, customer_id: str, return_url: str
    ) -> Optional[BillingPortalResponse]:
        """Create a Stripe Billing Portal session."""
        stripe = self._get_stripe()
        if not stripe:
            return None
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            return BillingPortalResponse(portal_url=session.url)
        except Exception:
            logger.exception("Stripe portal creation failed")
            return None

    async def handle_webhook_event(self, event: dict) -> bool:
        """Process a Stripe webhook event."""
        event_type = event.get("type", "")

        handlers = {
            "checkout.session.completed": self._handle_checkout_complete,
            "customer.subscription.updated": self._handle_subscription_update,
            "customer.subscription.deleted": self._handle_subscription_cancel,
            "invoice.payment_failed": self._handle_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            return await handler(event.get("data", {}).get("object", {}))

        logger.debug("Unhandled Stripe event: %s", event_type)
        return True

    async def _handle_checkout_complete(self, session: dict) -> bool:
        org_id = session.get("metadata", {}).get("org_id")
        plan = session.get("metadata", {}).get("plan")
        subscription_id = session.get("subscription")
        logger.info("Checkout complete: org=%s plan=%s sub=%s", org_id, plan, subscription_id)
        # TODO: Update org subscription in database
        return True

    async def _handle_subscription_update(self, subscription: dict) -> bool:
        logger.info("Subscription updated: %s status=%s", subscription.get("id"), subscription.get("status"))
        return True

    async def _handle_subscription_cancel(self, subscription: dict) -> bool:
        logger.info("Subscription cancelled: %s", subscription.get("id"))
        return True

    async def _handle_payment_failed(self, invoice: dict) -> bool:
        logger.warning("Payment failed: %s customer=%s", invoice.get("id"), invoice.get("customer"))
        return True
