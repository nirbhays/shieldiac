"""
ShieldIaC — Billing Pydantic Models
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class PlanTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class BillingPlan(BaseModel):
    tier: PlanTier
    name: str
    price_monthly: float
    price_yearly: float
    features: List[str]
    max_repos: int
    max_scans_per_month: int
    ai_fix_suggestions: bool
    compliance_reports: bool
    custom_rules: bool
    sla: Optional[str] = None


class Subscription(BaseModel):
    id: str
    org_id: str
    plan: PlanTier
    status: str  # active, canceled, past_due, trialing
    stripe_subscription_id: Optional[str] = None
    current_period_start: datetime
    current_period_end: datetime
    cancel_at_period_end: bool = False


class UsageSummary(BaseModel):
    org_id: str
    plan: PlanTier
    scans_used: int
    scans_limit: int
    repos_used: int
    repos_limit: int
    period_start: datetime
    period_end: datetime


class CheckoutRequest(BaseModel):
    plan: PlanTier
    billing_period: str = "monthly"  # monthly | yearly
    success_url: str
    cancel_url: str


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str


class BillingPortalResponse(BaseModel):
    portal_url: str


# ── Pricing Constants ────────────────────────────────────────────────────

PLANS: List[BillingPlan] = [
    BillingPlan(
        tier=PlanTier.FREE,
        name="Free",
        price_monthly=0,
        price_yearly=0,
        features=[
            "3 repositories",
            "50 scans/month",
            "100+ built-in rules",
            "GitHub integration",
            "PR comments",
            "Basic dashboard",
        ],
        max_repos=3,
        max_scans_per_month=50,
        ai_fix_suggestions=False,
        compliance_reports=False,
        custom_rules=False,
    ),
    BillingPlan(
        tier=PlanTier.PRO,
        name="Pro",
        price_monthly=29,
        price_yearly=290,
        features=[
            "Unlimited repositories",
            "Unlimited scans",
            "200+ built-in rules",
            "GitHub + GitLab integration",
            "AI-powered fix suggestions",
            "Compliance reports (SOC2, HIPAA, PCI-DSS)",
            "Custom rules",
            "Priority support",
            "Team management",
        ],
        max_repos=999999,
        max_scans_per_month=999999,
        ai_fix_suggestions=True,
        compliance_reports=True,
        custom_rules=True,
        sla="99.9% uptime",
    ),
    BillingPlan(
        tier=PlanTier.ENTERPRISE,
        name="Enterprise",
        price_monthly=99,
        price_yearly=990,
        features=[
            "Everything in Pro",
            "SSO / SAML",
            "Dedicated support engineer",
            "Custom compliance frameworks",
            "On-premise scanner option",
            "Audit logs",
            "SLA: 99.99% uptime",
            "Unlimited users",
        ],
        max_repos=999999,
        max_scans_per_month=999999,
        ai_fix_suggestions=True,
        compliance_reports=True,
        custom_rules=True,
        sla="99.99% uptime",
    ),
]
