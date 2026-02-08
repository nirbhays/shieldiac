"""
ShieldIaC — Rules Management API Endpoints
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from backend.models.rule import (
    CustomRuleCreate, CustomRuleUpdate, RuleComplianceMapping,
    RuleListResponse, RuleResponse,
)
from backend.rules.base import registry, ResourceType, Severity

router = APIRouter(prefix="/rules", tags=["Rules"])


@router.get("/", response_model=RuleListResponse)
async def list_rules(
    resource_type: Optional[str] = None,
    severity: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    """List all security rules with filtering."""
    rules = registry.all()

    # Apply filters
    if resource_type:
        try:
            rt = ResourceType(resource_type)
            rules = [r for r in rules if r.resource_type == rt]
        except ValueError:
            pass

    if severity:
        try:
            sev = Severity(severity.upper())
            rules = [r for r in rules if r.severity == sev]
        except ValueError:
            pass

    if tag:
        rules = [r for r in rules if tag in r.tags]

    if search:
        search_lower = search.lower()
        rules = [r for r in rules if search_lower in r.id.lower() or search_lower in r.description.lower()]

    total = len(rules)
    start = (page - 1) * page_size
    end = start + page_size
    page_rules = rules[start:end]

    items = [
        RuleResponse(
            id=r.id,
            description=r.description,
            severity=r.severity.value,
            resource_type=r.resource_type.value,
            remediation=r.remediation,
            compliance=[
                RuleComplianceMapping(
                    framework=c.framework.value,
                    control_id=c.control_id,
                    control_description=c.control_description,
                )
                for c in r.compliance
            ],
            tags=list(r.tags),
            enabled=r.enabled,
        )
        for r in page_rules
    ]

    return RuleListResponse(items=items, total=total)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str):
    """Get details for a specific rule."""
    rule_cls = registry.get(rule_id)
    if not rule_cls:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    return RuleResponse(
        id=rule_cls.id,
        description=rule_cls.description,
        severity=rule_cls.severity.value,
        resource_type=rule_cls.resource_type.value,
        remediation=rule_cls.remediation,
        compliance=[
            RuleComplianceMapping(
                framework=c.framework.value,
                control_id=c.control_id,
                control_description=c.control_description,
            )
            for c in rule_cls.compliance
        ],
        tags=list(rule_cls.tags),
        enabled=rule_cls.enabled,
    )


@router.get("/summary/stats")
async def get_rule_stats():
    """Get rule statistics by resource type and severity."""
    rules = registry.all()
    by_type = {}
    by_severity = {}
    for r in rules:
        rt = r.resource_type.value
        by_type[rt] = by_type.get(rt, 0) + 1
        sev = r.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len(rules),
        "by_resource_type": by_type,
        "by_severity": by_severity,
    }


@router.post("/custom")
async def create_custom_rule(rule: CustomRuleCreate):
    """Create a custom rule (Pro/Enterprise plan required)."""
    # TODO: Store in database, validate Rego policy
    return {"status": "created", "rule": rule.dict()}


@router.put("/custom/{rule_id}")
async def update_custom_rule(rule_id: str, update: CustomRuleUpdate):
    """Update a custom rule."""
    return {"status": "updated", "rule_id": rule_id}


@router.delete("/custom/{rule_id}")
async def delete_custom_rule(rule_id: str):
    """Delete a custom rule."""
    return {"status": "deleted", "rule_id": rule_id}
