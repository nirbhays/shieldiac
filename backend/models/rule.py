"""
ShieldIaC — Security Rule Pydantic Models (API-facing)
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class RuleComplianceMapping(BaseModel):
    framework: str
    control_id: str
    control_description: str = ""


class RuleResponse(BaseModel):
    id: str
    description: str
    severity: str
    resource_type: str
    remediation: str
    compliance: List[RuleComplianceMapping] = []
    tags: List[str] = []
    enabled: bool = True


class RuleListResponse(BaseModel):
    items: List[RuleResponse]
    total: int


class CustomRuleCreate(BaseModel):
    """User-defined custom rule via OPA/Rego policy."""
    name: str
    description: str
    severity: str
    resource_type: str
    remediation: str
    rego_policy: str
    tags: List[str] = []
    compliance_mappings: List[RuleComplianceMapping] = []


class CustomRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    remediation: Optional[str] = None
    rego_policy: Optional[str] = None
    enabled: Optional[bool] = None
    tags: Optional[List[str]] = None
