"""
ShieldIaC — Terraform AWS IAM Security Rules

Covers: wildcard policies, MFA, access keys rotation, password policy,
        assume role restrictions, inline policies, cross-account access.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _parse_policy(policy_str) -> Dict:
    if isinstance(policy_str, dict):
        return policy_str
    if isinstance(policy_str, str):
        try:
            return json.loads(policy_str)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _get_statements(policy: Dict) -> List[Dict]:
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return stmts


# ─── IAM-001  Wildcard actions ───────────────────────────────────────────

@registry.register
class IAMWildcardActions(BaseRule):
    id = "SHLD-IAM-001"
    description = "IAM policy grants wildcard (*) actions"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Replace `Action: \"*\"` with specific actions following the principle "
        "of least privilege."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.16", "Ensure IAM policies do not allow full admin"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.3", "Role-based access"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "7.1", "Limit access to system components"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(1)", "Access control"),
    ]
    tags = ["iam", "policy", "aws", "least-privilege"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            return []
        policy = _parse_policy(resource.get("config", {}).get("policy", ""))
        for stmt in _get_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if a == "*":
                    return [self.make_finding(
                        resource_name=resource.get("name", "unknown"),
                        file_path=context.file_path,
                        line_number=resource.get("line", 0),
                    )]
        return []


# ─── IAM-002  Wildcard resources ─────────────────────────────────────────

@registry.register
class IAMWildcardResources(BaseRule):
    id = "SHLD-IAM-002"
    description = "IAM policy grants access to all resources (*)"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Scope `Resource` to specific ARNs instead of `*`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.16", "Least privilege"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.3", "Role-based access"),
    ]
    tags = ["iam", "policy", "aws", "least-privilege"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
            return []
        policy = _parse_policy(resource.get("config", {}).get("policy", ""))
        for stmt in _get_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if "*" in resources:
                return [self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                )]
        return []


# ─── IAM-003  User has inline policy ─────────────────────────────────────

@registry.register
class IAMUserInlinePolicy(BaseRule):
    id = "SHLD-IAM-003"
    description = "IAM user has an inline policy attached directly"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Use managed policies attached to groups instead of inline policies "
        "on individual users."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.15", "Ensure no inline policies"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.3", "Role-based access"),
    ]
    tags = ["iam", "inline-policy", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_user_policy":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-004  Password policy length ─────────────────────────────────────

@registry.register
class IAMPasswordPolicyLength(BaseRule):
    id = "SHLD-IAM-004"
    description = "IAM password policy requires fewer than 14 characters"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `minimum_password_length` to at least 14."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.8", "Ensure password policy length >= 14"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "8.2.3", "Password complexity requirements"),
    ]
    tags = ["iam", "password-policy", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_account_password_policy":
            return []
        min_len = resource.get("config", {}).get("minimum_password_length", 0)
        if isinstance(min_len, int) and min_len >= 14:
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-005  Password policy reuse ──────────────────────────────────────

@registry.register
class IAMPasswordReuse(BaseRule):
    id = "SHLD-IAM-005"
    description = "IAM password policy does not prevent password reuse (require >= 24)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `password_reuse_prevention` to 24."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.9", "Ensure password reuse prevention"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "8.2.5", "Do not allow reuse of last 4 passwords"),
    ]
    tags = ["iam", "password-policy", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_account_password_policy":
            return []
        reuse = resource.get("config", {}).get("password_reuse_prevention", 0)
        if isinstance(reuse, int) and reuse >= 24:
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-006  Password policy requires uppercase ─────────────────────────

@registry.register
class IAMPasswordUppercase(BaseRule):
    id = "SHLD-IAM-006"
    description = "IAM password policy does not require uppercase characters"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `require_uppercase_characters = true`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.5", "Ensure uppercase letters required"),
    ]
    tags = ["iam", "password-policy", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_account_password_policy":
            return []
        val = resource.get("config", {}).get("require_uppercase_characters")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-007  Password policy requires symbols ───────────────────────────

@registry.register
class IAMPasswordSymbols(BaseRule):
    id = "SHLD-IAM-007"
    description = "IAM password policy does not require symbols"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `require_symbols = true`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.7", "Ensure symbols required"),
    ]
    tags = ["iam", "password-policy", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_account_password_policy":
            return []
        val = resource.get("config", {}).get("require_symbols")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-008  Assume role without external ID ────────────────────────────

@registry.register
class IAMAssumeRoleExternalId(BaseRule):
    id = "SHLD-IAM-008"
    description = "IAM role trust policy allows cross-account assume without external ID condition"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a `Condition` requiring `sts:ExternalId` in the assume role policy "
        "for cross-account trust relationships."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["iam", "assume-role", "aws", "cross-account"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_role":
            return []
        policy = _parse_policy(resource.get("config", {}).get("assume_role_policy", ""))
        for stmt in _get_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            # Check if any cross-account principal exists
            for p in aws_principals:
                if isinstance(p, str) and ":root" in p:
                    condition = stmt.get("Condition", {})
                    ext_id = condition.get("StringEquals", {}).get("sts:ExternalId")
                    if not ext_id:
                        return [self.make_finding(
                            resource_name=resource.get("name", "unknown"),
                            file_path=context.file_path,
                            line_number=resource.get("line", 0),
                        )]
        return []


# ─── IAM-009  Access key rotation ────────────────────────────────────────

@registry.register
class IAMAccessKeyRotation(BaseRule):
    id = "SHLD-IAM-009"
    description = "IAM access key defined in Terraform (should be managed externally with rotation)"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Avoid creating IAM access keys in Terraform. Use IAM roles with "
        "temporary credentials instead, or manage keys externally with rotation."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.4", "Ensure access keys are rotated"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "8.2.4", "Change credentials every 90 days"),
    ]
    tags = ["iam", "access-key", "aws", "credentials"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_iam_access_key":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── IAM-010  MFA not required ───────────────────────────────────────────

@registry.register
class IAMMFARequired(BaseRule):
    id = "SHLD-IAM-010"
    description = "IAM policy does not enforce MFA for sensitive operations"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a condition `\"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"}` "
        "to the policy statement for sensitive actions."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "1.2", "Ensure MFA is enabled"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "8.3", "Multi-factor authentication"),
    ]
    tags = ["iam", "mfa", "aws", "authentication"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        # We flag IAM group policies for sensitive services without MFA conditions
        if resource.get("type") not in ("aws_iam_policy", "aws_iam_group_policy"):
            return []
        policy = _parse_policy(resource.get("config", {}).get("policy", ""))
        sensitive_prefixes = ["iam:", "s3:Delete", "ec2:Terminate", "rds:Delete", "kms:"]
        for stmt in _get_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            is_sensitive = any(
                any(a.startswith(prefix) for prefix in sensitive_prefixes)
                for a in actions
            )
            if not is_sensitive:
                continue
            condition = stmt.get("Condition", {})
            mfa_check = condition.get("Bool", {}).get("aws:MultiFactorAuthPresent")
            if mfa_check != "true":
                return [self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                )]
        return []
