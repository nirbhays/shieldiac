"""
ShieldIaC — Terraform GCP IAM Security Rules

Covers: primitive roles, service account keys, impersonation, bindings,
        audit logging, organization policy.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class GCPIAMPrimitiveRoles(BaseRule):
    id = "SHLD-GCP-IAM-001"
    description = "GCP IAM binding uses primitive roles (Owner, Editor, Viewer)"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Use predefined or custom IAM roles instead of primitive roles."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "1.1", "Avoid primitive roles"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.3", "Role-based access"),
    ]
    tags = ["gcp", "iam", "primitive-roles", "least-privilege"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("google_project_iam_binding", "google_project_iam_member"):
            return []
        role = resource.get("config", {}).get("role", "")
        primitive = {"roles/owner", "roles/editor", "roles/viewer"}
        if role.lower() in primitive:
            return [self.make_finding(
                resource.get("name", "unknown"), context.file_path, resource.get("line", 0),
                description_override=f"IAM binding uses primitive role `{role}`",
            )]
        return []


@registry.register
class GCPIAMServiceAccountKey(BaseRule):
    id = "SHLD-GCP-IAM-002"
    description = "GCP service account key is managed in Terraform (prefer workload identity)"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Use Workload Identity Federation instead of creating service account keys."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "1.4", "Avoid user-managed SA keys"),
    ]
    tags = ["gcp", "iam", "service-account-key", "credentials"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_service_account_key":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPIAMPublicAccess(BaseRule):
    id = "SHLD-GCP-IAM-003"
    description = "GCP IAM binding grants access to allUsers or allAuthenticatedUsers"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Remove `allUsers` and `allAuthenticatedUsers` from IAM bindings."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "1.2", "Ensure no public IAM bindings"),
    ]
    tags = ["gcp", "iam", "public-access"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("google_project_iam_binding", "google_project_iam_member"):
            return []
        config = resource.get("config", {})
        members = config.get("members", [])
        member = config.get("member", "")
        if isinstance(members, str):
            members = [members]
        all_members = members + ([member] if member else [])
        public = {"allUsers", "allAuthenticatedUsers"}
        if any(m in public for m in all_members):
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPIAMAuditLogging(BaseRule):
    id = "SHLD-GCP-IAM-004"
    description = "GCP project does not have audit logging configured"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Create a `google_project_iam_audit_config` resource with "
        "`audit_log_config` for DATA_READ, DATA_WRITE, and ADMIN_READ."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "2.1", "Ensure audit logging is configured"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
    ]
    tags = ["gcp", "iam", "audit-logging", "monitoring"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_project_iam_audit_config":
            return []
        config = resource.get("config", {})
        log_types = []
        for alc in config.get("audit_log_config", []):
            if isinstance(alc, dict):
                log_types.append(alc.get("log_type", ""))
        required = {"DATA_READ", "DATA_WRITE", "ADMIN_READ"}
        if not required.issubset(set(log_types)):
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPIAMSAImpersonation(BaseRule):
    id = "SHLD-GCP-IAM-005"
    description = "GCP IAM binding grants Service Account Token Creator or User role broadly"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Restrict service account impersonation roles to specific identities."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "1.5", "Restrict SA impersonation"),
    ]
    tags = ["gcp", "iam", "impersonation"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("google_project_iam_binding", "google_service_account_iam_binding"):
            return []
        role = resource.get("config", {}).get("role", "")
        dangerous_roles = {
            "roles/iam.serviceAccountTokenCreator",
            "roles/iam.serviceAccountUser",
        }
        if role in dangerous_roles:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []
