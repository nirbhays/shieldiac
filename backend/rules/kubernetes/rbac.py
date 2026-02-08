"""
ShieldIaC — Kubernetes RBAC Security Rules

Covers: cluster-admin binding, wildcard verbs, secrets access, escalation,
        default service account.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class K8SClusterAdminBinding(BaseRule):
    id = "SHLD-K8S-RBAC-001"
    description = "ClusterRoleBinding grants cluster-admin to a user or service account"
    severity = Severity.CRITICAL
    resource_type = ResourceType.KUBERNETES
    remediation = "Use scoped roles with minimal permissions instead of cluster-admin."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.1", "Minimize cluster-admin usage"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.3", "Role-based access"),
    ]
    tags = ["kubernetes", "rbac", "cluster-admin"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") != "ClusterRoleBinding":
            return []
        role_ref = resource.get("config", {}).get("roleRef", {})
        if role_ref.get("name") == "cluster-admin":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SRBACWildcardVerbs(BaseRule):
    id = "SHLD-K8S-RBAC-002"
    description = "ClusterRole or Role uses wildcard verbs (*)"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Replace wildcard verbs with specific verbs: get, list, watch, create, update, delete."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.3", "Minimize wildcard RBAC"),
    ]
    tags = ["kubernetes", "rbac", "wildcard"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") not in ("ClusterRole", "Role"):
            return []
        rules = resource.get("config", {}).get("rules", [])
        for rule in rules:
            verbs = rule.get("verbs", [])
            if "*" in verbs:
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SRBACWildcardResources(BaseRule):
    id = "SHLD-K8S-RBAC-003"
    description = "ClusterRole or Role grants access to all resources (*)"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Scope `resources` to specific resource types."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.3", "Minimize wildcard RBAC"),
    ]
    tags = ["kubernetes", "rbac", "wildcard"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") not in ("ClusterRole", "Role"):
            return []
        rules = resource.get("config", {}).get("rules", [])
        for rule in rules:
            resources = rule.get("resources", [])
            if "*" in resources:
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SRBACSecretsAccess(BaseRule):
    id = "SHLD-K8S-RBAC-004"
    description = "Role grants get/list/watch access to secrets"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Restrict secrets access to only the service accounts that need it."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.2", "Restrict secrets access"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Data protection"),
    ]
    tags = ["kubernetes", "rbac", "secrets"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") not in ("ClusterRole", "Role"):
            return []
        rules = resource.get("config", {}).get("rules", [])
        for rule in rules:
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])
            if "secrets" in resources and any(v in verbs for v in ["*", "get", "list", "watch"]):
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SRBACEscalation(BaseRule):
    id = "SHLD-K8S-RBAC-005"
    description = "Role allows privilege escalation via bind/escalate/impersonate verbs"
    severity = Severity.CRITICAL
    resource_type = ResourceType.KUBERNETES
    remediation = "Remove `bind`, `escalate`, and `impersonate` verbs from the role."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.8", "Minimize RBAC escalation"),
    ]
    tags = ["kubernetes", "rbac", "escalation"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") not in ("ClusterRole", "Role"):
            return []
        rules = resource.get("config", {}).get("rules", [])
        dangerous_verbs = {"bind", "escalate", "impersonate"}
        for rule in rules:
            verbs = set(rule.get("verbs", []))
            if verbs & dangerous_verbs:
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SDefaultServiceAccount(BaseRule):
    id = "SHLD-K8S-RBAC-006"
    description = "Pod uses the default service account"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Create a dedicated service account with minimal permissions."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.5", "Minimize default SA usage"),
    ]
    tags = ["kubernetes", "rbac", "service-account"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        sa = pod_spec.get("serviceAccountName", "default")
        if sa == "default" or not sa:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []
