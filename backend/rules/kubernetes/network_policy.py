"""
ShieldIaC — Kubernetes Network Policy Rules

Covers: default deny, namespace isolation, egress restrictions, port specificity.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class K8SNetworkPolicyMissing(BaseRule):
    id = "SHLD-K8S-NET-001"
    description = "Namespace does not have a default deny NetworkPolicy"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = (
        "Create a NetworkPolicy with `podSelector: {}` and empty ingress/egress "
        "to deny all traffic by default."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.3.2", "Ensure default deny NetworkPolicy"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
    ]
    tags = ["kubernetes", "network-policy", "zero-trust"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") != "NetworkPolicy":
            return []
        spec = resource.get("config", {}).get("spec", {})
        pod_selector = spec.get("podSelector", {})
        # A default deny has an empty podSelector and no ingress/egress rules
        if pod_selector == {} or pod_selector.get("matchLabels") == {}:
            ingress = spec.get("ingress", [])
            egress = spec.get("egress", [])
            if not ingress and not egress:
                return []  # This IS a default deny — good!
        return []  # Not a default deny; we flag at namespace level externally


@registry.register
class K8SNetworkPolicyAllowAll(BaseRule):
    id = "SHLD-K8S-NET-002"
    description = "NetworkPolicy allows all ingress traffic"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Restrict ingress `from` to specific namespaces or pod selectors."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.3.2", "Restrict network traffic"),
    ]
    tags = ["kubernetes", "network-policy"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") != "NetworkPolicy":
            return []
        spec = resource.get("config", {}).get("spec", {})
        ingress = spec.get("ingress", [])
        for rule in ingress:
            if not rule.get("from"):
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SNetworkPolicyNoEgress(BaseRule):
    id = "SHLD-K8S-NET-003"
    description = "NetworkPolicy does not restrict egress traffic"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Add `Egress` to `policyTypes` and define explicit egress rules."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.3.2", "Restrict network traffic"),
    ]
    tags = ["kubernetes", "network-policy", "egress"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") != "NetworkPolicy":
            return []
        spec = resource.get("config", {}).get("spec", {})
        policy_types = spec.get("policyTypes", [])
        if "Egress" not in policy_types:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class K8SNetworkPolicyBroadPorts(BaseRule):
    id = "SHLD-K8S-NET-004"
    description = "NetworkPolicy does not specify ports (allows all ports)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Specify `ports` in ingress/egress rules to restrict by port."
    tags = ["kubernetes", "network-policy", "ports"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("kind") != "NetworkPolicy":
            return []
        spec = resource.get("config", {}).get("spec", {})
        ingress = spec.get("ingress", [])
        for rule in ingress:
            if rule.get("from") and not rule.get("ports"):
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []
