"""
ShieldIaC — Kubernetes Resource Limits Rules

Covers: CPU/memory requests and limits, resource quotas, limit ranges,
        ephemeral storage limits.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _iter_containers(resource: Dict[str, Any]):
    spec = resource.get("config", {}).get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", spec)
    containers = pod_spec.get("containers", [])
    init_containers = pod_spec.get("initContainers", [])
    for c in containers + init_containers:
        yield c, c.get("name", "unnamed")


@registry.register
class K8SResourceLimitsMissing(BaseRule):
    id = "SHLD-K8S-RES-001"
    description = "Container does not define resource limits (CPU/memory)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Add `resources.limits.cpu` and `resources.limits.memory`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.4.1", "Ensure resource limits are set"),
    ]
    tags = ["kubernetes", "resources", "limits"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


@registry.register
class K8SResourceRequestsMissing(BaseRule):
    id = "SHLD-K8S-RES-002"
    description = "Container does not define resource requests (CPU/memory)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Add `resources.requests.cpu` and `resources.requests.memory`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.4.1", "Ensure resource requests are set"),
    ]
    tags = ["kubernetes", "resources", "requests"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            resources = container.get("resources", {})
            requests = resources.get("requests", {})
            if not requests.get("cpu") or not requests.get("memory"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


@registry.register
class K8SMemoryLimitHigh(BaseRule):
    id = "SHLD-K8S-RES-003"
    description = "Container memory limit is excessively high (> 8Gi)"
    severity = Severity.LOW
    resource_type = ResourceType.KUBERNETES
    remediation = "Review memory limits to ensure they are appropriate for the workload."
    tags = ["kubernetes", "resources", "memory"]

    def _parse_memory(self, val: str) -> int:
        """Convert K8s memory string to bytes."""
        if not val:
            return 0
        val = str(val)
        multipliers = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4}
        for suffix, mult in multipliers.items():
            if val.endswith(suffix):
                try:
                    return int(val[:-len(suffix)]) * mult
                except ValueError:
                    return 0
        try:
            return int(val)
        except ValueError:
            return 0

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            mem = self._parse_memory(limits.get("memory", ""))
            if mem > 8 * 1024**3:  # 8Gi
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


@registry.register
class K8SEphemeralStorageLimit(BaseRule):
    id = "SHLD-K8S-RES-004"
    description = "Container does not define ephemeral storage limits"
    severity = Severity.LOW
    resource_type = ResourceType.KUBERNETES
    remediation = "Add `resources.limits.ephemeral-storage` to prevent disk exhaustion."
    tags = ["kubernetes", "resources", "storage"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("ephemeral-storage"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings
