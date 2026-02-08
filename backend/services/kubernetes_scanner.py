"""
ShieldIaC — Kubernetes YAML Scanner

Parses Kubernetes manifests and evaluates all registered Kubernetes rules.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import yaml

from backend.rules.base import Finding, ResourceType, RuleContext, registry

logger = logging.getLogger(__name__)

# Kubernetes resource kinds we scan
SCANNABLE_KINDS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
    "Job", "CronJob", "ReplicationController",
    "NetworkPolicy", "ClusterRole", "Role",
    "ClusterRoleBinding", "RoleBinding",
    "ServiceAccount", "ConfigMap", "Secret",
    "Service", "Ingress",
}


class KubernetesScanner:
    """Scans Kubernetes YAML manifests against registered rules."""

    async def scan(
        self,
        file_path: str,
        content: str,
        repo_name: str = "",
        scan_id: str = "",
    ) -> List[Finding]:
        resources = self._parse_yaml(content, file_path)
        if not resources:
            return []

        rules = registry.by_resource_type(ResourceType.KUBERNETES)
        context = RuleContext(
            file_path=file_path,
            file_content=content,
            repo_name=repo_name,
            scan_id=scan_id,
            all_resources=resources,
        )

        findings: List[Finding] = []
        for resource in resources:
            for rule_cls in rules:
                try:
                    rule = rule_cls()
                    results = rule.evaluate(resource, context)
                    findings.extend(results)
                except Exception:
                    logger.exception(
                        "Rule %s failed on %s/%s in %s",
                        rule_cls.id, resource.get("kind"), resource.get("name"), file_path,
                    )

        return findings

    def _parse_yaml(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Parse YAML content, handling multi-document files."""
        resources: List[Dict[str, Any]] = []
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            logger.warning("Failed to parse YAML: %s", file_path)
            return []

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")

            # Handle List resources
            if kind == "List":
                for item in doc.get("items", []):
                    if isinstance(item, dict) and item.get("kind") in SCANNABLE_KINDS:
                        resources.append(self._normalize_resource(item, file_path))
                continue

            if kind in SCANNABLE_KINDS:
                resources.append(self._normalize_resource(doc, file_path))

        return resources

    def _normalize_resource(self, doc: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """Normalize a K8s resource document into the scanner's internal format."""
        metadata = doc.get("metadata", {})
        return {
            "kind": doc.get("kind", ""),
            "apiVersion": doc.get("apiVersion", ""),
            "name": metadata.get("name", "unnamed"),
            "namespace": metadata.get("namespace", "default"),
            "config": doc,
            "line": 1,
            "file_path": file_path,
        }
