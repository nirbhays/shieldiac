"""
ShieldIaC — Dockerfile Scanner

Parses Dockerfiles and evaluates all registered Dockerfile rules.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from backend.rules.base import Finding, ResourceType, RuleContext, registry

logger = logging.getLogger(__name__)


class DockerfileScanner:
    """Scans Dockerfiles against registered Dockerfile rules."""

    async def scan(
        self,
        file_path: str,
        content: str,
        repo_name: str = "",
        scan_id: str = "",
    ) -> List[Finding]:
        """Scan a Dockerfile."""
        # For Dockerfiles, we pass the entire file as a single resource
        resource: Dict[str, Any] = {
            "type": "Dockerfile",
            "name": file_path.split("/")[-1] or "Dockerfile",
            "config": {},
            "line": 1,
            "file_path": file_path,
        }

        rules = registry.by_resource_type(ResourceType.DOCKERFILE)
        context = RuleContext(
            file_path=file_path,
            file_content=content,
            repo_name=repo_name,
            scan_id=scan_id,
        )

        findings: List[Finding] = []
        for rule_cls in rules:
            try:
                rule = rule_cls()
                results = rule.evaluate(resource, context)
                findings.extend(results)
            except Exception:
                logger.exception("Rule %s failed on %s", rule_cls.id, file_path)

        return findings
