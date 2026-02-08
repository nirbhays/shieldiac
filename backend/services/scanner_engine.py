"""
ShieldIaC — Core Scanning Orchestrator

Coordinates file discovery, parsing, rule evaluation, AI fix generation,
and result assembly for a complete scan.
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.config import get_settings
from backend.rules.base import (
    BaseRule, Finding, ResourceType, RuleContext, RuleRegistry, registry,
)
from backend.rules.loader import load_rules
from backend.services.terraform_scanner import TerraformScanner
from backend.services.kubernetes_scanner import KubernetesScanner
from backend.services.dockerfile_scanner import DockerfileScanner
from backend.services.cloudformation_scanner import CloudFormationScanner
from backend.services.ai_fix_generator import AIFixGenerator
from backend.services.scoring_engine import ScoringEngine

logger = logging.getLogger(__name__)
settings = get_settings()


class ScannerEngine:
    """Orchestrates IaC scanning across all supported file types."""

    # Map file extensions / names to scanner type
    FILE_TYPE_MAP: Dict[str, ResourceType] = {
        ".tf": ResourceType.TERRAFORM,
        ".tf.json": ResourceType.TERRAFORM,
        ".yaml": ResourceType.KUBERNETES,  # May also be CloudFormation
        ".yml": ResourceType.KUBERNETES,
        "Dockerfile": ResourceType.DOCKERFILE,
        ".dockerfile": ResourceType.DOCKERFILE,
    }

    def __init__(self):
        load_rules()
        self.terraform_scanner = TerraformScanner()
        self.kubernetes_scanner = KubernetesScanner()
        self.dockerfile_scanner = DockerfileScanner()
        self.cloudformation_scanner = CloudFormationScanner()
        self.ai_fix_generator = AIFixGenerator()
        self.scoring_engine = ScoringEngine()
        logger.info("ScannerEngine initialized with %d rules", registry.count)

    def detect_file_type(self, file_path: str, content: str = "") -> Optional[ResourceType]:
        """Detect the IaC resource type from file path and content."""
        p = Path(file_path)
        name = p.name.lower()

        # Dockerfile detection
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            return ResourceType.DOCKERFILE

        # Terraform
        if p.suffix == ".tf" or file_path.endswith(".tf.json"):
            return ResourceType.TERRAFORM

        # YAML — distinguish K8s from CloudFormation
        if p.suffix in (".yaml", ".yml"):
            if self._is_cloudformation(content):
                return ResourceType.CLOUDFORMATION
            return ResourceType.KUBERNETES

        return None

    def _is_cloudformation(self, content: str) -> bool:
        """Heuristic: CloudFormation templates contain AWSTemplateFormatVersion or Resources with Type: AWS::*"""
        if "AWSTemplateFormatVersion" in content:
            return True
        if "Type: AWS::" in content or '"Type": "AWS::' in content:
            return True
        return False

    async def scan_files(
        self,
        files: List[Dict[str, str]],
        repo_name: str = "",
        scan_id: str = "",
    ) -> Dict[str, Any]:
        """Scan a list of files and return all findings.

        Args:
            files: List of dicts with 'path' and 'content' keys.
            repo_name: Repository identifier.
            scan_id: Unique scan identifier.

        Returns:
            Dict with findings, summary, file_results, and score.
        """
        start_time = time.monotonic()
        all_findings: List[Finding] = []
        file_results: List[Dict] = []

        for file_info in files:
            file_path = file_info["path"]
            content = file_info["content"]

            if len(content) > settings.max_file_size_bytes:
                logger.warning("Skipping %s — exceeds max file size", file_path)
                continue

            file_type = self.detect_file_type(file_path, content)
            if file_type is None:
                continue

            try:
                findings = await self._scan_single_file(
                    file_path=file_path,
                    content=content,
                    file_type=file_type,
                    repo_name=repo_name,
                    scan_id=scan_id,
                )
                all_findings.extend(findings)

                severity_counts = self._count_severities(findings)
                file_results.append({
                    "file_path": file_path,
                    "file_type": file_type.value,
                    "findings_count": len(findings),
                    **severity_counts,
                })
            except Exception:
                logger.exception("Error scanning %s", file_path)
                file_results.append({
                    "file_path": file_path,
                    "file_type": file_type.value if file_type else "unknown",
                    "findings_count": 0,
                    "error": True,
                })

        # Generate AI fix suggestions for critical/high findings
        if settings.ai_fix_enabled and all_findings:
            all_findings = await self._enrich_with_ai_fixes(all_findings, files)

        # Calculate score
        duration = time.monotonic() - start_time
        total_counts = self._count_severities(all_findings)
        score, grade = self.scoring_engine.calculate(all_findings, len(files))

        return {
            "findings": all_findings,
            "file_results": file_results,
            "summary": {
                "total_files_scanned": len(file_results),
                "total_findings": len(all_findings),
                **total_counts,
                "security_score": score,
                "grade": grade,
                "duration_seconds": round(duration, 2),
            },
        }

    async def _scan_single_file(
        self,
        file_path: str,
        content: str,
        file_type: ResourceType,
        repo_name: str,
        scan_id: str,
    ) -> List[Finding]:
        """Scan a single file using the appropriate scanner."""
        scanner_map = {
            ResourceType.TERRAFORM: self.terraform_scanner,
            ResourceType.KUBERNETES: self.kubernetes_scanner,
            ResourceType.DOCKERFILE: self.dockerfile_scanner,
            ResourceType.CLOUDFORMATION: self.cloudformation_scanner,
        }
        scanner = scanner_map.get(file_type)
        if scanner is None:
            return []

        return await scanner.scan(
            file_path=file_path,
            content=content,
            repo_name=repo_name,
            scan_id=scan_id,
        )

    async def _enrich_with_ai_fixes(
        self, findings: List[Finding], files: List[Dict[str, str]]
    ) -> List[Finding]:
        """Add AI-generated fix suggestions to critical/high findings."""
        # Build a file content lookup
        file_map = {f["path"]: f["content"] for f in files}

        # Only generate fixes for critical and high severity
        priority_findings = [
            f for f in findings if f.severity.value in ("CRITICAL", "HIGH")
        ]
        # Limit to avoid excessive API calls
        priority_findings = priority_findings[:settings.ai_fix_max_findings_per_request]

        tasks = []
        for finding in priority_findings:
            code = file_map.get(finding.file_path, "")
            tasks.append(self.ai_fix_generator.generate_fix(finding, code))

        if tasks:
            try:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for finding, result in zip(priority_findings, results):
                    if isinstance(result, str):
                        finding.ai_fix_suggestion = result
                    elif isinstance(result, Exception):
                        logger.warning("AI fix generation failed for %s: %s", finding.rule_id, result)
            except Exception:
                logger.exception("AI fix generation batch failed")

        return findings

    @staticmethod
    def _count_severities(findings: List[Finding]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            key = f.severity.value.lower()
            if key in counts:
                counts[key] += 1
        return counts
