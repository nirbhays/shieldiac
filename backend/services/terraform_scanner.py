"""
ShieldIaC — Terraform Scanner

Parses Terraform HCL/JSON files and evaluates all registered Terraform rules.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from backend.rules.base import Finding, ResourceType, RuleContext, registry

logger = logging.getLogger(__name__)


class TerraformScanner:
    """Scans Terraform files (.tf, .tf.json) against registered rules."""

    # Regex patterns for basic HCL parsing (block detection)
    RESOURCE_PATTERN = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
    )
    DATA_PATTERN = re.compile(
        r'data\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
    )
    VARIABLE_PATTERN = re.compile(
        r'variable\s+"([^"]+)"\s*\{', re.MULTILINE
    )

    async def scan(
        self,
        file_path: str,
        content: str,
        repo_name: str = "",
        scan_id: str = "",
    ) -> List[Finding]:
        """Parse and scan a Terraform file."""
        if file_path.endswith(".tf.json") or file_path.endswith(".json"):
            resources = self._parse_tf_json(content, file_path)
        else:
            resources = self._parse_hcl(content, file_path)

        if not resources:
            return []

        rules = registry.by_resource_type(ResourceType.TERRAFORM)
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
                        "Rule %s failed on resource %s in %s",
                        rule_cls.id, resource.get("name"), file_path,
                    )

        return findings

    def _parse_hcl(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Basic HCL parser — extracts resource blocks and their attributes.

        This is a simplified parser that handles the most common Terraform patterns.
        For production, consider using python-hcl2 or pyhcl.
        """
        resources: List[Dict[str, Any]] = []
        lines = content.split("\n")

        for match in self.RESOURCE_PATTERN.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            start_pos = match.start()
            line_number = content[:start_pos].count("\n") + 1

            # Extract the block content
            block_start = content.index("{", match.end() - 1)
            block_content = self._extract_block(content, block_start)

            config = self._parse_block_attributes(block_content)

            resources.append({
                "type": resource_type,
                "name": resource_name,
                "config": config,
                "line": line_number,
                "file_path": file_path,
            })

        return resources

    def _extract_block(self, content: str, start: int) -> str:
        """Extract content between matching braces."""
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return content[start + 1:i]
            i += 1
        return content[start + 1:]

    def _parse_block_attributes(self, block: str) -> Dict[str, Any]:
        """Parse HCL block attributes into a dictionary.

        Handles:
        - Simple key = value pairs
        - Nested blocks
        - Lists and maps
        - String, number, boolean values
        """
        attrs: Dict[str, Any] = {}
        lines = block.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("//"):
                i += 1
                continue

            # Handle line continuations
            while line.endswith("\\") and i + 1 < len(lines):
                i += 1
                line = line[:-1] + lines[i].strip()

            # Key = value assignment
            eq_match = re.match(r'(\w+)\s*=\s*(.*)', line)
            if eq_match:
                key = eq_match.group(1)
                value = eq_match.group(2).strip()
                attrs[key] = self._parse_value(value)
                i += 1
                continue

            # Nested block: key { or key "name" {
            block_match = re.match(r'(\w+)\s*(?:"[^"]*"\s*)?\{', line)
            if block_match:
                key = block_match.group(1)
                # Find the closing brace
                nested_content = self._collect_nested_block(lines, i)
                attrs[key] = self._parse_block_attributes(nested_content)
                # Skip past the block
                depth = 0
                while i < len(lines):
                    for ch in lines[i]:
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            depth -= 1
                    if depth <= 0:
                        break
                    i += 1
                i += 1
                continue

            i += 1

        return attrs

    def _collect_nested_block(self, lines: List[str], start: int) -> str:
        """Collect content of a nested block starting at line index."""
        depth = 0
        content_lines = []
        for i in range(start, len(lines)):
            line = lines[i]
            for ch in line:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            if depth > 1 or (depth == 1 and i > start):
                content_lines.append(line)
            if depth == 0 and i > start:
                break
        return "\n".join(content_lines)

    def _parse_value(self, value: str) -> Any:
        """Parse an HCL value string into a Python type."""
        value = value.strip().rstrip(",")

        # Boolean
        if value == "true":
            return True
        if value == "false":
            return False

        # Number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        # String (quoted)
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]

        # List
        if value.startswith("["):
            return self._parse_list(value)

        # Reference or expression
        return value

    def _parse_list(self, value: str) -> List:
        """Parse an HCL list value."""
        inner = value.strip("[]").strip()
        if not inner:
            return []
        items = []
        for item in inner.split(","):
            item = item.strip().strip('"')
            if item:
                items.append(item)
        return items

    def _parse_tf_json(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Parse Terraform JSON format."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Terraform JSON: %s", file_path)
            return []

        resources = []
        for resource_type, instances in data.get("resource", {}).items():
            for name, config in instances.items():
                if isinstance(config, list):
                    config = config[0] if config else {}
                resources.append({
                    "type": resource_type,
                    "name": name,
                    "config": config,
                    "line": 1,
                    "file_path": file_path,
                })

        return resources
