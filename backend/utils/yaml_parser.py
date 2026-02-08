"""
ShieldIaC — YAML Parser Utility

Safe YAML parsing with security validation and multi-document support.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# Maximum YAML document size (5 MB)
MAX_YAML_SIZE = 5 * 1024 * 1024
# Maximum recursion depth
MAX_DEPTH = 50


class SafeYAMLParser:
    """Secure YAML parser that prevents common YAML attacks."""

    def parse(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Parse YAML content into a list of documents.

        Uses yaml.safe_load to prevent arbitrary code execution.
        Validates document size and structure.
        """
        if len(content) > MAX_YAML_SIZE:
            logger.warning("YAML file too large: %s (%d bytes)", file_path, len(content))
            return []

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            logger.warning("YAML parse error in %s: %s", file_path, e)
            return []

        result = []
        for doc in docs:
            if doc is None:
                continue
            if not isinstance(doc, dict):
                continue
            if self._validate_depth(doc):
                result.append(doc)
            else:
                logger.warning("YAML document exceeds max depth in %s", file_path)

        return result

    def parse_single(self, content: str, file_path: str = "") -> Optional[Dict[str, Any]]:
        """Parse a single YAML document."""
        docs = self.parse(content, file_path)
        return docs[0] if docs else None

    def _validate_depth(self, obj: Any, depth: int = 0) -> bool:
        """Ensure YAML structure doesn't exceed maximum depth."""
        if depth > MAX_DEPTH:
            return False
        if isinstance(obj, dict):
            return all(self._validate_depth(v, depth + 1) for v in obj.values())
        if isinstance(obj, list):
            return all(self._validate_depth(v, depth + 1) for v in obj)
        return True


def parse_yaml(content: str, file_path: str = "") -> List[Dict[str, Any]]:
    """Convenience function for safe YAML parsing."""
    return SafeYAMLParser().parse(content, file_path)


def parse_yaml_single(content: str, file_path: str = "") -> Optional[Dict[str, Any]]:
    """Convenience function for parsing a single YAML document."""
    return SafeYAMLParser().parse_single(content, file_path)
