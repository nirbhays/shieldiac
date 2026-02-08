"""
ShieldIaC — Base Rule & Rule Registry

Every security rule inherits from `BaseRule`.  The global `RuleRegistry`
auto-collects rules when modules are imported and exposes helpers to
filter, search, and instantiate them.
"""

from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Type


# ── Enums ────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, Enum):
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    DOCKERFILE = "dockerfile"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"


class ComplianceFramework(str, Enum):
    CIS_AWS = "CIS-AWS"
    CIS_GCP = "CIS-GCP"
    CIS_K8S = "CIS-K8S"
    SOC2 = "SOC2"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI-DSS"
    NIST_800_53 = "NIST-800-53"
    ISO_27001 = "ISO-27001"
    GDPR = "GDPR"


@dataclass
class ComplianceMapping:
    """Maps a rule to a specific compliance framework control."""
    framework: ComplianceFramework
    control_id: str
    control_description: str = ""


@dataclass
class Finding:
    """A single security finding produced by a rule."""
    rule_id: str
    severity: Severity
    resource_type: str
    resource_name: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    compliance: List[ComplianceMapping] = field(default_factory=list)
    ai_fix_suggestion: Optional[str] = None
    code_snippet: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        """Deterministic hash for deduplication."""
        raw = f"{self.rule_id}|{self.file_path}|{self.resource_name}|{self.line_number}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Base Rule ────────────────────────────────────────────────────────────

class BaseRule(abc.ABC):
    """Abstract base for every ShieldIaC security rule."""

    # Subclasses MUST set these
    id: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity]
    resource_type: ClassVar[ResourceType]
    remediation: ClassVar[str]
    compliance: ClassVar[List[ComplianceMapping]] = []
    tags: ClassVar[List[str]] = []
    enabled: ClassVar[bool] = True

    @abc.abstractmethod
    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        """Run the rule against a single parsed resource.

        Returns an empty list when the resource passes, or one-or-more
        `Finding` instances when issues are detected.
        """
        ...

    def make_finding(
        self,
        resource_name: str,
        file_path: str,
        line_number: int = 0,
        code_snippet: Optional[str] = None,
        description_override: Optional[str] = None,
    ) -> Finding:
        """Helper to create a Finding pre-filled with rule metadata."""
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            resource_type=self.resource_type.value,
            resource_name=resource_name,
            file_path=file_path,
            line_number=line_number,
            description=description_override or self.description,
            remediation=self.remediation,
            compliance=list(self.compliance),
            code_snippet=code_snippet,
        )


@dataclass
class RuleContext:
    """Contextual information passed alongside every resource evaluation."""
    file_path: str = ""
    file_content: str = ""
    repo_name: str = ""
    scan_id: str = ""
    all_resources: List[Dict[str, Any]] = field(default_factory=list)


# ── Rule Registry (Singleton) ───────────────────────────────────────────

class RuleRegistry:
    """Central catalogue of all known security rules.

    Rules self-register when their module is imported via `register()`.
    """

    _instance: ClassVar[Optional["RuleRegistry"]] = None
    _rules: Dict[str, Type[BaseRule]]

    def __new__(cls) -> "RuleRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._rules = {}
        return cls._instance

    # ── Registration ─────────────────────────────────────────────────
    def register(self, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        """Register a rule class. Usable as a decorator."""
        if not getattr(rule_cls, "id", None):
            raise ValueError(f"Rule {rule_cls.__name__} must define a class-level `id`.")
        self._rules[rule_cls.id] = rule_cls
        return rule_cls

    def register_all(self, *rule_classes: Type[BaseRule]) -> None:
        for rc in rule_classes:
            self.register(rc)

    # ── Lookup ───────────────────────────────────────────────────────
    def get(self, rule_id: str) -> Optional[Type[BaseRule]]:
        return self._rules.get(rule_id)

    def all(self) -> List[Type[BaseRule]]:
        return list(self._rules.values())

    def enabled(self) -> List[Type[BaseRule]]:
        return [r for r in self._rules.values() if r.enabled]

    def by_resource_type(self, rt: ResourceType) -> List[Type[BaseRule]]:
        return [r for r in self._rules.values() if r.resource_type == rt and r.enabled]

    def by_severity(self, sev: Severity) -> List[Type[BaseRule]]:
        return [r for r in self._rules.values() if r.severity == sev and r.enabled]

    def by_framework(self, fw: ComplianceFramework) -> List[Type[BaseRule]]:
        return [
            r for r in self._rules.values()
            if r.enabled and any(c.framework == fw for c in r.compliance)
        ]

    def by_tag(self, tag: str) -> List[Type[BaseRule]]:
        return [r for r in self._rules.values() if tag in r.tags and r.enabled]

    @property
    def count(self) -> int:
        return len(self._rules)

    def summary(self) -> Dict[str, int]:
        """Return counts grouped by resource type."""
        out: Dict[str, int] = {}
        for r in self._rules.values():
            key = r.resource_type.value
            out[key] = out.get(key, 0) + 1
        return out

    def reset(self) -> None:
        """Clear all registered rules (useful in tests)."""
        self._rules.clear()


# Convenience singleton accessor
registry = RuleRegistry()
