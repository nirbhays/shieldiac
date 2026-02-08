"""
ShieldIaC — Terraform GCP Storage Security Rules

Covers: uniform bucket access, public access prevention, versioning,
        logging, encryption, retention policy, lifecycle rules.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class GCPStorageUniformAccess(BaseRule):
    id = "SHLD-GCP-STORAGE-001"
    description = "GCP storage bucket does not enforce uniform bucket-level access"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `uniform_bucket_level_access = true`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "5.1", "Ensure uniform bucket-level access"),
    ]
    tags = ["gcp", "storage", "access-control"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket":
            return []
        val = resource.get("config", {}).get("uniform_bucket_level_access")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPStoragePublicAccess(BaseRule):
    id = "SHLD-GCP-STORAGE-002"
    description = "GCP storage bucket allows public access via allUsers or allAuthenticatedUsers"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Remove bindings granting access to `allUsers` or `allAuthenticatedUsers`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "5.1", "Ensure bucket is not publicly accessible"),
    ]
    tags = ["gcp", "storage", "public-access"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket_iam_binding":
            return []
        members = resource.get("config", {}).get("members", [])
        if isinstance(members, str):
            members = [members]
        public = {"allUsers", "allAuthenticatedUsers"}
        if any(m in public for m in members):
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPStorageVersioning(BaseRule):
    id = "SHLD-GCP-STORAGE-003"
    description = "GCP storage bucket does not have versioning enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `versioning { enabled = true }`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "5.2", "Ensure bucket versioning is enabled"),
    ]
    tags = ["gcp", "storage", "versioning", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket":
            return []
        ver = resource.get("config", {}).get("versioning", {})
        if isinstance(ver, dict) and (ver.get("enabled") is True or str(ver.get("enabled")).lower() == "true"):
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPStorageLogging(BaseRule):
    id = "SHLD-GCP-STORAGE-004"
    description = "GCP storage bucket does not have access logging enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `logging { log_bucket = \"...\" }` to the bucket."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "5.3", "Ensure bucket logging is enabled"),
    ]
    tags = ["gcp", "storage", "logging", "monitoring"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket":
            return []
        if resource.get("config", {}).get("logging"):
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPStorageCMEK(BaseRule):
    id = "SHLD-GCP-STORAGE-005"
    description = "GCP storage bucket does not use customer-managed encryption key"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `encryption { default_kms_key_name = \"...\" }`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "5.3", "Ensure CMEK encryption"),
    ]
    tags = ["gcp", "storage", "encryption", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket":
            return []
        enc = resource.get("config", {}).get("encryption", {})
        if isinstance(enc, dict) and enc.get("default_kms_key_name"):
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPStorageRetentionPolicy(BaseRule):
    id = "SHLD-GCP-STORAGE-006"
    description = "GCP storage bucket does not have a retention policy"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `retention_policy { retention_period = <seconds> }` for data retention compliance."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.5", "Data retention"),
    ]
    tags = ["gcp", "storage", "retention", "compliance"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_storage_bucket":
            return []
        if resource.get("config", {}).get("retention_policy"):
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
