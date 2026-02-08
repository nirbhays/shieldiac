"""
ShieldIaC — Terraform AWS RDS Security Rules

Covers: encryption, public access, backup retention, deletion protection,
        multi-AZ, minor version upgrades, IAM auth, logging, storage encryption.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class RDSEncryptionAtRest(BaseRule):
    id = "SHLD-RDS-001"
    description = "RDS instance does not have encryption at rest enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `storage_encrypted = true` and optionally specify `kms_key_id`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.3.1", "Ensure RDS encryption is enabled"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption and decryption"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Data protection"),
    ]
    tags = ["rds", "encryption", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("aws_db_instance", "aws_rds_cluster"):
            return []
        enc = resource.get("config", {}).get("storage_encrypted")
        if enc is True or str(enc).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSPublicAccess(BaseRule):
    id = "SHLD-RDS-002"
    description = "RDS instance is publicly accessible"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `publicly_accessible = false` to keep the database in a private subnet."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.3.2", "Ensure RDS is not publicly accessible"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.3.1", "Prohibit direct public access"),
    ]
    tags = ["rds", "public-access", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        pub = resource.get("config", {}).get("publicly_accessible")
        if pub is True or str(pub).lower() == "true":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class RDSBackupRetention(BaseRule):
    id = "SHLD-RDS-003"
    description = "RDS instance has insufficient backup retention period (< 7 days)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `backup_retention_period` to at least 7 (30 recommended for production)."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "A1.2", "Availability — backup and recovery"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.308(a)(7)(ii)(A)", "Data backup plan"),
    ]
    tags = ["rds", "backup", "aws", "disaster-recovery"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("aws_db_instance", "aws_rds_cluster"):
            return []
        retention = resource.get("config", {}).get("backup_retention_period", 0)
        try:
            retention = int(retention)
        except (ValueError, TypeError):
            retention = 0
        if retention >= 7:
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSDeletionProtection(BaseRule):
    id = "SHLD-RDS-004"
    description = "RDS instance does not have deletion protection enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `deletion_protection = true` to prevent accidental deletion."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "A1.2", "Availability"),
    ]
    tags = ["rds", "deletion-protection", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") not in ("aws_db_instance", "aws_rds_cluster"):
            return []
        dp = resource.get("config", {}).get("deletion_protection")
        if dp is True or str(dp).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSMultiAZ(BaseRule):
    id = "SHLD-RDS-005"
    description = "RDS instance is not configured for Multi-AZ deployment"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `multi_az = true` for high availability."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "A1.2", "Availability"),
    ]
    tags = ["rds", "multi-az", "aws", "high-availability"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        maz = resource.get("config", {}).get("multi_az")
        if maz is True or str(maz).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSMinorVersionUpgrade(BaseRule):
    id = "SHLD-RDS-006"
    description = "RDS instance does not have auto minor version upgrade enabled"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `auto_minor_version_upgrade = true`."
    tags = ["rds", "patching", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        val = resource.get("config", {}).get("auto_minor_version_upgrade")
        if val is False or str(val).lower() == "false":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class RDSIAMAuth(BaseRule):
    id = "SHLD-RDS-007"
    description = "RDS instance does not have IAM database authentication enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `iam_database_authentication_enabled = true`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.3.3", "Ensure IAM auth is enabled for RDS"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["rds", "iam-auth", "aws", "authentication"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        val = resource.get("config", {}).get("iam_database_authentication_enabled")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSEnhancedMonitoring(BaseRule):
    id = "SHLD-RDS-008"
    description = "RDS instance does not have enhanced monitoring enabled"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `monitoring_interval` to 1, 5, 10, 15, 30, or 60 seconds and provide `monitoring_role_arn`."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
    ]
    tags = ["rds", "monitoring", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        interval = resource.get("config", {}).get("monitoring_interval", 0)
        try:
            interval = int(interval)
        except (ValueError, TypeError):
            interval = 0
        if interval > 0:
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSCopyTagsToSnapshot(BaseRule):
    id = "SHLD-RDS-009"
    description = "RDS instance does not copy tags to snapshots"
    severity = Severity.INFO
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `copy_tags_to_snapshot = true`."
    tags = ["rds", "tagging", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        val = resource.get("config", {}).get("copy_tags_to_snapshot")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class RDSPerformanceInsights(BaseRule):
    id = "SHLD-RDS-010"
    description = "RDS instance does not have Performance Insights enabled"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `performance_insights_enabled = true` and optionally encrypt with a KMS key."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
    ]
    tags = ["rds", "monitoring", "aws", "performance"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_db_instance":
            return []
        val = resource.get("config", {}).get("performance_insights_enabled")
        if val is True or str(val).lower() == "true":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
