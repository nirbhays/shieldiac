"""
ShieldIaC — Terraform AWS S3 Security Rules

Covers: encryption, public access, versioning, logging, lifecycle, MFA delete,
        ACLs, CORS, replication, SSL enforcement.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


# ─── Helpers ────────────────────────────────────────────────────────────

def _get_nested(d: Dict, *keys, default=None):
    """Safely traverse nested dicts."""
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


# ─── S3-001  Encryption at rest ─────────────────────────────────────────

@registry.register
class S3EncryptionAtRest(BaseRule):
    id = "SHLD-S3-001"
    description = "S3 bucket does not have server-side encryption enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a `server_side_encryption_configuration` block with `sse_algorithm` "
        "set to `aws:kms` or `AES256`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.1", "Ensure S3 bucket encryption is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical and physical access controls"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption and decryption"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable"),
    ]
    tags = ["s3", "encryption", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        sse = _get_nested(config, "server_side_encryption_configuration")
        if not sse:
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        rules = _get_nested(sse, "rule") or []
        if isinstance(rules, dict):
            rules = [rules]
        for rule in rules:
            sse_algo = _get_nested(rule, "apply_server_side_encryption_by_default", "sse_algorithm")
            if sse_algo in ("aws:kms", "AES256"):
                return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
            description_override="S3 bucket encryption is configured but uses an unsupported algorithm",
        )]


# ─── S3-002  Public access block ────────────────────────────────────────

@registry.register
class S3PublicAccessBlock(BaseRule):
    id = "SHLD-S3-002"
    description = "S3 bucket does not have a public access block configuration"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Create an `aws_s3_bucket_public_access_block` resource with all four "
        "settings (`block_public_acls`, `block_public_policy`, "
        "`ignore_public_acls`, `restrict_public_buckets`) set to `true`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.5", "Ensure S3 bucket has public access block"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical and physical access controls"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound and outbound traffic"),
    ]
    tags = ["s3", "public-access", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket_public_access_block":
            # We look for the companion resource; if scanning a bucket, the
            # orchestrator should ensure we also evaluate companion resources.
            return []
        config = resource.get("config", {})
        required = ["block_public_acls", "block_public_policy",
                     "ignore_public_acls", "restrict_public_buckets"]
        findings: List[Finding] = []
        for key in required:
            val = config.get(key)
            if val is not True and str(val).lower() != "true":
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                    description_override=f"S3 public access block: `{key}` is not set to true",
                ))
        return findings


# ─── S3-003  Versioning ─────────────────────────────────────────────────

@registry.register
class S3Versioning(BaseRule):
    id = "SHLD-S3-003"
    description = "S3 bucket does not have versioning enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `versioning { enabled = true }` to the bucket resource."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.3", "Ensure S3 bucket versioning is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "System change management"),
    ]
    tags = ["s3", "versioning", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        versioning = _get_nested(config, "versioning", "enabled")
        if versioning is True or str(versioning).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── S3-004  Access logging ─────────────────────────────────────────────

@registry.register
class S3AccessLogging(BaseRule):
    id = "SHLD-S3-004"
    description = "S3 bucket does not have access logging enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a `logging` block with `target_bucket` pointing to a dedicated "
        "logging bucket."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.2", "Ensure S3 bucket logging is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "10.1", "Implement audit trails"),
    ]
    tags = ["s3", "logging", "aws", "monitoring"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        if not config.get("logging"):
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        return []


# ─── S3-005  MFA Delete ─────────────────────────────────────────────────

@registry.register
class S3MFADelete(BaseRule):
    id = "SHLD-S3-005"
    description = "S3 bucket versioning does not enforce MFA delete"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Enable MFA delete on the bucket versioning configuration: "
        "`versioning { enabled = true  mfa_delete = true }`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.3", "Ensure MFA delete is enabled"),
    ]
    tags = ["s3", "mfa", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        mfa = _get_nested(config, "versioning", "mfa_delete")
        if mfa is True or str(mfa).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── S3-006  Bucket ACL is private ──────────────────────────────────────

@registry.register
class S3BucketACL(BaseRule):
    id = "SHLD-S3-006"
    description = "S3 bucket ACL allows public access"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `acl` to `private` or remove the `acl` argument entirely."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.5", "Ensure S3 bucket is not publicly accessible"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound and outbound traffic"),
    ]
    tags = ["s3", "acl", "aws", "public-access"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        acl = resource.get("config", {}).get("acl", "private")
        public_acls = {"public-read", "public-read-write", "authenticated-read"}
        if acl in public_acls:
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
                description_override=f"S3 bucket ACL is set to `{acl}` which allows public access",
            )]
        return []


# ─── S3-007  SSL enforcement (bucket policy) ────────────────────────────

@registry.register
class S3SSLEnforcement(BaseRule):
    id = "SHLD-S3-007"
    description = "S3 bucket policy does not enforce SSL/TLS for data in transit"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a bucket policy that denies requests where `aws:SecureTransport` is `false`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.1.2", "Ensure data in transit is encrypted"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(e)(1)", "Transmission security"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "4.1", "Use strong cryptography"),
    ]
    tags = ["s3", "ssl", "aws", "encryption-in-transit"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket_policy":
            return []
        policy = resource.get("config", {}).get("policy", "")
        if isinstance(policy, str) and "aws:SecureTransport" in policy:
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── S3-008  Lifecycle configuration ────────────────────────────────────

@registry.register
class S3LifecycleConfiguration(BaseRule):
    id = "SHLD-S3-008"
    description = "S3 bucket does not have a lifecycle configuration for data retention"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add a `lifecycle_rule` block with appropriate transitions and expiration "
        "to manage storage costs and data retention."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.5", "Data retention"),
    ]
    tags = ["s3", "lifecycle", "aws", "cost-optimization"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        if not config.get("lifecycle_rule"):
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        return []


# ─── S3-009  Cross-region replication ────────────────────────────────────

@registry.register
class S3CrossRegionReplication(BaseRule):
    id = "SHLD-S3-009"
    description = "S3 bucket does not have cross-region replication configured for disaster recovery"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Create an `aws_s3_bucket_replication_configuration` resource to enable "
        "cross-region replication for critical buckets."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "A1.2", "Availability"),
    ]
    tags = ["s3", "replication", "aws", "disaster-recovery"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        if not config.get("replication_configuration"):
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        return []


# ─── S3-010  Object lock ────────────────────────────────────────────────

@registry.register
class S3ObjectLock(BaseRule):
    id = "SHLD-S3-010"
    description = "S3 bucket does not have object lock enabled for WORM compliance"
    severity = Severity.INFO
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Enable object lock on the bucket: `object_lock_configuration { "
        "object_lock_enabled = \"Enabled\" }`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Data integrity"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "10.7", "Retain audit trail history"),
    ]
    tags = ["s3", "object-lock", "aws", "compliance"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_s3_bucket":
            return []
        config = resource.get("config", {})
        lock = _get_nested(config, "object_lock_configuration", "object_lock_enabled")
        if lock == "Enabled":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]
