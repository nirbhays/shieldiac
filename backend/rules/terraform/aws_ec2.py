"""
ShieldIaC — Terraform AWS EC2 Security Rules

Covers: security groups, instance metadata, EBS encryption, public IPs,
        detailed monitoring, IMDSv2, user data secrets, key pairs.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _get_nested(d: Dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


# ─── EC2-001  Security group allows unrestricted SSH ────────────────────

@registry.register
class EC2UnrestrictedSSH(BaseRule):
    id = "SHLD-EC2-001"
    description = "Security group allows unrestricted SSH access (0.0.0.0/0 on port 22)"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Restrict the SSH ingress rule to specific CIDR blocks or use a bastion host / SSM."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.2", "Ensure no security groups allow SSH from 0.0.0.0/0"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["ec2", "security-group", "ssh", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_security_group":
            return []
        config = resource.get("config", {})
        ingress_rules = config.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        findings: List[Finding] = []
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            cidrs = rule.get("cidr_blocks", [])
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if (from_port <= 22 <= to_port) and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── EC2-002  Security group allows unrestricted RDP ────────────────────

@registry.register
class EC2UnrestrictedRDP(BaseRule):
    id = "SHLD-EC2-002"
    description = "Security group allows unrestricted RDP access (0.0.0.0/0 on port 3389)"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Restrict RDP ingress to specific CIDR blocks. Prefer VPN or SSM."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.3", "Ensure no security groups allow RDP from 0.0.0.0/0"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
    ]
    tags = ["ec2", "security-group", "rdp", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_security_group":
            return []
        config = resource.get("config", {})
        ingress_rules = config.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        findings: List[Finding] = []
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            cidrs = rule.get("cidr_blocks", [])
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if (from_port <= 3389 <= to_port) and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── EC2-003  All traffic ingress ────────────────────────────────────────

@registry.register
class EC2AllTrafficIngress(BaseRule):
    id = "SHLD-EC2-003"
    description = "Security group allows all traffic (0.0.0.0/0) on all ports"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Restrict ingress to only required ports and known CIDR ranges."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.4", "Restrict all traffic ingress"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
    ]
    tags = ["ec2", "security-group", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_security_group":
            return []
        config = resource.get("config", {})
        ingress_rules = config.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        findings: List[Finding] = []
        for rule in ingress_rules:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            protocol = str(rule.get("protocol", "")).lower()
            cidrs = rule.get("cidr_blocks", [])
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if protocol in ("-1", "all") and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
            elif from_port == 0 and to_port == 65535 and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── EC2-004  IMDSv2 not enforced ───────────────────────────────────────

@registry.register
class EC2IMDSv2(BaseRule):
    id = "SHLD-EC2-004"
    description = "EC2 instance does not enforce IMDSv2 (Instance Metadata Service v2)"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add `metadata_options { http_tokens = \"required\" http_endpoint = \"enabled\" }` "
        "to the instance resource."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.6", "Ensure IMDSv2 is required"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["ec2", "imds", "aws", "metadata"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        config = resource.get("config", {})
        http_tokens = _get_nested(config, "metadata_options", "http_tokens")
        if http_tokens == "required":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── EC2-005  EBS encryption ────────────────────────────────────────────

@registry.register
class EC2EBSEncryption(BaseRule):
    id = "SHLD-EC2-005"
    description = "EBS volume is not encrypted"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `encrypted = true` on the `aws_ebs_volume` resource and optionally specify a KMS key."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.2.1", "Ensure EBS volume encryption is enabled"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption and decryption"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "3.4", "Render PAN unreadable"),
    ]
    tags = ["ec2", "ebs", "encryption", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_ebs_volume":
            return []
        encrypted = resource.get("config", {}).get("encrypted")
        if encrypted is True or str(encrypted).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── EC2-006  Public IP association ──────────────────────────────────────

@registry.register
class EC2PublicIP(BaseRule):
    id = "SHLD-EC2-006"
    description = "EC2 instance is configured with a public IP address"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Set `associate_public_ip_address = false` and use a NAT gateway or "
        "VPN for outbound access."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.1", "Minimize public exposure"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.3.1", "Prohibit direct public access"),
    ]
    tags = ["ec2", "public-ip", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        pub = resource.get("config", {}).get("associate_public_ip_address")
        if pub is True or str(pub).lower() == "true":
            return [self.make_finding(
                resource_name=resource.get("name", "unknown"),
                file_path=context.file_path,
                line_number=resource.get("line", 0),
            )]
        return []


# ─── EC2-007  Detailed monitoring ────────────────────────────────────────

@registry.register
class EC2DetailedMonitoring(BaseRule):
    id = "SHLD-EC2-007"
    description = "EC2 instance does not have detailed monitoring enabled"
    severity = Severity.LOW
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `monitoring = true` on the `aws_instance` resource."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "4.11", "Ensure detailed monitoring is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
    ]
    tags = ["ec2", "monitoring", "aws"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        monitoring = resource.get("config", {}).get("monitoring")
        if monitoring is True or str(monitoring).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── EC2-008  User data contains secrets ────────────────────────────────

@registry.register
class EC2UserDataSecrets(BaseRule):
    id = "SHLD-EC2-008"
    description = "EC2 user data may contain hardcoded secrets or credentials"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Use AWS Secrets Manager or SSM Parameter Store for secrets, and "
        "reference them in user data instead of hardcoding."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "2.1", "Do not use vendor-supplied defaults"),
    ]
    tags = ["ec2", "secrets", "aws", "credentials"]

    SECRET_PATTERNS = [
        "AKIA",  # AWS access key prefix
        "password=",
        "Password=",
        "SECRET_KEY=",
        "secret_key=",
        "api_key=",
        "API_KEY=",
        "token=",
        "TOKEN=",
        "mysql_root_password",
        "POSTGRES_PASSWORD",
    ]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        user_data = resource.get("config", {}).get("user_data", "")
        if not isinstance(user_data, str):
            return []
        for pattern in self.SECRET_PATTERNS:
            if pattern in user_data:
                return [self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                    description_override=f"EC2 user data contains potential secret pattern: `{pattern}`",
                )]
        return []


# ─── EC2-009  EBS optimized ──────────────────────────────────────────────

@registry.register
class EC2EBSOptimized(BaseRule):
    id = "SHLD-EC2-009"
    description = "EC2 instance is not EBS optimized"
    severity = Severity.INFO
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `ebs_optimized = true` for consistent EBS performance."
    tags = ["ec2", "ebs", "aws", "performance"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        opt = resource.get("config", {}).get("ebs_optimized")
        if opt is True or str(opt).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]


# ─── EC2-010  Root block device encryption ───────────────────────────────

@registry.register
class EC2RootVolumeEncryption(BaseRule):
    id = "SHLD-EC2-010"
    description = "EC2 instance root block device is not encrypted"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add `root_block_device { encrypted = true }` to the instance resource."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "2.2.1", "Ensure EBS encryption"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(a)(2)(iv)", "Encryption and decryption"),
    ]
    tags = ["ec2", "encryption", "aws", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_instance":
            return []
        config = resource.get("config", {})
        encrypted = _get_nested(config, "root_block_device", "encrypted")
        if encrypted is True or str(encrypted).lower() == "true":
            return []
        return [self.make_finding(
            resource_name=resource.get("name", "unknown"),
            file_path=context.file_path,
            line_number=resource.get("line", 0),
        )]
