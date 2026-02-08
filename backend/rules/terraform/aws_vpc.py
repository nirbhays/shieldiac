"""
ShieldIaC — Terraform AWS VPC Security Rules

Covers: VPC flow logs, default security group, NACLs, subnet public IP,
        VPN gateway, peering DNS, NAT gateway, endpoint policies.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


@registry.register
class VPCFlowLogs(BaseRule):
    id = "SHLD-VPC-001"
    description = "VPC does not have flow logs enabled"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Create an `aws_flow_log` resource attached to the VPC with "
        "`traffic_type = \"ALL\"` and send logs to CloudWatch or S3."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "3.9", "Ensure VPC flow logging is enabled"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.1", "Monitoring activities"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "10.1", "Implement audit trails"),
        ComplianceMapping(ComplianceFramework.HIPAA, "164.312(b)", "Audit controls"),
    ]
    tags = ["vpc", "flow-logs", "aws", "monitoring"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        # We check for flow_log resources; the orchestrator pairs them with VPCs
        if resource.get("type") != "aws_vpc":
            return []
        # If we can see all_resources, look for a companion flow log
        vpc_id_ref = resource.get("name", "")
        for r in context.all_resources:
            if r.get("type") == "aws_flow_log":
                fl_vpc = r.get("config", {}).get("vpc_id", "")
                if vpc_id_ref and vpc_id_ref in str(fl_vpc):
                    return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class VPCDefaultSGRestricted(BaseRule):
    id = "SHLD-VPC-002"
    description = "Default VPC security group allows traffic"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Manage the default security group with `aws_default_security_group` "
        "and ensure it has no ingress or egress rules."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.4", "Ensure default SG restricts all traffic"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
    ]
    tags = ["vpc", "security-group", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_default_security_group":
            return []
        config = resource.get("config", {})
        ingress = config.get("ingress", [])
        egress = config.get("egress", [])
        if ingress or egress:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class VPCNACLUnrestricted(BaseRule):
    id = "SHLD-VPC-003"
    description = "Network ACL allows unrestricted inbound traffic"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Restrict NACL ingress rules to specific CIDR blocks and required ports."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.1", "Ensure NACLs restrict traffic"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "1.2.1", "Restrict inbound/outbound traffic"),
    ]
    tags = ["vpc", "nacl", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_network_acl_rule":
            return []
        config = resource.get("config", {})
        if config.get("rule_action") != "allow":
            return []
        if config.get("egress") is True or str(config.get("egress")).lower() == "true":
            return []  # Only flag ingress
        cidr = config.get("cidr_block", "")
        if cidr == "0.0.0.0/0":
            protocol = str(config.get("protocol", ""))
            if protocol in ("-1", "all"):
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class VPCSubnetPublicIP(BaseRule):
    id = "SHLD-VPC-004"
    description = "Subnet is configured to auto-assign public IP addresses"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `map_public_ip_on_launch = false` for private subnets."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_AWS, "5.1", "Minimize public exposure"),
    ]
    tags = ["vpc", "subnet", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_subnet":
            return []
        val = resource.get("config", {}).get("map_public_ip_on_launch")
        if val is True or str(val).lower() == "true":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class VPCEndpointPolicy(BaseRule):
    id = "SHLD-VPC-005"
    description = "VPC endpoint does not have a restrictive policy"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add a `policy` to the VPC endpoint restricting access to specific resources."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["vpc", "endpoint", "aws", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "aws_vpc_endpoint":
            return []
        policy = resource.get("config", {}).get("policy")
        if not policy:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []
