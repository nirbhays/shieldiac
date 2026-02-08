"""
ShieldIaC — Terraform GCP Compute Security Rules

Covers: serial port, OS login, shielded VM, public IPs, IP forwarding,
        disk encryption, default service account, firewall rules.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _get_nested(d, *keys, default=None):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


@registry.register
class GCPComputeSerialPort(BaseRule):
    id = "SHLD-GCP-COMPUTE-001"
    description = "GCP Compute instance has serial port access enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `metadata.serial-port-enable` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.5", "Ensure serial port is disabled"),
    ]
    tags = ["gcp", "compute", "serial-port"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        meta = resource.get("config", {}).get("metadata", {})
        if isinstance(meta, dict) and str(meta.get("serial-port-enable", "")).lower() == "true":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPComputeOSLogin(BaseRule):
    id = "SHLD-GCP-COMPUTE-002"
    description = "GCP Compute instance does not have OS Login enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `metadata.enable-oslogin` to `TRUE`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.4", "Ensure OS Login is enabled"),
    ]
    tags = ["gcp", "compute", "os-login", "authentication"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        meta = resource.get("config", {}).get("metadata", {})
        if isinstance(meta, dict) and str(meta.get("enable-oslogin", "")).upper() == "TRUE":
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPComputeShieldedVM(BaseRule):
    id = "SHLD-GCP-COMPUTE-003"
    description = "GCP Compute instance does not use Shielded VM features"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = (
        "Add `shielded_instance_config { enable_secure_boot = true "
        "enable_vtpm = true enable_integrity_monitoring = true }`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.8", "Ensure Shielded VM is enabled"),
    ]
    tags = ["gcp", "compute", "shielded-vm"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        config = resource.get("config", {})
        shielded = config.get("shielded_instance_config", {})
        if not shielded:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        if not all([
            shielded.get("enable_secure_boot"),
            shielded.get("enable_vtpm"),
            shielded.get("enable_integrity_monitoring"),
        ]):
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPComputePublicIP(BaseRule):
    id = "SHLD-GCP-COMPUTE-004"
    description = "GCP Compute instance has a public IP via access_config"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Remove the `access_config` block from `network_interface` to avoid public IPs."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.9", "Ensure instances do not have public IPs"),
    ]
    tags = ["gcp", "compute", "public-ip", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        config = resource.get("config", {})
        nics = config.get("network_interface", [])
        if isinstance(nics, dict):
            nics = [nics]
        for nic in nics:
            if nic.get("access_config") is not None:
                return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPComputeIPForwarding(BaseRule):
    id = "SHLD-GCP-COMPUTE-005"
    description = "GCP Compute instance has IP forwarding enabled"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Set `can_ip_forward = false` unless the instance is a NAT gateway or router."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.6", "Ensure IP forwarding is disabled"),
    ]
    tags = ["gcp", "compute", "ip-forwarding"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        val = resource.get("config", {}).get("can_ip_forward")
        if val is True or str(val).lower() == "true":
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPComputeDefaultSA(BaseRule):
    id = "SHLD-GCP-COMPUTE-006"
    description = "GCP Compute instance uses the default service account"
    severity = Severity.HIGH
    resource_type = ResourceType.TERRAFORM
    remediation = "Create a custom service account with minimal permissions and assign it."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.1", "Ensure default SA is not used"),
    ]
    tags = ["gcp", "compute", "service-account", "least-privilege"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_instance":
            return []
        sa = resource.get("config", {}).get("service_account", {})
        if isinstance(sa, list) and sa:
            sa = sa[0]
        email = sa.get("email", "") if isinstance(sa, dict) else ""
        if not email or "compute@developer.gserviceaccount.com" in email:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


@registry.register
class GCPComputeDiskEncryption(BaseRule):
    id = "SHLD-GCP-COMPUTE-007"
    description = "GCP Compute disk does not use customer-managed encryption key (CMEK)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.TERRAFORM
    remediation = "Add `disk_encryption_key { kms_key_self_link = ... }` to the disk."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "4.7", "Ensure VM disks are encrypted with CMEK"),
    ]
    tags = ["gcp", "compute", "encryption", "data-protection"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_disk":
            return []
        dek = resource.get("config", {}).get("disk_encryption_key")
        if dek and dek.get("kms_key_self_link"):
            return []
        return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]


@registry.register
class GCPFirewallAllowAll(BaseRule):
    id = "SHLD-GCP-COMPUTE-008"
    description = "GCP firewall rule allows all traffic from 0.0.0.0/0"
    severity = Severity.CRITICAL
    resource_type = ResourceType.TERRAFORM
    remediation = "Restrict `source_ranges` to specific CIDR blocks and limit allowed ports."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_GCP, "3.6", "Ensure firewall rules are restrictive"),
    ]
    tags = ["gcp", "firewall", "network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        if resource.get("type") != "google_compute_firewall":
            return []
        config = resource.get("config", {})
        if config.get("direction", "INGRESS").upper() != "INGRESS":
            return []
        sources = config.get("source_ranges", [])
        if isinstance(sources, str):
            sources = [sources]
        if "0.0.0.0/0" in sources:
            allow_rules = config.get("allow", [])
            if isinstance(allow_rules, dict):
                allow_rules = [allow_rules]
            for rule in allow_rules:
                protocol = str(rule.get("protocol", "")).lower()
                ports = rule.get("ports", [])
                if protocol == "all" or not ports:
                    return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []
