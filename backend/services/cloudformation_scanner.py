"""
ShieldIaC — CloudFormation Scanner

Parses CloudFormation templates and evaluates security rules.
Reuses Terraform rules where resource types overlap, plus CF-specific checks.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

import yaml

from backend.rules.base import Finding, ResourceType, RuleContext, registry

logger = logging.getLogger(__name__)

# Map CF resource types to equivalent Terraform types for rule reuse
CF_TO_TF_TYPE_MAP = {
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::EC2::SecurityGroup": "aws_security_group",
    "AWS::EC2::Instance": "aws_instance",
    "AWS::RDS::DBInstance": "aws_db_instance",
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::IAM::Policy": "aws_iam_policy",
    "AWS::EC2::VPC": "aws_vpc",
    "AWS::EBS::Volume": "aws_ebs_volume",
}


class CloudFormationScanner:
    """Scans CloudFormation YAML/JSON templates against security rules."""

    async def scan(
        self,
        file_path: str,
        content: str,
        repo_name: str = "",
        scan_id: str = "",
    ) -> List[Finding]:
        resources = self._parse_template(content, file_path)
        if not resources:
            return []

        # Use Terraform rules by mapping CF types
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
                        "Rule %s failed on CF resource %s",
                        rule_cls.id, resource.get("name"),
                    )

        return findings

    def _parse_template(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Parse a CloudFormation template into scanner resources."""
        template = self._load_template(content, file_path)
        if not template:
            return []

        resources: List[Dict[str, Any]] = []
        cf_resources = template.get("Resources", {})

        for logical_id, cf_resource in cf_resources.items():
            cf_type = cf_resource.get("Type", "")
            properties = cf_resource.get("Properties", {})

            # Map to Terraform type for rule reuse
            tf_type = CF_TO_TF_TYPE_MAP.get(cf_type)
            if tf_type:
                config = self._map_properties(cf_type, properties)
                resources.append({
                    "type": tf_type,
                    "name": logical_id,
                    "config": config,
                    "line": 1,
                    "file_path": file_path,
                    "cf_type": cf_type,
                })

        return resources

    def _load_template(self, content: str, file_path: str) -> Dict:
        """Load CF template from YAML or JSON."""
        try:
            if file_path.endswith(".json"):
                return json.loads(content)
            return yaml.safe_load(content) or {}
        except (json.JSONDecodeError, yaml.YAMLError):
            logger.warning("Failed to parse CloudFormation template: %s", file_path)
            return {}

    def _map_properties(self, cf_type: str, properties: Dict) -> Dict:
        """Map CloudFormation properties to Terraform-like config."""
        if cf_type == "AWS::S3::Bucket":
            return self._map_s3(properties)
        if cf_type == "AWS::EC2::SecurityGroup":
            return self._map_sg(properties)
        if cf_type == "AWS::EC2::Instance":
            return self._map_instance(properties)
        if cf_type == "AWS::RDS::DBInstance":
            return self._map_rds(properties)
        return properties

    def _map_s3(self, props: Dict) -> Dict:
        config: Dict[str, Any] = {}
        bec = props.get("BucketEncryption", {})
        rules = bec.get("ServerSideEncryptionConfiguration", [])
        if rules:
            config["server_side_encryption_configuration"] = {
                "rule": {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": rules[0].get("ServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                    }
                }
            }
        vc = props.get("VersioningConfiguration", {})
        if vc.get("Status") == "Enabled":
            config["versioning"] = {"enabled": True}
        acl = props.get("AccessControl", "")
        if acl:
            config["acl"] = acl.lower()
        lc = props.get("LoggingConfiguration", {})
        if lc:
            config["logging"] = lc
        return config

    def _map_sg(self, props: Dict) -> Dict:
        ingress = []
        for rule in props.get("SecurityGroupIngress", []):
            ingress.append({
                "from_port": rule.get("FromPort", 0),
                "to_port": rule.get("ToPort", 65535),
                "protocol": rule.get("IpProtocol", "-1"),
                "cidr_blocks": [rule.get("CidrIp", "")] if rule.get("CidrIp") else [],
            })
        return {"ingress": ingress}

    def _map_instance(self, props: Dict) -> Dict:
        config: Dict[str, Any] = {}
        metadata = props.get("MetadataOptions", {})
        if metadata:
            config["metadata_options"] = {
                "http_tokens": metadata.get("HttpTokens", "optional"),
            }
        if props.get("NetworkInterfaces"):
            for ni in props["NetworkInterfaces"]:
                if ni.get("AssociatePublicIpAddress"):
                    config["associate_public_ip_address"] = True
        if props.get("Monitoring"):
            config["monitoring"] = True
        return config

    def _map_rds(self, props: Dict) -> Dict:
        return {
            "storage_encrypted": props.get("StorageEncrypted", False),
            "publicly_accessible": props.get("PubliclyAccessible", False),
            "backup_retention_period": props.get("BackupRetentionPeriod", 0),
            "deletion_protection": props.get("DeletionProtection", False),
            "multi_az": props.get("MultiAZ", False),
            "auto_minor_version_upgrade": props.get("AutoMinorVersionUpgrade", True),
            "iam_database_authentication_enabled": props.get("EnableIAMDatabaseAuthentication", False),
        }
