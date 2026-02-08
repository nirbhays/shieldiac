-- =============================================================================
-- ShieldIaC — Seed Data
-- Populates built-in rules and compliance mappings
-- =============================================================================

-- ── Terraform S3 Rules ──────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-S3-001', 'S3 bucket does not have server-side encryption enabled', 'HIGH', 'terraform', 'Add a server_side_encryption_configuration block with sse_algorithm set to aws:kms or AES256.', '["s3","encryption","aws","data-protection"]'),
('SHLD-S3-002', 'S3 bucket does not have a public access block configuration', 'CRITICAL', 'terraform', 'Create an aws_s3_bucket_public_access_block resource with all four settings set to true.', '["s3","public-access","aws","network"]'),
('SHLD-S3-003', 'S3 bucket does not have versioning enabled', 'MEDIUM', 'terraform', 'Add versioning { enabled = true } to the bucket resource.', '["s3","versioning","aws","data-protection"]'),
('SHLD-S3-004', 'S3 bucket does not have access logging enabled', 'MEDIUM', 'terraform', 'Add a logging block with target_bucket.', '["s3","logging","aws","monitoring"]'),
('SHLD-S3-005', 'S3 bucket versioning does not enforce MFA delete', 'MEDIUM', 'terraform', 'Enable MFA delete on bucket versioning.', '["s3","mfa","aws","data-protection"]'),
('SHLD-S3-006', 'S3 bucket ACL allows public access', 'CRITICAL', 'terraform', 'Set acl to private.', '["s3","acl","aws","public-access"]'),
('SHLD-S3-007', 'S3 bucket policy does not enforce SSL/TLS', 'HIGH', 'terraform', 'Add a bucket policy denying non-SSL requests.', '["s3","ssl","aws","encryption-in-transit"]'),
('SHLD-S3-008', 'S3 bucket does not have lifecycle configuration', 'LOW', 'terraform', 'Add lifecycle_rule block.', '["s3","lifecycle","aws","cost-optimization"]'),
('SHLD-S3-009', 'S3 bucket does not have cross-region replication', 'LOW', 'terraform', 'Create aws_s3_bucket_replication_configuration.', '["s3","replication","aws","disaster-recovery"]'),
('SHLD-S3-010', 'S3 bucket does not have object lock enabled', 'INFO', 'terraform', 'Enable object lock on the bucket.', '["s3","object-lock","aws","compliance"]');

-- ── Terraform EC2 Rules ─────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-EC2-001', 'Security group allows unrestricted SSH access (0.0.0.0/0 on port 22)', 'CRITICAL', 'terraform', 'Restrict SSH ingress to specific CIDR blocks.', '["ec2","security-group","ssh","aws","network"]'),
('SHLD-EC2-002', 'Security group allows unrestricted RDP access', 'CRITICAL', 'terraform', 'Restrict RDP ingress to specific CIDR blocks.', '["ec2","security-group","rdp","aws","network"]'),
('SHLD-EC2-003', 'Security group allows all traffic from 0.0.0.0/0', 'CRITICAL', 'terraform', 'Restrict ingress to required ports.', '["ec2","security-group","aws","network"]'),
('SHLD-EC2-004', 'EC2 instance does not enforce IMDSv2', 'HIGH', 'terraform', 'Add metadata_options { http_tokens = "required" }.', '["ec2","imds","aws","metadata"]'),
('SHLD-EC2-005', 'EBS volume is not encrypted', 'HIGH', 'terraform', 'Set encrypted = true on aws_ebs_volume.', '["ec2","ebs","encryption","aws"]'),
('SHLD-EC2-006', 'EC2 instance has a public IP address', 'HIGH', 'terraform', 'Set associate_public_ip_address = false.', '["ec2","public-ip","aws","network"]'),
('SHLD-EC2-007', 'EC2 instance does not have detailed monitoring', 'LOW', 'terraform', 'Set monitoring = true.', '["ec2","monitoring","aws"]'),
('SHLD-EC2-008', 'EC2 user data may contain hardcoded secrets', 'CRITICAL', 'terraform', 'Use Secrets Manager or SSM Parameter Store.', '["ec2","secrets","aws","credentials"]'),
('SHLD-EC2-009', 'EC2 instance is not EBS optimized', 'INFO', 'terraform', 'Set ebs_optimized = true.', '["ec2","ebs","aws","performance"]'),
('SHLD-EC2-010', 'EC2 root block device is not encrypted', 'HIGH', 'terraform', 'Add root_block_device { encrypted = true }.', '["ec2","encryption","aws"]');

-- ── Terraform IAM Rules ─────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-IAM-001', 'IAM policy grants wildcard (*) actions', 'CRITICAL', 'terraform', 'Replace with specific actions.', '["iam","policy","aws","least-privilege"]'),
('SHLD-IAM-002', 'IAM policy grants access to all resources (*)', 'HIGH', 'terraform', 'Scope to specific ARNs.', '["iam","policy","aws","least-privilege"]'),
('SHLD-IAM-003', 'IAM user has an inline policy attached', 'MEDIUM', 'terraform', 'Use managed policies on groups.', '["iam","inline-policy","aws"]'),
('SHLD-IAM-004', 'IAM password policy requires fewer than 14 characters', 'MEDIUM', 'terraform', 'Set minimum_password_length to 14.', '["iam","password-policy","aws"]'),
('SHLD-IAM-005', 'IAM password policy does not prevent reuse', 'MEDIUM', 'terraform', 'Set password_reuse_prevention to 24.', '["iam","password-policy","aws"]'),
('SHLD-IAM-006', 'IAM password policy does not require uppercase', 'LOW', 'terraform', 'Set require_uppercase_characters = true.', '["iam","password-policy","aws"]'),
('SHLD-IAM-007', 'IAM password policy does not require symbols', 'LOW', 'terraform', 'Set require_symbols = true.', '["iam","password-policy","aws"]'),
('SHLD-IAM-008', 'IAM role trust allows cross-account without external ID', 'HIGH', 'terraform', 'Add sts:ExternalId condition.', '["iam","assume-role","aws","cross-account"]'),
('SHLD-IAM-009', 'IAM access key defined in Terraform', 'HIGH', 'terraform', 'Use IAM roles instead.', '["iam","access-key","aws","credentials"]'),
('SHLD-IAM-010', 'IAM policy does not enforce MFA for sensitive ops', 'HIGH', 'terraform', 'Add MFA condition to policy.', '["iam","mfa","aws","authentication"]');

-- ── Terraform RDS Rules ─────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-RDS-001', 'RDS instance does not have encryption at rest', 'HIGH', 'terraform', 'Set storage_encrypted = true.', '["rds","encryption","aws"]'),
('SHLD-RDS-002', 'RDS instance is publicly accessible', 'CRITICAL', 'terraform', 'Set publicly_accessible = false.', '["rds","public-access","aws"]'),
('SHLD-RDS-003', 'RDS backup retention period < 7 days', 'MEDIUM', 'terraform', 'Set backup_retention_period to 7+.', '["rds","backup","aws"]'),
('SHLD-RDS-004', 'RDS does not have deletion protection', 'MEDIUM', 'terraform', 'Set deletion_protection = true.', '["rds","deletion-protection","aws"]'),
('SHLD-RDS-005', 'RDS is not Multi-AZ', 'MEDIUM', 'terraform', 'Set multi_az = true.', '["rds","multi-az","aws"]'),
('SHLD-RDS-006', 'RDS auto minor version upgrade disabled', 'LOW', 'terraform', 'Set auto_minor_version_upgrade = true.', '["rds","patching","aws"]'),
('SHLD-RDS-007', 'RDS IAM auth not enabled', 'MEDIUM', 'terraform', 'Set iam_database_authentication_enabled = true.', '["rds","iam-auth","aws"]'),
('SHLD-RDS-008', 'RDS enhanced monitoring not enabled', 'LOW', 'terraform', 'Set monitoring_interval > 0.', '["rds","monitoring","aws"]'),
('SHLD-RDS-009', 'RDS does not copy tags to snapshots', 'INFO', 'terraform', 'Set copy_tags_to_snapshot = true.', '["rds","tagging","aws"]'),
('SHLD-RDS-010', 'RDS Performance Insights not enabled', 'LOW', 'terraform', 'Set performance_insights_enabled = true.', '["rds","monitoring","aws"]');

-- ── Terraform VPC Rules ─────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-VPC-001', 'VPC does not have flow logs enabled', 'HIGH', 'terraform', 'Create aws_flow_log for the VPC.', '["vpc","flow-logs","aws","monitoring"]'),
('SHLD-VPC-002', 'Default VPC security group allows traffic', 'HIGH', 'terraform', 'Restrict default SG with aws_default_security_group.', '["vpc","security-group","aws"]'),
('SHLD-VPC-003', 'Network ACL allows unrestricted inbound traffic', 'HIGH', 'terraform', 'Restrict NACL ingress rules.', '["vpc","nacl","aws","network"]'),
('SHLD-VPC-004', 'Subnet auto-assigns public IPs', 'MEDIUM', 'terraform', 'Set map_public_ip_on_launch = false.', '["vpc","subnet","aws"]'),
('SHLD-VPC-005', 'VPC endpoint lacks restrictive policy', 'MEDIUM', 'terraform', 'Add policy to VPC endpoint.', '["vpc","endpoint","aws"]');

-- ── Kubernetes Pod Security Rules ───────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-K8S-POD-001', 'Container runs in privileged mode', 'CRITICAL', 'kubernetes', 'Set securityContext.privileged to false.', '["kubernetes","pod-security","privileged"]'),
('SHLD-K8S-POD-002', 'Container runs as root (UID 0)', 'HIGH', 'kubernetes', 'Set runAsNonRoot to true.', '["kubernetes","pod-security","root"]'),
('SHLD-K8S-POD-003', 'Container adds dangerous capabilities', 'HIGH', 'kubernetes', 'Remove dangerous capabilities from add.', '["kubernetes","pod-security","capabilities"]'),
('SHLD-K8S-POD-004', 'Container does not drop all capabilities', 'MEDIUM', 'kubernetes', 'Add capabilities.drop: [ALL].', '["kubernetes","pod-security","capabilities"]'),
('SHLD-K8S-POD-005', 'Pod uses host network', 'HIGH', 'kubernetes', 'Set hostNetwork to false.', '["kubernetes","pod-security","host-network"]'),
('SHLD-K8S-POD-006', 'Pod uses host PID', 'HIGH', 'kubernetes', 'Set hostPID to false.', '["kubernetes","pod-security","host-pid"]'),
('SHLD-K8S-POD-007', 'Pod uses host IPC', 'HIGH', 'kubernetes', 'Set hostIPC to false.', '["kubernetes","pod-security","host-ipc"]'),
('SHLD-K8S-POD-008', 'Container does not use read-only root filesystem', 'MEDIUM', 'kubernetes', 'Set readOnlyRootFilesystem to true.', '["kubernetes","pod-security","filesystem"]'),
('SHLD-K8S-POD-009', 'Container allows privilege escalation', 'HIGH', 'kubernetes', 'Set allowPrivilegeEscalation to false.', '["kubernetes","pod-security","privilege-escalation"]'),
('SHLD-K8S-POD-010', 'Container has no Seccomp profile', 'MEDIUM', 'kubernetes', 'Set seccompProfile.type to RuntimeDefault.', '["kubernetes","pod-security","seccomp"]'),
('SHLD-K8S-POD-011', 'Container image uses latest tag', 'MEDIUM', 'kubernetes', 'Use specific image tag or SHA digest.', '["kubernetes","pod-security","image"]'),
('SHLD-K8S-POD-012', 'Container imagePullPolicy not Always', 'LOW', 'kubernetes', 'Set imagePullPolicy to Always.', '["kubernetes","pod-security","image"]'),
('SHLD-K8S-POD-013', 'Pod mounts hostPath volume', 'HIGH', 'kubernetes', 'Use PersistentVolumeClaims instead.', '["kubernetes","pod-security","volumes"]'),
('SHLD-K8S-POD-014', 'Pod automounts service account token', 'MEDIUM', 'kubernetes', 'Set automountServiceAccountToken to false.', '["kubernetes","pod-security","service-account"]'),
('SHLD-K8S-POD-015', 'Container has no liveness probe', 'LOW', 'kubernetes', 'Add livenessProbe.', '["kubernetes","reliability","probes"]'),
('SHLD-K8S-POD-016', 'Container has no readiness probe', 'LOW', 'kubernetes', 'Add readinessProbe.', '["kubernetes","reliability","probes"]');

-- ── Kubernetes Network Policy Rules ─────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-K8S-NET-001', 'Namespace has no default deny NetworkPolicy', 'HIGH', 'kubernetes', 'Create default deny NetworkPolicy.', '["kubernetes","network-policy","zero-trust"]'),
('SHLD-K8S-NET-002', 'NetworkPolicy allows all ingress', 'HIGH', 'kubernetes', 'Restrict ingress from.', '["kubernetes","network-policy"]'),
('SHLD-K8S-NET-003', 'NetworkPolicy does not restrict egress', 'MEDIUM', 'kubernetes', 'Add Egress to policyTypes.', '["kubernetes","network-policy","egress"]'),
('SHLD-K8S-NET-004', 'NetworkPolicy does not specify ports', 'MEDIUM', 'kubernetes', 'Specify ports in rules.', '["kubernetes","network-policy","ports"]');

-- ── Kubernetes RBAC Rules ───────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-K8S-RBAC-001', 'ClusterRoleBinding grants cluster-admin', 'CRITICAL', 'kubernetes', 'Use scoped roles.', '["kubernetes","rbac","cluster-admin"]'),
('SHLD-K8S-RBAC-002', 'Role uses wildcard verbs (*)', 'HIGH', 'kubernetes', 'Use specific verbs.', '["kubernetes","rbac","wildcard"]'),
('SHLD-K8S-RBAC-003', 'Role grants access to all resources (*)', 'HIGH', 'kubernetes', 'Scope resources.', '["kubernetes","rbac","wildcard"]'),
('SHLD-K8S-RBAC-004', 'Role grants secrets access', 'HIGH', 'kubernetes', 'Restrict secrets access.', '["kubernetes","rbac","secrets"]'),
('SHLD-K8S-RBAC-005', 'Role allows privilege escalation verbs', 'CRITICAL', 'kubernetes', 'Remove bind/escalate/impersonate.', '["kubernetes","rbac","escalation"]'),
('SHLD-K8S-RBAC-006', 'Pod uses default service account', 'MEDIUM', 'kubernetes', 'Create dedicated service account.', '["kubernetes","rbac","service-account"]');

-- ── Kubernetes Resource Rules ───────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-K8S-RES-001', 'Container has no resource limits', 'MEDIUM', 'kubernetes', 'Add resources.limits.', '["kubernetes","resources","limits"]'),
('SHLD-K8S-RES-002', 'Container has no resource requests', 'MEDIUM', 'kubernetes', 'Add resources.requests.', '["kubernetes","resources","requests"]'),
('SHLD-K8S-RES-003', 'Container memory limit excessively high', 'LOW', 'kubernetes', 'Review memory limits.', '["kubernetes","resources","memory"]'),
('SHLD-K8S-RES-004', 'Container has no ephemeral storage limit', 'LOW', 'kubernetes', 'Add ephemeral-storage limit.', '["kubernetes","resources","storage"]');

-- ── Dockerfile Rules ────────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-DOCKER-001', 'Dockerfile has no USER instruction', 'HIGH', 'dockerfile', 'Add USER nonroot before CMD.', '["docker","user","root"]'),
('SHLD-DOCKER-002', 'Dockerfile uses ADD instead of COPY', 'MEDIUM', 'dockerfile', 'Use COPY instead.', '["docker","add","copy"]'),
('SHLD-DOCKER-003', 'Dockerfile uses latest/untagged base image', 'HIGH', 'dockerfile', 'Pin base image version.', '["docker","base-image","pinning"]'),
('SHLD-DOCKER-004', 'Dockerfile exposes secrets in ENV/ARG', 'CRITICAL', 'dockerfile', 'Use build secrets instead.', '["docker","secrets","credentials"]'),
('SHLD-DOCKER-005', 'Dockerfile has no HEALTHCHECK', 'LOW', 'dockerfile', 'Add HEALTHCHECK instruction.', '["docker","healthcheck"]'),
('SHLD-DOCKER-006', 'Dockerfile uses sudo', 'MEDIUM', 'dockerfile', 'Remove sudo.', '["docker","sudo"]'),
('SHLD-DOCKER-007', 'Dockerfile uses shell form CMD', 'LOW', 'dockerfile', 'Use exec form.', '["docker","cmd","exec-form"]'),
('SHLD-DOCKER-008', 'apt-get install without pinned versions', 'MEDIUM', 'dockerfile', 'Pin package versions.', '["docker","apt-get","pinning"]'),
('SHLD-DOCKER-009', 'apt-get install without cleanup', 'LOW', 'dockerfile', 'Add apt-get clean.', '["docker","apt-get","cleanup"]'),
('SHLD-DOCKER-010', 'Dockerfile exposes SSH port 22', 'HIGH', 'dockerfile', 'Remove EXPOSE 22.', '["docker","ssh","expose"]'),
('SHLD-DOCKER-011', 'Dockerfile has no WORKDIR', 'LOW', 'dockerfile', 'Add WORKDIR /app.', '["docker","workdir"]'),
('SHLD-DOCKER-012', 'Dockerfile has multiple CMD instructions', 'MEDIUM', 'dockerfile', 'Use single CMD.', '["docker","cmd"]'),
('SHLD-DOCKER-013', 'Dockerfile pipes curl to shell', 'HIGH', 'dockerfile', 'Download then verify then execute.', '["docker","curl","supply-chain"]'),
('SHLD-DOCKER-014', 'Dockerfile COPY uses wildcard', 'MEDIUM', 'dockerfile', 'Copy specific files.', '["docker","copy"]'),
('SHLD-DOCKER-015', 'Dockerfile downloads without SSL', 'HIGH', 'dockerfile', 'Remove --no-check-certificate.', '["docker","ssl"]'),
('SHLD-DOCKER-016', 'Dockerfile uses untrusted base image', 'MEDIUM', 'dockerfile', 'Use official images.', '["docker","base-image","supply-chain"]'),
('SHLD-DOCKER-017', 'Dockerfile sets USER to root', 'HIGH', 'dockerfile', 'Change to non-root user.', '["docker","user","root"]'),
('SHLD-DOCKER-018', 'pip install without --no-cache-dir', 'INFO', 'dockerfile', 'Add --no-cache-dir.', '["docker","pip","image-size"]'),
('SHLD-DOCKER-019', 'Dockerfile has no LABEL instructions', 'INFO', 'dockerfile', 'Add LABEL metadata.', '["docker","label","metadata"]'),
('SHLD-DOCKER-020', 'Dockerfile uses npm --unsafe-perm', 'MEDIUM', 'dockerfile', 'Remove --unsafe-perm.', '["docker","npm","security"]');

-- ── GCP Rules ───────────────────────────────────────────────────────────
INSERT INTO rules (id, description, severity, resource_type, remediation, tags) VALUES
('SHLD-GCP-COMPUTE-001', 'GCP instance has serial port enabled', 'MEDIUM', 'terraform', 'Set serial-port-enable to false.', '["gcp","compute","serial-port"]'),
('SHLD-GCP-COMPUTE-002', 'GCP instance has no OS Login', 'MEDIUM', 'terraform', 'Set enable-oslogin to TRUE.', '["gcp","compute","os-login"]'),
('SHLD-GCP-COMPUTE-003', 'GCP instance lacks Shielded VM', 'MEDIUM', 'terraform', 'Enable shielded_instance_config.', '["gcp","compute","shielded-vm"]'),
('SHLD-GCP-COMPUTE-004', 'GCP instance has public IP', 'HIGH', 'terraform', 'Remove access_config.', '["gcp","compute","public-ip"]'),
('SHLD-GCP-COMPUTE-005', 'GCP instance has IP forwarding', 'MEDIUM', 'terraform', 'Set can_ip_forward = false.', '["gcp","compute","ip-forwarding"]'),
('SHLD-GCP-COMPUTE-006', 'GCP instance uses default SA', 'HIGH', 'terraform', 'Create custom service account.', '["gcp","compute","service-account"]'),
('SHLD-GCP-COMPUTE-007', 'GCP disk has no CMEK', 'MEDIUM', 'terraform', 'Add disk_encryption_key.', '["gcp","compute","encryption"]'),
('SHLD-GCP-COMPUTE-008', 'GCP firewall allows all from 0.0.0.0/0', 'CRITICAL', 'terraform', 'Restrict source_ranges.', '["gcp","firewall","network"]'),
('SHLD-GCP-STORAGE-001', 'GCP bucket no uniform access', 'MEDIUM', 'terraform', 'Set uniform_bucket_level_access = true.', '["gcp","storage","access-control"]'),
('SHLD-GCP-STORAGE-002', 'GCP bucket allows public access', 'CRITICAL', 'terraform', 'Remove allUsers/allAuthenticatedUsers.', '["gcp","storage","public-access"]'),
('SHLD-GCP-STORAGE-003', 'GCP bucket no versioning', 'MEDIUM', 'terraform', 'Add versioning { enabled = true }.', '["gcp","storage","versioning"]'),
('SHLD-GCP-STORAGE-004', 'GCP bucket no logging', 'MEDIUM', 'terraform', 'Add logging block.', '["gcp","storage","logging"]'),
('SHLD-GCP-STORAGE-005', 'GCP bucket no CMEK', 'MEDIUM', 'terraform', 'Add encryption { default_kms_key_name }.', '["gcp","storage","encryption"]'),
('SHLD-GCP-STORAGE-006', 'GCP bucket no retention policy', 'LOW', 'terraform', 'Add retention_policy.', '["gcp","storage","retention"]'),
('SHLD-GCP-IAM-001', 'GCP IAM uses primitive roles', 'HIGH', 'terraform', 'Use predefined or custom roles.', '["gcp","iam","primitive-roles"]'),
('SHLD-GCP-IAM-002', 'GCP SA key managed in Terraform', 'HIGH', 'terraform', 'Use Workload Identity.', '["gcp","iam","service-account-key"]'),
('SHLD-GCP-IAM-003', 'GCP IAM binding grants public access', 'CRITICAL', 'terraform', 'Remove allUsers/allAuthenticatedUsers.', '["gcp","iam","public-access"]'),
('SHLD-GCP-IAM-004', 'GCP project no audit logging', 'HIGH', 'terraform', 'Configure audit_log_config.', '["gcp","iam","audit-logging"]'),
('SHLD-GCP-IAM-005', 'GCP IAM SA impersonation role granted broadly', 'HIGH', 'terraform', 'Restrict SA impersonation.', '["gcp","iam","impersonation"]');

-- ── Compliance Mappings (sample) ────────────────────────────────────────
INSERT INTO compliance_mappings (rule_id, framework, control_id, control_desc) VALUES
('SHLD-S3-001', 'CIS-AWS', '2.1.1', 'Ensure S3 bucket encryption is enabled'),
('SHLD-S3-001', 'SOC2', 'CC6.1', 'Logical and physical access controls'),
('SHLD-S3-001', 'HIPAA', '164.312(a)(2)(iv)', 'Encryption and decryption'),
('SHLD-S3-001', 'PCI-DSS', '3.4', 'Render PAN unreadable'),
('SHLD-S3-002', 'CIS-AWS', '2.1.5', 'Ensure S3 bucket has public access block'),
('SHLD-S3-002', 'PCI-DSS', '1.2.1', 'Restrict inbound and outbound traffic'),
('SHLD-EC2-001', 'CIS-AWS', '5.2', 'Ensure no security groups allow SSH from 0.0.0.0/0'),
('SHLD-EC2-001', 'PCI-DSS', '1.2.1', 'Restrict inbound/outbound traffic'),
('SHLD-IAM-001', 'CIS-AWS', '1.16', 'Ensure IAM policies do not allow full admin'),
('SHLD-IAM-001', 'SOC2', 'CC6.3', 'Role-based access'),
('SHLD-RDS-001', 'HIPAA', '164.312(a)(2)(iv)', 'Encryption and decryption'),
('SHLD-RDS-002', 'CIS-AWS', '2.3.2', 'Ensure RDS is not publicly accessible'),
('SHLD-K8S-POD-001', 'CIS-K8S', '5.2.1', 'Minimize privileged containers'),
('SHLD-K8S-RBAC-001', 'CIS-K8S', '5.1.1', 'Minimize cluster-admin usage');
