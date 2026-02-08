"""
ShieldIaC — Kubernetes Pod Security Rules

Covers: privileged containers, root user, capabilities, host namespaces,
        read-only root filesystem, security context, privilege escalation,
        seccomp profiles, AppArmor, proc mount.
"""
from __future__ import annotations
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _iter_containers(resource: Dict[str, Any]):
    """Yield (container_dict, container_name) for all init+regular containers."""
    spec = resource.get("config", {}).get("spec", {})
    # Pod-level spec or template-level spec
    pod_spec = spec.get("template", {}).get("spec", spec)
    containers = pod_spec.get("containers", [])
    init_containers = pod_spec.get("initContainers", [])
    for c in containers + init_containers:
        yield c, c.get("name", "unnamed")


def _get_security_context(container: Dict):
    return container.get("securityContext", {})


# ─── K8S-POD-001  Privileged container ──────────────────────────────────

@registry.register
class K8SPrivilegedContainer(BaseRule):
    id = "SHLD-K8S-POD-001"
    description = "Container runs in privileged mode"
    severity = Severity.CRITICAL
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `securityContext.privileged` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.1", "Minimize privileged containers"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "2.2", "Develop configuration standards"),
    ]
    tags = ["kubernetes", "pod-security", "privileged"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            if sc.get("privileged") is True:
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-002  Run as root ───────────────────────────────────────────

@registry.register
class K8SRunAsRoot(BaseRule):
    id = "SHLD-K8S-POD-002"
    description = "Container runs as root (UID 0)"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `securityContext.runAsNonRoot` to `true` and `runAsUser` to a non-zero UID."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.6", "Minimize containers running as root"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["kubernetes", "pod-security", "root"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            run_as_non_root = sc.get("runAsNonRoot")
            run_as_user = sc.get("runAsUser", -1)
            if run_as_non_root is not True and (run_as_user == 0 or run_as_user == -1):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-003  Dangerous capabilities ────────────────────────────────

@registry.register
class K8SDangerousCapabilities(BaseRule):
    id = "SHLD-K8S-POD-003"
    description = "Container adds dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL)"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Remove dangerous capabilities from `securityContext.capabilities.add` and use `drop: [ALL]`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.7", "Minimize capabilities"),
    ]
    tags = ["kubernetes", "pod-security", "capabilities"]

    DANGEROUS = {"SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "NET_RAW", "SYS_MODULE"}

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            caps = sc.get("capabilities", {})
            added = caps.get("add", [])
            if isinstance(added, str):
                added = [added]
            for cap in added:
                if cap.upper() in self.DANGEROUS:
                    findings.append(self.make_finding(
                        resource_name=f"{resource.get('name', 'unknown')}/{name}",
                        file_path=context.file_path,
                        line_number=resource.get("line", 0),
                        description_override=f"Container adds dangerous capability: {cap}",
                    ))
        return findings


# ─── K8S-POD-004  Drop all capabilities ─────────────────────────────────

@registry.register
class K8SDropAllCapabilities(BaseRule):
    id = "SHLD-K8S-POD-004"
    description = "Container does not drop all Linux capabilities"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Add `securityContext.capabilities.drop: [\"ALL\"]` and add back only needed caps."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.7", "Minimize capabilities"),
    ]
    tags = ["kubernetes", "pod-security", "capabilities"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            caps = sc.get("capabilities", {})
            dropped = caps.get("drop", [])
            if isinstance(dropped, str):
                dropped = [dropped]
            if "ALL" not in [d.upper() for d in dropped]:
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-005  Host network ──────────────────────────────────────────

@registry.register
class K8SHostNetwork(BaseRule):
    id = "SHLD-K8S-POD-005"
    description = "Pod uses host network namespace"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `spec.hostNetwork` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.4", "Minimize host network usage"),
    ]
    tags = ["kubernetes", "pod-security", "host-network"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        if pod_spec.get("hostNetwork") is True:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


# ─── K8S-POD-006  Host PID ──────────────────────────────────────────────

@registry.register
class K8SHostPID(BaseRule):
    id = "SHLD-K8S-POD-006"
    description = "Pod uses host PID namespace"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `spec.hostPID` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.2", "Minimize host PID usage"),
    ]
    tags = ["kubernetes", "pod-security", "host-pid"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        if pod_spec.get("hostPID") is True:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


# ─── K8S-POD-007  Host IPC ──────────────────────────────────────────────

@registry.register
class K8SHostIPC(BaseRule):
    id = "SHLD-K8S-POD-007"
    description = "Pod uses host IPC namespace"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `spec.hostIPC` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.3", "Minimize host IPC usage"),
    ]
    tags = ["kubernetes", "pod-security", "host-ipc"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        if pod_spec.get("hostIPC") is True:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


# ─── K8S-POD-008  Read-only root filesystem ─────────────────────────────

@registry.register
class K8SReadOnlyRootFS(BaseRule):
    id = "SHLD-K8S-POD-008"
    description = "Container does not use a read-only root filesystem"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `securityContext.readOnlyRootFilesystem` to `true`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.8", "Ensure read-only root filesystem"),
    ]
    tags = ["kubernetes", "pod-security", "filesystem"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            if sc.get("readOnlyRootFilesystem") is not True:
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-009  Privilege escalation ───────────────────────────────────

@registry.register
class K8SPrivilegeEscalation(BaseRule):
    id = "SHLD-K8S-POD-009"
    description = "Container allows privilege escalation"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `securityContext.allowPrivilegeEscalation` to `false`."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.5", "Minimize privilege escalation"),
    ]
    tags = ["kubernetes", "pod-security", "privilege-escalation"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-010  Seccomp profile ────────────────────────────────────────

@registry.register
class K8SSeccompProfile(BaseRule):
    id = "SHLD-K8S-POD-010"
    description = "Container does not have a Seccomp profile configured"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = (
        "Set `securityContext.seccompProfile.type` to `RuntimeDefault` or `Localhost`."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.7.2", "Ensure Seccomp profile is set"),
    ]
    tags = ["kubernetes", "pod-security", "seccomp"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            sc = _get_security_context(container)
            seccomp = sc.get("seccompProfile", {})
            if not seccomp or seccomp.get("type") not in ("RuntimeDefault", "Localhost"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-011  Latest image tag ───────────────────────────────────────

@registry.register
class K8SLatestImageTag(BaseRule):
    id = "SHLD-K8S-POD-011"
    description = "Container image uses 'latest' tag or no tag (non-deterministic)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Use a specific image tag or SHA digest instead of `latest`."
    tags = ["kubernetes", "pod-security", "image"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            image = container.get("image", "")
            if not image:
                continue
            if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                    description_override=f"Container image `{image}` uses latest or no tag",
                ))
        return findings


# ─── K8S-POD-012  Image pull policy ──────────────────────────────────────

@registry.register
class K8SImagePullPolicy(BaseRule):
    id = "SHLD-K8S-POD-012"
    description = "Container does not set imagePullPolicy to Always"
    severity = Severity.LOW
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `imagePullPolicy` to `Always` to ensure the latest image is pulled."
    tags = ["kubernetes", "pod-security", "image"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            policy = container.get("imagePullPolicy", "")
            if policy != "Always":
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-013  Host path volumes ──────────────────────────────────────

@registry.register
class K8SHostPathVolume(BaseRule):
    id = "SHLD-K8S-POD-013"
    description = "Pod mounts a hostPath volume (security risk)"
    severity = Severity.HIGH
    resource_type = ResourceType.KUBERNETES
    remediation = "Avoid `hostPath` volumes. Use PersistentVolumeClaims instead."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.2.9", "Minimize hostPath usage"),
    ]
    tags = ["kubernetes", "pod-security", "volumes"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        volumes = pod_spec.get("volumes", [])
        findings = []
        for vol in volumes:
            if vol.get("hostPath"):
                findings.append(self.make_finding(
                    resource_name=resource.get("name", "unknown"),
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                    description_override=f"Pod mounts hostPath volume: {vol.get('name', 'unnamed')}",
                ))
        return findings


# ─── K8S-POD-014  Automount service account token ───────────────────────

@registry.register
class K8SAutomountSAToken(BaseRule):
    id = "SHLD-K8S-POD-014"
    description = "Pod automounts service account token (default behavior)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.KUBERNETES
    remediation = "Set `automountServiceAccountToken: false` unless the pod needs API access."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "5.1.6", "Minimize SA token automounting"),
    ]
    tags = ["kubernetes", "pod-security", "service-account"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        spec = resource.get("config", {}).get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)
        if pod_spec.get("automountServiceAccountToken") is not False:
            return [self.make_finding(resource.get("name", "unknown"), context.file_path, resource.get("line", 0))]
        return []


# ─── K8S-POD-015  Liveness probe missing ─────────────────────────────────

@registry.register
class K8SLivenessProbe(BaseRule):
    id = "SHLD-K8S-POD-015"
    description = "Container does not define a liveness probe"
    severity = Severity.LOW
    resource_type = ResourceType.KUBERNETES
    remediation = "Add a `livenessProbe` to detect deadlocked containers."
    tags = ["kubernetes", "reliability", "probes"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            if not container.get("livenessProbe"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings


# ─── K8S-POD-016  Readiness probe missing ────────────────────────────────

@registry.register
class K8SReadinessProbe(BaseRule):
    id = "SHLD-K8S-POD-016"
    description = "Container does not define a readiness probe"
    severity = Severity.LOW
    resource_type = ResourceType.KUBERNETES
    remediation = "Add a `readinessProbe` to control traffic routing."
    tags = ["kubernetes", "reliability", "probes"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        findings = []
        for container, name in _iter_containers(resource):
            if not container.get("readinessProbe"):
                findings.append(self.make_finding(
                    resource_name=f"{resource.get('name', 'unknown')}/{name}",
                    file_path=context.file_path,
                    line_number=resource.get("line", 0),
                ))
        return findings
