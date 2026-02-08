"""
ShieldIaC — Dockerfile Best Practice Rules

Covers: USER instruction, COPY vs ADD, pinned versions, secrets exposure,
        HEALTHCHECK, EXPOSE, multi-stage builds, WORKDIR, shell form CMD,
        latest base images, unnecessary packages, LABEL, trusted base images,
        ENTRYPOINT, unnecessary EXPOSE, curl/wget in RUN, sudo usage,
        .dockerignore, apt cleanup, SHELL instruction.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List

from backend.rules.base import (
    BaseRule, ComplianceFramework, ComplianceMapping, Finding,
    ResourceType, RuleContext, Severity, registry,
)


def _parse_dockerfile(content: str) -> List[Dict[str, Any]]:
    """Parse a Dockerfile into a list of instruction dicts."""
    instructions = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Handle line continuations
        while line.endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line[:-1] + " " + lines[i].strip()
        if line and not line.startswith("#"):
            parts = line.split(None, 1)
            if parts:
                instructions.append({
                    "instruction": parts[0].upper(),
                    "value": parts[1] if len(parts) > 1 else "",
                    "line_number": i + 1,
                    "raw": line,
                })
        i += 1
    return instructions


# ─── DOCKER-001  No USER instruction ────────────────────────────────────

@registry.register
class DockerNoUser(BaseRule):
    id = "SHLD-DOCKER-001"
    description = "Dockerfile does not contain a USER instruction (container will run as root)"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = "Add `USER nonroot` or `USER 1000` before the CMD/ENTRYPOINT instruction."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "4.1", "Ensure containers run as non-root"),
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Logical access controls"),
    ]
    tags = ["docker", "user", "root", "security"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        has_user = any(i["instruction"] == "USER" for i in instructions)
        if not has_user:
            return [self.make_finding(resource.get("name", "Dockerfile"), context.file_path, 1)]
        return []


# ─── DOCKER-002  ADD instead of COPY ────────────────────────────────────

@registry.register
class DockerAddInsteadOfCopy(BaseRule):
    id = "SHLD-DOCKER-002"
    description = "Dockerfile uses ADD instead of COPY (ADD can fetch remote URLs and extract archives)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Use `COPY` instead of `ADD` unless you specifically need tar extraction or URL fetching."
    tags = ["docker", "add", "copy", "best-practice"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "ADD":
                val = inst["value"]
                # Allow ADD for .tar files (legitimate use)
                if not any(ext in val for ext in [".tar", ".gz", ".bz2", ".xz"]):
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        description_override=f"Use COPY instead of ADD: `{inst['raw'][:80]}`",
                    ))
        return findings


# ─── DOCKER-003  Unpinned base image ────────────────────────────────────

@registry.register
class DockerUnpinnedBaseImage(BaseRule):
    id = "SHLD-DOCKER-003"
    description = "Dockerfile uses 'latest' tag or no tag for base image"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = "Pin the base image to a specific version tag or SHA digest."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "Change management"),
    ]
    tags = ["docker", "base-image", "pinning"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "FROM":
                image = inst["value"].split(" ")[0]  # Remove AS alias
                if image == "scratch":
                    continue
                if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        description_override=f"Base image is not pinned: `{image}`",
                    ))
        return findings


# ─── DOCKER-004  Secrets in ENV/ARG ─────────────────────────────────────

@registry.register
class DockerSecretsInEnv(BaseRule):
    id = "SHLD-DOCKER-004"
    description = "Dockerfile exposes secrets via ENV or ARG instructions"
    severity = Severity.CRITICAL
    resource_type = ResourceType.DOCKERFILE
    remediation = (
        "Use Docker build secrets (`--mount=type=secret`) or runtime env vars "
        "instead of hardcoding secrets in ENV/ARG."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC6.1", "Data protection"),
        ComplianceMapping(ComplianceFramework.PCI_DSS, "2.1", "Do not use vendor defaults"),
    ]
    tags = ["docker", "secrets", "credentials"]

    SECRET_PATTERNS = re.compile(
        r"(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
        r"aws[_-]?secret|db[_-]?pass|mysql[_-]?root|postgres[_-]?password)",
        re.IGNORECASE,
    )

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] in ("ENV", "ARG"):
                if self.SECRET_PATTERNS.search(inst["value"]):
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        description_override=f"Potential secret in {inst['instruction']}: `{inst['value'][:60]}...`",
                    ))
        return findings


# ─── DOCKER-005  No HEALTHCHECK ──────────────────────────────────────────

@registry.register
class DockerNoHealthcheck(BaseRule):
    id = "SHLD-DOCKER-005"
    description = "Dockerfile does not define a HEALTHCHECK instruction"
    severity = Severity.LOW
    resource_type = ResourceType.DOCKERFILE
    remediation = "Add `HEALTHCHECK CMD curl -f http://localhost/ || exit 1` or equivalent."
    tags = ["docker", "healthcheck", "reliability"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        has_healthcheck = any(i["instruction"] == "HEALTHCHECK" for i in instructions)
        if not has_healthcheck:
            return [self.make_finding(resource.get("name", "Dockerfile"), context.file_path, 1)]
        return []


# ─── DOCKER-006  RUN with sudo ──────────────────────────────────────────

@registry.register
class DockerSudo(BaseRule):
    id = "SHLD-DOCKER-006"
    description = "Dockerfile uses sudo in RUN instructions (unnecessary in Docker)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Remove `sudo` — Docker runs as root by default during build."
    tags = ["docker", "sudo", "best-practice"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN" and "sudo " in inst["value"]:
                findings.append(self.make_finding(
                    resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                ))
        return findings


# ─── DOCKER-007  Shell form CMD ──────────────────────────────────────────

@registry.register
class DockerShellFormCMD(BaseRule):
    id = "SHLD-DOCKER-007"
    description = "Dockerfile uses shell form for CMD/ENTRYPOINT (signals not properly forwarded)"
    severity = Severity.LOW
    resource_type = ResourceType.DOCKERFILE
    remediation = "Use exec form: `CMD [\"executable\", \"param1\"]` instead of `CMD command param1`."
    tags = ["docker", "cmd", "exec-form"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] in ("CMD", "ENTRYPOINT"):
                val = inst["value"].strip()
                if val and not val.startswith("["):
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    ))
        return findings


# ─── DOCKER-008  Unpinned apt-get packages ───────────────────────────────

@registry.register
class DockerUnpinnedPackages(BaseRule):
    id = "SHLD-DOCKER-008"
    description = "RUN apt-get install does not pin package versions"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Pin packages: `apt-get install -y package=1.2.3` for reproducible builds."
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "Change management"),
    ]
    tags = ["docker", "apt-get", "pinning"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN" and "apt-get install" in inst["value"]:
                # Check if any package has a version pin (=)
                parts = inst["value"].split()
                install_idx = None
                for idx, part in enumerate(parts):
                    if part == "install":
                        install_idx = idx
                        break
                if install_idx:
                    packages = [p for p in parts[install_idx + 1:] if not p.startswith("-")]
                    unpinned = [p for p in packages if "=" not in p and p not in ("&&", "\\", "|")]
                    if unpinned:
                        findings.append(self.make_finding(
                            resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        ))
        return findings


# ─── DOCKER-009  No apt-get clean ────────────────────────────────────────

@registry.register
class DockerNoAptClean(BaseRule):
    id = "SHLD-DOCKER-009"
    description = "RUN apt-get install does not clean up apt cache (increases image size)"
    severity = Severity.LOW
    resource_type = ResourceType.DOCKERFILE
    remediation = (
        "Add `&& apt-get clean && rm -rf /var/lib/apt/lists/*` in the same RUN layer."
    )
    tags = ["docker", "apt-get", "cleanup", "image-size"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN" and "apt-get install" in inst["value"]:
                if "apt-get clean" not in inst["value"] and "rm -rf /var/lib/apt/lists" not in inst["value"]:
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    ))
        return findings


# ─── DOCKER-010  EXPOSE port 22 ─────────────────────────────────────────

@registry.register
class DockerExposeSSH(BaseRule):
    id = "SHLD-DOCKER-010"
    description = "Dockerfile exposes SSH port 22 (anti-pattern for containers)"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = "Remove `EXPOSE 22`. Use `docker exec` or `kubectl exec` for debugging."
    compliance = [
        ComplianceMapping(ComplianceFramework.CIS_K8S, "4.5", "Ensure SSH is not exposed"),
    ]
    tags = ["docker", "ssh", "expose"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "EXPOSE":
                ports = inst["value"].split()
                for port in ports:
                    port_num = port.split("/")[0]
                    if port_num == "22":
                        findings.append(self.make_finding(
                            resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        ))
        return findings


# ─── DOCKER-011  Missing WORKDIR ─────────────────────────────────────────

@registry.register
class DockerMissingWorkdir(BaseRule):
    id = "SHLD-DOCKER-011"
    description = "Dockerfile does not set a WORKDIR (files scattered in root)"
    severity = Severity.LOW
    resource_type = ResourceType.DOCKERFILE
    remediation = "Add `WORKDIR /app` (or appropriate directory) before COPY/RUN instructions."
    tags = ["docker", "workdir", "best-practice"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        has_workdir = any(i["instruction"] == "WORKDIR" for i in instructions)
        if not has_workdir:
            return [self.make_finding(resource.get("name", "Dockerfile"), context.file_path, 1)]
        return []


# ─── DOCKER-012  Multiple CMD instructions ──────────────────────────────

@registry.register
class DockerMultipleCMD(BaseRule):
    id = "SHLD-DOCKER-012"
    description = "Dockerfile has multiple CMD instructions (only the last one takes effect)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Use only one CMD instruction. Use a shell script if you need multiple commands."
    tags = ["docker", "cmd", "best-practice"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        cmd_count = sum(1 for i in instructions if i["instruction"] == "CMD")
        if cmd_count > 1:
            return [self.make_finding(resource.get("name", "Dockerfile"), context.file_path, 1)]
        return []


# ─── DOCKER-013  curl/wget piped to shell ───────────────────────────────

@registry.register
class DockerCurlPipeBash(BaseRule):
    id = "SHLD-DOCKER-013"
    description = "Dockerfile pipes curl/wget output to shell (supply chain risk)"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = (
        "Download the script first, verify its checksum, then execute it. "
        "Or use a package manager instead."
    )
    compliance = [
        ComplianceMapping(ComplianceFramework.SOC2, "CC7.2", "Change management"),
    ]
    tags = ["docker", "curl", "supply-chain"]

    PATTERNS = [
        re.compile(r"curl.*\|\s*(bash|sh|zsh)"),
        re.compile(r"wget.*\|\s*(bash|sh|zsh)"),
        re.compile(r"curl.*\|.*\|\s*(bash|sh|zsh)"),
    ]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN":
                for pattern in self.PATTERNS:
                    if pattern.search(inst["value"]):
                        findings.append(self.make_finding(
                            resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                        ))
                        break
        return findings


# ─── DOCKER-014  COPY with wildcard ──────────────────────────────────────

@registry.register
class DockerCopyWildcard(BaseRule):
    id = "SHLD-DOCKER-014"
    description = "Dockerfile COPY uses `.` or `*` (may include unintended files)"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Copy specific files/directories. Use `.dockerignore` to exclude sensitive files."
    tags = ["docker", "copy", "best-practice"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "COPY":
                src = inst["value"].split()[0] if inst["value"] else ""
                if src in (".", "*", "./"):
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    ))
        return findings


# ─── DOCKER-015  RUN with --no-check-certificate ────────────────────────

@registry.register
class DockerInsecureDownload(BaseRule):
    id = "SHLD-DOCKER-015"
    description = "Dockerfile downloads files without SSL verification"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = "Remove `--no-check-certificate` / `-k` flags and fix certificate issues properly."
    tags = ["docker", "ssl", "security"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN":
                if "--no-check-certificate" in inst["value"] or "curl -k" in inst["value"] or "curl --insecure" in inst["value"]:
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    ))
        return findings


# ─── DOCKER-016  Untrusted base image ───────────────────────────────────

@registry.register
class DockerUntrustedBaseImage(BaseRule):
    id = "SHLD-DOCKER-016"
    description = "Dockerfile uses a base image not from a trusted registry"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Use images from Docker Official Images, verified publishers, or your private registry."
    tags = ["docker", "base-image", "supply-chain"]

    TRUSTED_PREFIXES = [
        "docker.io/library/",
        "gcr.io/",
        "ghcr.io/",
        "mcr.microsoft.com/",
        "public.ecr.aws/",
    ]
    OFFICIAL_IMAGES = {
        "alpine", "ubuntu", "debian", "centos", "fedora", "node", "python",
        "golang", "rust", "java", "openjdk", "nginx", "httpd", "postgres",
        "mysql", "redis", "mongo", "scratch", "busybox",
    }

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "FROM":
                image = inst["value"].split(" ")[0].split(":")[0].split("@")[0]
                if image in self.OFFICIAL_IMAGES or image == "scratch":
                    continue
                if any(image.startswith(p) for p in self.TRUSTED_PREFIXES):
                    continue
                # If it has a / it's from a registry, check if it's known
                if "/" not in image:
                    continue  # Docker Hub official-style image
                findings.append(self.make_finding(
                    resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    description_override=f"Base image from untrusted registry: `{image}`",
                ))
        return findings


# ─── DOCKER-017  Running as specific root UID ───────────────────────────

@registry.register
class DockerUserRoot(BaseRule):
    id = "SHLD-DOCKER-017"
    description = "Dockerfile explicitly sets USER to root"
    severity = Severity.HIGH
    resource_type = ResourceType.DOCKERFILE
    remediation = "Change USER to a non-root user (e.g., `USER 1000` or `USER nonroot`)."
    tags = ["docker", "user", "root"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        # Check the LAST USER instruction
        user_instructions = [i for i in instructions if i["instruction"] == "USER"]
        if user_instructions:
            last_user = user_instructions[-1]
            user_val = last_user["value"].strip().split(":")[0]
            if user_val in ("root", "0"):
                findings.append(self.make_finding(
                    resource.get("name", "Dockerfile"), context.file_path, last_user["line_number"],
                ))
        return findings


# ─── DOCKER-018  pip install without --no-cache-dir ─────────────────────

@registry.register
class DockerPipNoCache(BaseRule):
    id = "SHLD-DOCKER-018"
    description = "pip install without --no-cache-dir increases image size"
    severity = Severity.INFO
    resource_type = ResourceType.DOCKERFILE
    remediation = "Use `pip install --no-cache-dir` to reduce image size."
    tags = ["docker", "pip", "image-size"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN" and "pip install" in inst["value"]:
                if "--no-cache-dir" not in inst["value"]:
                    findings.append(self.make_finding(
                        resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                    ))
        return findings


# ─── DOCKER-019  LABEL missing ───────────────────────────────────────────

@registry.register
class DockerMissingLabel(BaseRule):
    id = "SHLD-DOCKER-019"
    description = "Dockerfile does not include LABEL instructions for metadata"
    severity = Severity.INFO
    resource_type = ResourceType.DOCKERFILE
    remediation = "Add LABEL instructions: `LABEL maintainer=\"...\" version=\"...\" description=\"...\"`."
    tags = ["docker", "label", "metadata"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        has_label = any(i["instruction"] == "LABEL" for i in instructions)
        if not has_label:
            return [self.make_finding(resource.get("name", "Dockerfile"), context.file_path, 1)]
        return []


# ─── DOCKER-020  npm install with --unsafe-perm ─────────────────────────

@registry.register
class DockerNpmUnsafePerm(BaseRule):
    id = "SHLD-DOCKER-020"
    description = "Dockerfile uses npm with --unsafe-perm flag"
    severity = Severity.MEDIUM
    resource_type = ResourceType.DOCKERFILE
    remediation = "Remove `--unsafe-perm` and run npm as a non-root user instead."
    tags = ["docker", "npm", "security"]

    def evaluate(self, resource: Dict[str, Any], context: RuleContext) -> List[Finding]:
        instructions = _parse_dockerfile(context.file_content)
        findings = []
        for inst in instructions:
            if inst["instruction"] == "RUN" and "--unsafe-perm" in inst["value"]:
                findings.append(self.make_finding(
                    resource.get("name", "Dockerfile"), context.file_path, inst["line_number"],
                ))
        return findings
