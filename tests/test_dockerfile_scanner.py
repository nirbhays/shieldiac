"""
ShieldIaC — Dockerfile Scanner Tests
"""
import pytest
from pathlib import Path

from backend.rules.base import RuleContext, Severity, ResourceType, registry
from backend.services.dockerfile_scanner import DockerfileScanner


@pytest.fixture
def scanner():
    return DockerfileScanner()


@pytest.fixture
def insecure_dockerfile():
    return Path(__file__).parent / "fixtures" / "docker" / "insecure_dockerfile"


@pytest.fixture
def secure_dockerfile():
    return Path(__file__).parent / "fixtures" / "docker" / "secure_dockerfile"


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_no_user(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-001" in rule_ids  # No USER


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_add(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-002" in rule_ids  # ADD instead of COPY


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_unpinned(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-003" in rule_ids  # Unpinned base image


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_secrets(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-004" in rule_ids  # Secrets in ENV/ARG


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_curl_pipe(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-013" in rule_ids  # curl piped to bash


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_ssh(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-010" in rule_ids  # EXPOSE 22


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_sudo(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-006" in rule_ids  # sudo


@pytest.mark.asyncio
async def test_insecure_dockerfile_finds_multiple_cmd(scanner, insecure_dockerfile):
    content = insecure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-DOCKER-012" in rule_ids  # Multiple CMD


@pytest.mark.asyncio
async def test_secure_dockerfile_minimal_findings(scanner, secure_dockerfile):
    content = secure_dockerfile.read_text()
    findings = await scanner.scan("Dockerfile", content)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(critical) == 0
    assert len(high) == 0


def test_rule_registry_has_dockerfile_rules():
    docker_rules = registry.by_resource_type(ResourceType.DOCKERFILE)
    assert len(docker_rules) >= 20, f"Expected 20+ Dockerfile rules, got {len(docker_rules)}"
