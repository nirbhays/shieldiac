"""
ShieldIaC — Kubernetes Scanner Tests
"""
import pytest
from pathlib import Path

from backend.rules.base import RuleContext, Severity, ResourceType, registry
from backend.services.kubernetes_scanner import KubernetesScanner


@pytest.fixture
def scanner():
    return KubernetesScanner()


@pytest.fixture
def insecure_pod():
    return Path(__file__).parent / "fixtures" / "kubernetes" / "insecure_pod.yaml"


@pytest.fixture
def secure_deployment():
    return Path(__file__).parent / "fixtures" / "kubernetes" / "secure_deployment.yaml"


@pytest.mark.asyncio
async def test_insecure_pod_finds_privileged(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-001" in rule_ids  # Privileged


@pytest.mark.asyncio
async def test_insecure_pod_finds_root(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-002" in rule_ids  # Run as root


@pytest.mark.asyncio
async def test_insecure_pod_finds_host_network(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-005" in rule_ids  # Host network


@pytest.mark.asyncio
async def test_insecure_pod_finds_capabilities(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-003" in rule_ids  # Dangerous capabilities


@pytest.mark.asyncio
async def test_insecure_pod_finds_hostpath(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-013" in rule_ids  # Host path volume


@pytest.mark.asyncio
async def test_insecure_pod_finds_latest_tag(scanner, insecure_pod):
    content = insecure_pod.read_text()
    findings = await scanner.scan("insecure_pod.yaml", content)
    rule_ids = {f.rule_id for f in findings}
    assert "SHLD-K8S-POD-011" in rule_ids  # Latest image tag


@pytest.mark.asyncio
async def test_secure_deployment_minimal_findings(scanner, secure_deployment):
    content = secure_deployment.read_text()
    findings = await scanner.scan("secure_deployment.yaml", content)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(critical) == 0, f"Secure deployment should have no critical findings: {[f.rule_id for f in critical]}"
    assert len(high) == 0, f"Secure deployment should have no high findings: {[f.rule_id for f in high]}"


def test_privileged_container_rule():
    from backend.rules.kubernetes.pod_security import K8SPrivilegedContainer
    rule = K8SPrivilegedContainer()
    resource = {
        "name": "test-pod",
        "kind": "Pod",
        "config": {
            "spec": {
                "containers": [{
                    "name": "app",
                    "securityContext": {"privileged": True}
                }]
            }
        },
        "line": 1,
    }
    context = RuleContext(file_path="test.yaml")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_rbac_cluster_admin_rule():
    from backend.rules.kubernetes.rbac import K8SClusterAdminBinding
    rule = K8SClusterAdminBinding()
    resource = {
        "name": "admin-binding",
        "kind": "ClusterRoleBinding",
        "config": {
            "roleRef": {"name": "cluster-admin", "kind": "ClusterRole"}
        },
        "line": 1,
    }
    context = RuleContext(file_path="test.yaml")
    findings = rule.evaluate(resource, context)
    assert len(findings) == 1


def test_rule_registry_has_kubernetes_rules():
    k8s_rules = registry.by_resource_type(ResourceType.KUBERNETES)
    assert len(k8s_rules) >= 30, f"Expected 30+ Kubernetes rules, got {len(k8s_rules)}"
