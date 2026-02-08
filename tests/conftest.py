"""
ShieldIaC — Test Configuration (conftest.py)
"""
import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.rules.base import registry, RuleRegistry
from backend.rules.loader import load_rules


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset the rule registry before each test to avoid cross-contamination."""
    registry.reset()
    load_rules()
    yield
    # registry persists across tests, which is fine since we reset it


@pytest.fixture
def terraform_resource():
    """Factory for creating Terraform resource dicts."""
    def _make(resource_type: str, name: str = "test", config: dict = None, line: int = 1):
        return {
            "type": resource_type,
            "name": name,
            "config": config or {},
            "line": line,
            "file_path": "test.tf",
        }
    return _make


@pytest.fixture
def k8s_resource():
    """Factory for creating Kubernetes resource dicts."""
    def _make(kind: str, name: str = "test", spec: dict = None, line: int = 1):
        return {
            "kind": kind,
            "apiVersion": "v1",
            "name": name,
            "namespace": "default",
            "config": {
                "kind": kind,
                "metadata": {"name": name},
                "spec": spec or {},
            },
            "line": line,
            "file_path": "test.yaml",
        }
    return _make


@pytest.fixture
def sample_files():
    """Load all test fixtures as file dicts."""
    fixtures_dir = Path(__file__).parent / "fixtures"
    files = {}
    for f in fixtures_dir.rglob("*"):
        if f.is_file():
            files[f.relative_to(fixtures_dir).as_posix()] = {
                "path": f.relative_to(fixtures_dir).as_posix(),
                "content": f.read_text(encoding="utf-8"),
            }
    return files
