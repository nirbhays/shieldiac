"""
ShieldIaC — AI Fix Generator Tests
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from backend.rules.base import Finding, Severity
from backend.services.ai_fix_generator import AIFixGenerator


@pytest.fixture
def generator():
    return AIFixGenerator()


@pytest.fixture
def sample_finding():
    return Finding(
        rule_id="SHLD-S3-001",
        severity=Severity.HIGH,
        resource_type="terraform",
        resource_name="test_bucket",
        file_path="main.tf",
        line_number=5,
        description="S3 bucket does not have encryption enabled",
        remediation="Add server_side_encryption_configuration block",
    )


def test_build_prompt(generator, sample_finding):
    """Test that the prompt is well-formed."""
    prompt = generator._build_prompt(sample_finding, 'resource "aws_s3_bucket" "test" {}')
    assert "SHLD-S3-001" in prompt
    assert "HIGH" in prompt
    assert "aws_s3_bucket" in prompt
    assert "encryption" in prompt.lower()


def test_extract_context(generator):
    """Test code context extraction."""
    content = "\n".join([f"line {i}" for i in range(100)])
    context = generator._extract_context(content, 50, 10)
    lines = context.split("\n")
    assert len(lines) <= 10


def test_cache_key_deterministic(generator, sample_finding):
    """Cache keys should be deterministic."""
    key1 = generator._cache_key(sample_finding, "content1")
    key2 = generator._cache_key(sample_finding, "content1")
    assert key1 == key2


def test_cache_key_varies_with_content(generator, sample_finding):
    """Different content should produce different cache keys."""
    key1 = generator._cache_key(sample_finding, "content1")
    key2 = generator._cache_key(sample_finding, "content2")
    assert key1 != key2


@pytest.mark.asyncio
async def test_generate_fix_without_api_key(generator, sample_finding):
    """Without an API key, should return None."""
    with patch("backend.services.ai_fix_generator.settings") as mock_settings:
        mock_settings.openai_api_key = None
        mock_settings.ai_fix_enabled = True
        result = await generator.generate_fix(sample_finding, "test content")
        assert result is None
