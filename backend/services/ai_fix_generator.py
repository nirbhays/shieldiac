"""
ShieldIaC — AI-Powered Fix Suggestion Generator

Uses OpenAI GPT-4.1-mini to generate context-aware fix suggestions
for detected security findings.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Dict, Optional

from backend.config import get_settings
from backend.rules.base import Finding

logger = logging.getLogger(__name__)
settings = get_settings()

# ── In-memory cache (Redis-backed in production) ────────────────────────
_fix_cache: Dict[str, str] = {}

SYSTEM_PROMPT = """You are ShieldIaC, an expert Infrastructure-as-Code security engineer.
Your job is to generate precise, production-ready code fixes for IaC security findings.

Rules:
1. Output ONLY the corrected code snippet — no explanations, no markdown fences.
2. Preserve the original code style (indentation, naming, comments).
3. Fix ONLY the specific security issue described — do not refactor unrelated code.
4. If multiple approaches exist, choose the most secure AND least disruptive option.
5. For Terraform: use latest provider syntax (AWS provider v5+).
6. For Kubernetes: follow Pod Security Standards (restricted profile).
7. For Dockerfiles: follow CIS Docker Benchmark recommendations.
8. Never introduce new security issues in the fix.
"""

FEW_SHOT_EXAMPLES = [
    {
        "role": "user",
        "content": (
            "Finding: S3 bucket does not have server-side encryption enabled\n"
            "Rule ID: SHLD-S3-001\n"
            "Severity: HIGH\n"
            "File: main.tf\n\n"
            "Original code:\n"
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "my-data-bucket"\n'
            '  acl    = "private"\n'
            "}\n"
        ),
    },
    {
        "role": "assistant",
        "content": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "my-data-bucket"\n'
            '  acl    = "private"\n'
            "}\n\n"
            'resource "aws_s3_bucket_server_side_encryption_configuration" "data" {\n'
            '  bucket = aws_s3_bucket.data.id\n\n'
            "  rule {\n"
            "    apply_server_side_encryption_by_default {\n"
            '      sse_algorithm = "aws:kms"\n'
            "    }\n"
            "    bucket_key_enabled = true\n"
            "  }\n"
            "}\n"
        ),
    },
    {
        "role": "user",
        "content": (
            "Finding: Container runs as root (UID 0)\n"
            "Rule ID: SHLD-K8S-POD-002\n"
            "Severity: HIGH\n"
            "File: deployment.yaml\n\n"
            "Original code:\n"
            "containers:\n"
            "  - name: app\n"
            "    image: myapp:1.0\n"
            "    ports:\n"
            "      - containerPort: 8080\n"
        ),
    },
    {
        "role": "assistant",
        "content": (
            "containers:\n"
            "  - name: app\n"
            "    image: myapp:1.0\n"
            "    ports:\n"
            "      - containerPort: 8080\n"
            "    securityContext:\n"
            "      runAsNonRoot: true\n"
            "      runAsUser: 1000\n"
            "      runAsGroup: 1000\n"
            "      allowPrivilegeEscalation: false\n"
            "      readOnlyRootFilesystem: true\n"
            "      capabilities:\n"
            "        drop:\n"
            "          - ALL\n"
        ),
    },
    {
        "role": "user",
        "content": (
            "Finding: Dockerfile does not contain a USER instruction\n"
            "Rule ID: SHLD-DOCKER-001\n"
            "Severity: HIGH\n"
            "File: Dockerfile\n\n"
            "Original code:\n"
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install -r requirements.txt\n"
            'CMD ["python", "main.py"]\n'
        ),
    },
    {
        "role": "assistant",
        "content": (
            "FROM python:3.11-slim\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            "RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\n"
            "USER appuser\n"
            'CMD ["python", "main.py"]\n'
        ),
    },
]


class AIFixGenerator:
    """Generates AI-powered fix suggestions using OpenAI."""

    def __init__(self):
        self._client = None

    async def _get_client(self):
        """Lazy-init the OpenAI async client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(api_key=settings.openai_api_key)
            except ImportError:
                logger.warning("openai package not installed — AI fixes disabled")
                return None
        return self._client

    async def generate_fix(
        self,
        finding: Finding,
        file_content: str,
        max_context_lines: int = 40,
    ) -> Optional[str]:
        """Generate an AI fix suggestion for a finding.

        Returns the fix as a string, or None if generation fails.
        """
        if not settings.openai_api_key or not settings.ai_fix_enabled:
            return None

        # Check cache
        cache_key = self._cache_key(finding, file_content)
        if cache_key in _fix_cache:
            return _fix_cache[cache_key]

        # Extract relevant code context
        code_context = self._extract_context(file_content, finding.line_number, max_context_lines)

        # Build the user prompt
        user_prompt = self._build_prompt(finding, code_context)

        try:
            client = await self._get_client()
            if client is None:
                return None

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                *FEW_SHOT_EXAMPLES,
                {"role": "user", "content": user_prompt},
            ]

            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=messages,
                max_tokens=settings.openai_max_tokens,
                temperature=settings.openai_temperature,
            )

            fix = response.choices[0].message.content.strip()

            # Validate the fix isn't empty or just a repeat of the original
            if fix and len(fix) > 10 and fix != code_context:
                _fix_cache[cache_key] = fix
                return fix

            return None

        except Exception:
            logger.exception("AI fix generation failed for %s", finding.rule_id)
            return None

    def _build_prompt(self, finding: Finding, code_context: str) -> str:
        """Build the user prompt for the AI model."""
        return (
            f"Finding: {finding.description}\n"
            f"Rule ID: {finding.rule_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Resource: {finding.resource_name}\n"
            f"File: {finding.file_path}\n"
            f"Remediation guidance: {finding.remediation}\n\n"
            f"Original code:\n{code_context}\n"
        )

    def _extract_context(self, content: str, line_number: int, max_lines: int) -> str:
        """Extract code context around the finding line."""
        lines = content.split("\n")
        if not lines:
            return content

        # Center the context window around the finding
        half = max_lines // 2
        start = max(0, line_number - half - 1)
        end = min(len(lines), line_number + half)
        return "\n".join(lines[start:end])

    @staticmethod
    def _cache_key(finding: Finding, content: str) -> str:
        """Generate a deterministic cache key."""
        raw = f"{finding.rule_id}|{finding.file_path}|{finding.resource_name}|{hashlib.md5(content.encode()).hexdigest()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
