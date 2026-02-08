"""
ShieldIaC — Configuration Management

Centralizes all environment-variable–driven settings with sensible defaults
for local development.  Uses pydantic-settings for validation and .env support.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application-wide settings loaded from env / .env file."""

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        env_prefix="SHIELDIAC_",
        case_sensitive=False,
    )

    # ── General ──────────────────────────────────────────────────────────
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = True
    app_name: str = "ShieldIaC"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    allowed_origins: list[str] = Field(default=["http://localhost:3000", "https://shieldiac.dev"])
    log_level: str = "INFO"

    # ── Database (PostgreSQL / Supabase) ─────────────────────────────────
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/shieldiac"
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # ── Redis ────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_scan_queue: str = "shieldiac:scans"
    redis_result_ttl: int = 3600  # seconds

    # ── GitHub ───────────────────────────────────────────────────────────
    github_app_id: Optional[str] = None
    github_app_private_key: Optional[str] = None
    github_webhook_secret: str = "change-me-in-production"
    github_api_base: str = "https://api.github.com"

    # ── GitLab ───────────────────────────────────────────────────────────
    gitlab_webhook_secret: str = "change-me-in-production"
    gitlab_api_base: str = "https://gitlab.com/api/v4"

    # ── OpenAI (AI Fix Suggestions) ──────────────────────────────────────
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4.1-mini"
    openai_max_tokens: int = 1024
    openai_temperature: float = 0.2
    ai_fix_enabled: bool = True
    ai_fix_max_findings_per_request: int = 5
    ai_fix_cache_ttl: int = 86400  # 24 hours

    # ── Clerk (Auth) ─────────────────────────────────────────────────────
    clerk_secret_key: Optional[str] = None
    clerk_publishable_key: Optional[str] = None
    clerk_webhook_secret: Optional[str] = None

    # ── Stripe (Billing) ─────────────────────────────────────────────────
    stripe_secret_key: Optional[str] = None
    stripe_publishable_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None
    stripe_price_pro_monthly: Optional[str] = None
    stripe_price_pro_yearly: Optional[str] = None
    stripe_price_enterprise_monthly: Optional[str] = None
    stripe_price_enterprise_yearly: Optional[str] = None

    # ── Scanning Limits ──────────────────────────────────────────────────
    max_file_size_bytes: int = 5_000_000  # 5 MB
    max_files_per_scan: int = 500
    scan_timeout_seconds: int = 300
    max_concurrent_scans: int = 10

    # ── PDF Reports ──────────────────────────────────────────────────────
    report_storage_path: str = "/tmp/shieldiac/reports"
    report_retention_days: int = 90

    # ── Free-tier limits ─────────────────────────────────────────────────
    free_scans_per_month: int = 50
    free_repos: int = 3

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.environment == Environment.DEVELOPMENT


@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings instance (read env once)."""
    return Settings()
