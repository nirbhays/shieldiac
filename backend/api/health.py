"""
ShieldIaC — Health Check Endpoint
"""
from __future__ import annotations

from fastapi import APIRouter
from backend.config import get_settings
from backend.rules.base import registry

router = APIRouter(tags=["Health"])
settings = get_settings()


@router.get("/health")
async def health_check():
    """Basic health check."""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "environment": settings.environment.value,
    }


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check with dependency status."""
    redis_ok = await _check_redis()
    return {
        "status": "healthy" if redis_ok else "degraded",
        "version": settings.app_version,
        "environment": settings.environment.value,
        "rules_loaded": registry.count,
        "rules_by_type": registry.summary(),
        "dependencies": {
            "redis": "ok" if redis_ok else "unavailable",
            "ai_fixes": "enabled" if settings.ai_fix_enabled and settings.openai_api_key else "disabled",
        },
    }


async def _check_redis() -> bool:
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
        return True
    except Exception:
        return False
