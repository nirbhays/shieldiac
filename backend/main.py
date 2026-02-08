"""
ShieldIaC — FastAPI Application Entry Point

This is the main application module.  It creates the FastAPI app,
registers all routers, configures middleware, and loads security rules
on startup.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.rules.loader import load_rules

# ── API Routers ──────────────────────────────────────────────────────────
from backend.api.health import router as health_router
from backend.api.webhooks import router as webhooks_router
from backend.api.scans import router as scans_router
from backend.api.dashboard import router as dashboard_router
from backend.api.reports import router as reports_router
from backend.api.rules import router as rules_router
from backend.api.billing import router as billing_router

settings = get_settings()

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    logger.info("Starting ShieldIaC %s (%s)", settings.app_version, settings.environment.value)

    # Load all security rules
    reg = load_rules()
    logger.info("Loaded %d security rules: %s", reg.count, reg.summary())

    yield

    logger.info("Shutting down ShieldIaC")


# ── App Factory ──────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ShieldIaC",
        description=(
            "Infrastructure-as-Code Security Scanner API. "
            "Scans Terraform, Kubernetes, Dockerfiles, and CloudFormation "
            "against 200+ security rules with AI-powered fix suggestions."
        ),
        version=settings.app_version,
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan,
    )

    # ── CORS ─────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────────────────
    prefix = settings.api_prefix
    app.include_router(health_router)
    app.include_router(webhooks_router, prefix=prefix)
    app.include_router(scans_router, prefix=prefix)
    app.include_router(dashboard_router, prefix=prefix)
    app.include_router(reports_router, prefix=prefix)
    app.include_router(rules_router, prefix=prefix)
    app.include_router(billing_router, prefix=prefix)

    return app


# ── Application instance ─────────────────────────────────────────────────
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.is_development,
        log_level=settings.log_level.lower(),
    )
