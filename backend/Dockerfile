# =============================================================================
# ShieldIaC Backend — Production Docker Image
# =============================================================================
# Multi-stage build for minimal image size.
# Based on python:3.12-slim for security (no unnecessary packages).

# Stage 1: Install dependencies
FROM python:3.12-slim AS builder

LABEL maintainer="ShieldIaC Team" \
      version="1.0.0" \
      description="ShieldIaC Backend — IaC Security Scanner"

WORKDIR /build

# Install system dependencies needed for compiling Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production image
FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd --system shieldiac && \
    useradd --system --gid shieldiac --create-home shieldiac

# Install runtime dependencies only (no compilers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY . .

# Create report storage directory
RUN mkdir -p /tmp/shieldiac/reports && \
    chown -R shieldiac:shieldiac /tmp/shieldiac /app

# Switch to non-root user
USER shieldiac

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
