# =============================================================================
# Zentryc SOAR/SIEM Platform - Docker Image
# Multi-stage build: Node.js frontend + Python backend
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Frontend - build CSS/JS assets with Vite
# ---------------------------------------------------------------------------
FROM node:22-alpine AS frontend

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit
COPY vite.config.js ./
COPY static/ ./static/
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: Python Builder - install dependencies and build wheels
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY appliance/requirements.lock requirements.txt

# Pin bcrypt for passlib compatibility
RUN pip download --require-hashes --no-deps --dest /build/wheels -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 3: Runtime - minimal image with only what's needed
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 zentryc && \
    useradd -u 1000 -g zentryc -m -s /bin/bash zentryc

WORKDIR /app

# Install Python packages from wheels
COPY --from=builder /build/wheels /tmp/wheels
RUN pip install --upgrade --no-cache-dir pip==26.2.1 && pip install --no-cache-dir /tmp/wheels/*.whl && \
    rm -rf /tmp/wheels

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/zenshield-browsers
RUN python -m playwright install --with-deps chromium --only-shell && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY fastapi_app/ ./fastapi_app/

# Copy built frontend assets from Stage 1
COPY --from=frontend /build/fastapi_app/static/dist/ ./fastapi_app/static/dist/

COPY run_fastapi.py run_syslog.py zenshield_reset_password.py alembic.ini ./
COPY appliance/dns-agent-release/ /app/dns-agent/
COPY appliance/dns-agent/README.md /app/dns-agent/README.md
ENV ZENSHIELD_APPLIANCE=1

# Copy static files (favicon, etc.)
COPY static/favicon.svg ./static/favicon.svg

# Copy entrypoint
COPY docker/entrypoint.sh /app/docker/entrypoint.sh
RUN chmod +x /app/docker/entrypoint.sh

# Create runtime directories
RUN mkdir -p /app/logs /app/data/credentials && \
    chown -R zentryc:zentryc /app

USER zentryc

EXPOSE 8000
EXPOSE 514/udp

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]

ARG ZENSHIELD_VERSION=0.4.2
ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.title="ZenShield" org.opencontainers.image.version="${ZENSHIELD_VERSION}" org.opencontainers.image.revision="${SOURCE_COMMIT}"
