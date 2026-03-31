# =============================================================================
# Zentryc SOAR/SIEM Platform - Docker Image
# Multi-stage build: Node.js frontend + Python backend
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Frontend - build CSS/JS assets with Vite
# ---------------------------------------------------------------------------
FROM node:20-alpine AS frontend

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

COPY fastapi_app/requirements.txt .

# Pin bcrypt for passlib compatibility
RUN pip install --no-cache-dir wheel && \
    pip wheel --no-cache-dir --wheel-dir /build/wheels \
    -r requirements.txt \
    bcrypt==4.0.1

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
RUN pip install --no-cache-dir /tmp/wheels/*.whl && \
    rm -rf /tmp/wheels

# Copy application code
COPY fastapi_app/ ./fastapi_app/

# Copy built frontend assets from Stage 1
COPY --from=frontend /build/fastapi_app/static/dist/ ./fastapi_app/static/dist/

COPY run_fastapi.py run_syslog.py ./

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
