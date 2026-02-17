#!/bin/sh
set -e

CERT_DIR="/etc/nginx/certs"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

# Auto-generate self-signed certificate if none exists
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "[nginx-entrypoint] No TLS certificate found — generating self-signed cert..."
    mkdir -p "$CERT_DIR"
    apk add --no-cache openssl > /dev/null 2>&1 || true
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/CN=netlogs/O=NetLogs/OU=SIEM" \
        2>/dev/null
    echo "[nginx-entrypoint] Self-signed certificate generated (replace with real cert for production)"
else
    echo "[nginx-entrypoint] TLS certificate found at ${CERT_DIR}"
fi

# Start nginx
exec nginx -g 'daemon off;'
