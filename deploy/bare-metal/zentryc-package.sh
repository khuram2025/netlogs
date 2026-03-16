#!/bin/bash
# =============================================================================
# Zentryc Offline Package Builder
#
# Builds a self-contained tarball for air-gapped installations.
# Run this on a dev machine with internet access.
#
# Usage:
#   ./zentryc-package.sh [output_dir]
#
# Output: zentryc-VERSION-TIMESTAMP.tar.gz
# Install: sudo ./install.sh --offline zentryc-VERSION-TIMESTAMP.tar.gz
# Upgrade: sudo zentryc-upgrade zentryc-VERSION-TIMESTAMP.tar.gz
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${1:-$(pwd)}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# Output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# Validate
if [[ ! -f "$REPO_DIR/fastapi_app/__version__.py" ]]; then
    fail "Cannot find Zentryc source at $REPO_DIR"
fi

if [[ ! -f "$REPO_DIR/fastapi_app/requirements.txt" ]]; then
    fail "Cannot find requirements.txt"
fi

VERSION=$(grep '__version__' "$REPO_DIR/fastapi_app/__version__.py" | cut -d'"' -f2)
PACKAGE_NAME="zentryc-${VERSION}-${TIMESTAMP}"
WORK_DIR=$(mktemp -d)
PKG_DIR="$WORK_DIR/$PACKAGE_NAME"

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

info "Building offline package: $PACKAGE_NAME"
info "Source: $REPO_DIR"
info "Output: $OUTPUT_DIR/"

mkdir -p "$PKG_DIR/app" "$PKG_DIR/wheels"

# =============================================================================
# 1. Copy application code
# =============================================================================
info "Copying application code..."

rsync -a \
    --exclude='.git/' \
    --exclude='venv/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='logs/' \
    --exclude='backups/' \
    --exclude='*.log' \
    --exclude='*.log.*' \
    --exclude='.installed' \
    --exclude='node_modules/' \
    "$REPO_DIR/" "$PKG_DIR/app/"

ok "Application code copied"

# =============================================================================
# 2. Download pip wheels for offline install
# =============================================================================
info "Downloading Python wheels (this may take a few minutes)..."

pip download \
    --dest "$PKG_DIR/wheels" \
    --platform manylinux2014_x86_64 \
    --python-version 3 \
    --only-binary=:all: \
    -r "$REPO_DIR/fastapi_app/requirements.txt" \
    2>/dev/null || true

# Also download source packages for any that don't have binary wheels
pip download \
    --dest "$PKG_DIR/wheels" \
    -r "$REPO_DIR/fastapi_app/requirements.txt" \
    --no-binary=:none: \
    2>/dev/null || true

# Ensure bcrypt 4.0.1 is included
pip download \
    --dest "$PKG_DIR/wheels" \
    "bcrypt==4.0.1" \
    2>/dev/null || true

WHEEL_COUNT=$(find "$PKG_DIR/wheels" -type f | wc -l)
ok "Downloaded $WHEEL_COUNT packages"

# =============================================================================
# 3. Write package metadata
# =============================================================================
cat > "$PKG_DIR/PACKAGE_INFO" <<EOF
{
    "name": "zentryc",
    "version": "$VERSION",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "built_on": "$(hostname)",
    "built_by": "$(whoami)",
    "python_version": "$(python3 --version 2>&1)",
    "platform": "$(uname -s)-$(uname -m)"
}
EOF

ok "Package metadata written"

# =============================================================================
# 4. Create compressed archive
# =============================================================================
info "Creating archive..."

mkdir -p "$OUTPUT_DIR"
tar -czf "$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz" -C "$WORK_DIR" "$PACKAGE_NAME"

ARCHIVE_SIZE=$(du -sh "$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz" | cut -f1)

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Offline Package Built Successfully${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  File:    $OUTPUT_DIR/${PACKAGE_NAME}.tar.gz"
echo "  Size:    $ARCHIVE_SIZE"
echo "  Version: $VERSION"
echo ""
echo "  Fresh install:"
echo "    sudo ./deploy/bare-metal/install.sh --offline ${PACKAGE_NAME}.tar.gz"
echo ""
echo "  Upgrade existing:"
echo "    sudo zentryc-upgrade ${PACKAGE_NAME}.tar.gz"
echo ""
