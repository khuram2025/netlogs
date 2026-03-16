#!/bin/bash
# =============================================================================
# Zentryc Appliance Build Script
#
# Stages source, compiles .py → .so via Cython, cleans sources, packages.
#
# Usage:
#   ./build/build_appliance.sh
#
# Output:
#   output/zentryc-VERSION-compiled.tar.gz
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$SCRIPT_DIR/staging"
OUTPUT_DIR="$SCRIPT_DIR/output"

# Read version
VERSION=$(grep '__version__' "$REPO_DIR/fastapi_app/__version__.py" | cut -d'"' -f2)
if [[ -z "$VERSION" ]]; then
    echo "ERROR: Cannot read version from __version__.py"
    exit 1
fi

echo "=========================================="
echo "  Zentryc Appliance Build v${VERSION}"
echo "=========================================="
echo ""

# ─── Step 1: Clean previous build ─────────────────────────────────
echo "==> Step 1: Cleaning previous build..."
rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# ─── Step 2: Stage source code ────────────────────────────────────
echo "==> Step 2: Staging source code..."
rsync -a \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='logs/*.log*' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='build/staging' \
    --exclude='build/output' \
    --exclude='*.egg-info' \
    "$REPO_DIR/" "$BUILD_DIR/"

echo "  Staged to: $BUILD_DIR"

# ─── Step 3: Install build dependencies ───────────────────────────
echo "==> Step 3: Installing build dependencies..."

# Use system python or venv
PYTHON="${PYTHON:-python3}"
if [[ -d "$REPO_DIR/venv" ]]; then
    PYTHON="$REPO_DIR/venv/bin/python"
fi

$PYTHON -m pip install -q -r "$SCRIPT_DIR/requirements-build.txt"

# ─── Step 4: Cython compilation ───────────────────────────────────
echo "==> Step 4: Compiling Python → shared objects..."

# Copy setup_cython.py into staging (it needs to run from there)
cp "$SCRIPT_DIR/setup_cython.py" "$BUILD_DIR/setup_cython.py"

cd "$BUILD_DIR"
$PYTHON setup_cython.py build_ext --inplace 2>&1 | tail -20

# Count compiled modules
SO_COUNT=$(find . -name "*.so" -path "*/fastapi_app/*" | wc -l)
echo "  Compiled $SO_COUNT modules to .so"

if [[ "$SO_COUNT" -eq 0 ]]; then
    echo "ERROR: No .so files produced — compilation failed!"
    exit 1
fi

# ─── Step 5: Clean source files ───────────────────────────────────
echo "==> Step 5: Cleaning source files..."
cp "$SCRIPT_DIR/cleanup_sources.py" "$BUILD_DIR/cleanup_sources.py"
$PYTHON cleanup_sources.py

# ─── Step 6: Clean build artifacts ────────────────────────────────
echo "==> Step 6: Cleaning build artifacts..."
rm -rf "$BUILD_DIR/build/"
rm -rf "$BUILD_DIR"/*.egg-info
rm -f "$BUILD_DIR/setup_cython.py"
rm -f "$BUILD_DIR/cleanup_sources.py"
find "$BUILD_DIR" -name "*.c" -path "*/fastapi_app/*" -delete
find "$BUILD_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# ─── Step 7: Package ──────────────────────────────────────────────
echo "==> Step 7: Packaging..."

TARBALL="$OUTPUT_DIR/zentryc-${VERSION}-compiled.tar.gz"
cd "$BUILD_DIR"
tar -czf "$TARBALL" \
    --transform="s,^\.,zentryc-${VERSION}," \
    .

TARBALL_SIZE=$(du -h "$TARBALL" | cut -f1)
echo ""
echo "=========================================="
echo "  Build Complete!"
echo "=========================================="
echo "  Version:  ${VERSION}"
echo "  Output:   ${TARBALL}"
echo "  Size:     ${TARBALL_SIZE}"
echo "  Modules:  ${SO_COUNT} compiled .so files"
echo "=========================================="

# ─── Cleanup staging ──────────────────────────────────────────────
echo ""
echo "==> Cleaning staging directory..."
rm -rf "$BUILD_DIR"
echo "Done."
