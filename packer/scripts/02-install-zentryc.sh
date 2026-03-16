#!/bin/bash
# =============================================================================
# 02-install-zentryc.sh — Install Zentryc from compiled tarball
#
# Expects the compiled tarball at /tmp/zentryc-compiled.tar.gz
# Runs the bare-metal installer in --appliance mode.
# =============================================================================
set -euo pipefail

echo "==> 02-install-zentryc: Installing Zentryc..."

TARBALL="/tmp/zentryc-compiled.tar.gz"
INSTALL_DIR="/opt/zentryc"

if [[ ! -f "$TARBALL" ]]; then
    echo "ERROR: Compiled tarball not found at $TARBALL"
    exit 1
fi

# Extract tarball
echo "  Extracting tarball..."
mkdir -p "$INSTALL_DIR"
tar -xzf "$TARBALL" -C "$INSTALL_DIR" --strip-components=1

# Run the bare-metal installer in appliance mode
echo "  Running installer in appliance mode..."
if [[ -f "$INSTALL_DIR/deploy/bare-metal/install.sh" ]]; then
    chmod +x "$INSTALL_DIR/deploy/bare-metal/install.sh"
    cd "$INSTALL_DIR"
    bash deploy/bare-metal/install.sh --appliance
else
    echo "ERROR: install.sh not found in tarball"
    exit 1
fi

# Clean up tarball
rm -f "$TARBALL"

echo "==> 02-install-zentryc: Done."
