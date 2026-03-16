#!/bin/bash
# =============================================================================
# Zentryc Release Build Script
#
# Master script: compile → packer build → package → checksum → release notes
#
# Usage:
#   ./build/release.sh                     # Full build (compile + VM image)
#   ./build/release.sh --skip-vm           # Skip Packer VM build (tarball only)
#   ./build/release.sh --skip-compile      # Skip Cython (use existing tarball)
#
# Prerequisites:
#   - Python 3.12 with venv
#   - Cython 3.0+ (pip install cython)
#   - Packer 1.9+ (optional, for VM build)
#   - qemu-img (optional, for OVA conversion)
#   - KVM support (optional, for VM build)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKER_DIR="$REPO_DIR/packer"

# Parse arguments
SKIP_VM=false
SKIP_COMPILE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-vm)      SKIP_VM=true; shift ;;
        --skip-compile) SKIP_COMPILE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--skip-vm] [--skip-compile]"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# Read version
VERSION=$(grep '__version__' "$REPO_DIR/fastapi_app/__version__.py" | cut -d'"' -f2)
if [[ -z "$VERSION" ]]; then
    echo "ERROR: Cannot read version from __version__.py"
    exit 1
fi

RELEASE_DIR="$REPO_DIR/release/zentryc-${VERSION}"
TARBALL="$SCRIPT_DIR/output/zentryc-${VERSION}-compiled.tar.gz"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║         Zentryc Release Build v${VERSION}                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Cython compilation ───────────────────────────────────
if [[ "$SKIP_COMPILE" == false ]]; then
    echo "═══ Step 1: Compiling source code ═══"
    bash "$SCRIPT_DIR/build_appliance.sh"
    echo ""
else
    echo "═══ Step 1: Skipping compilation (--skip-compile) ═══"
    if [[ ! -f "$TARBALL" ]]; then
        echo "ERROR: Compiled tarball not found: $TARBALL"
        echo "Run without --skip-compile first."
        exit 1
    fi
fi

# ─── Step 2: Packer VM build ──────────────────────────────────────
if [[ "$SKIP_VM" == false ]]; then
    echo "═══ Step 2: Building VM image with Packer ═══"

    # Check prerequisites
    if ! command -v packer &>/dev/null; then
        echo "WARNING: Packer not found. Skipping VM build."
        echo "Install from: https://www.packer.io/downloads"
        SKIP_VM=true
    elif ! command -v qemu-img &>/dev/null; then
        echo "WARNING: qemu-img not found. Skipping VM build."
        echo "Install: apt install qemu-utils"
        SKIP_VM=true
    fi
fi

if [[ "$SKIP_VM" == false ]]; then
    cd "$PACKER_DIR"

    # Initialize Packer plugins
    packer init .

    # Run Packer build
    packer build \
        -var "version=${VERSION}" \
        -var "compiled_tarball=${TARBALL}" \
        -var "output_dir=${PACKER_DIR}/output" \
        .

    echo "VM images built."
    echo ""
else
    echo "═══ Step 2: Skipping VM build ═══"
    echo ""
fi

# ─── Step 3: Assemble release artifacts ───────────────────────────
echo "═══ Step 3: Assembling release artifacts ═══"

mkdir -p "$RELEASE_DIR"

# Copy compiled tarball
cp "$TARBALL" "$RELEASE_DIR/"
echo "  Copied: zentryc-${VERSION}-compiled.tar.gz"

# Copy VM images if they exist
if [[ -f "$PACKER_DIR/output/release/zentryc-${VERSION}.ova" ]]; then
    cp "$PACKER_DIR/output/release/zentryc-${VERSION}.ova" "$RELEASE_DIR/"
    echo "  Copied: zentryc-${VERSION}.ova"
fi

if [[ -f "$PACKER_DIR/output/release/zentryc-${VERSION}.qcow2" ]]; then
    cp "$PACKER_DIR/output/release/zentryc-${VERSION}.qcow2" "$RELEASE_DIR/"
    echo "  Copied: zentryc-${VERSION}.qcow2"
fi

# ─── Step 4: Generate checksums ───────────────────────────────────
echo "═══ Step 4: Generating checksums ═══"

cd "$RELEASE_DIR"
sha256sum *.tar.gz *.ova *.qcow2 2>/dev/null > SHA256SUMS || true
echo "  SHA256SUMS generated"

# ─── Step 5: Generate release notes ──────────────────────────────
echo "═══ Step 5: Generating release notes ═══"

cat > "$RELEASE_DIR/RELEASE_NOTES.md" <<EOF
# Zentryc ${VERSION} — Release Notes

## Artifacts

| File | Description |
|------|-------------|
| \`zentryc-${VERSION}.ova\` | VMware / VirtualBox appliance image |
| \`zentryc-${VERSION}.qcow2\` | Proxmox / KVM appliance image |
| \`zentryc-${VERSION}-compiled.tar.gz\` | Bare-metal offline install package |
| \`SHA256SUMS\` | File integrity checksums |

## Quick Start

### Virtual Appliance (OVA)
1. Import \`zentryc-${VERSION}.ova\` into VMware ESXi, Workstation, or VirtualBox
2. Boot the VM — the first-boot wizard will run automatically on console
3. Configure: network, hostname, timezone, admin password
4. Access: \`https://<IP>/\`

### Virtual Appliance (QCOW2)
1. Upload \`zentryc-${VERSION}.qcow2\` to Proxmox or create a KVM VM
2. Boot → first-boot wizard → configure → access web UI

### Bare-Metal Install
\`\`\`bash
tar xzf zentryc-${VERSION}-compiled.tar.gz
cd zentryc-${VERSION}
sudo bash deploy/bare-metal/install.sh
\`\`\`

## Appliance CLI

SSH to the appliance for management:
\`\`\`
ssh zentryc@<IP>
\`\`\`

Key commands:
- \`show system status\` — System overview
- \`show system health\` — Application health
- \`set interface ens18 address 10.0.0.5/24\` — Configure IP
- \`request backup now\` — Create backup
- \`request system reboot\` — Reboot appliance

## Verify Integrity
\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`
EOF

echo "  RELEASE_NOTES.md generated"

# ─── Summary ──────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              Release Build Complete!                     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Version: ${VERSION}                                         ║"
echo "║  Output:  release/zentryc-${VERSION}/                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Artifacts:"
ls -lh "$RELEASE_DIR/" | tail -n +2
echo ""
