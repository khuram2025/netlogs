#!/bin/bash
# =============================================================================
# 01-base-setup.sh — Base system setup for Zentryc appliance VM
#
# Removes unnecessary packages, upgrades system, installs base deps.
# =============================================================================
set -euo pipefail

echo "==> 01-base-setup: Configuring base system..."

export DEBIAN_FRONTEND=noninteractive

# Wait for cloud-init to complete
cloud-init status --wait || true

# Remove snap (saves ~500MB)
if command -v snap &>/dev/null; then
    echo "  Removing snap..."
    snap list 2>/dev/null | awk 'NR>1 {print $1}' | while read pkg; do
        snap remove --purge "$pkg" 2>/dev/null || true
    done
    apt-get purge -y snapd 2>/dev/null || true
    rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd
    echo "  Snap removed."
fi

# Remove cloud-init (not needed after initial setup)
echo "  Removing cloud-init..."
apt-get purge -y cloud-init cloud-guest-utils 2>/dev/null || true
rm -rf /etc/cloud /var/lib/cloud
echo "  Cloud-init removed."

# Full system upgrade
echo "  Upgrading system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get dist-upgrade -y -qq
apt-get autoremove -y -qq

# Install base packages
echo "  Installing base packages..."
apt-get install -y -qq \
    python3 python3-venv python3-dev python3-pip \
    build-essential libpq-dev libffi-dev \
    nginx \
    ufw \
    openssl \
    curl wget gnupg lsb-release \
    rsync \
    net-tools \
    > /dev/null 2>&1

echo "==> 01-base-setup: Done."
