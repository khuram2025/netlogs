#!/bin/bash
# =============================================================================
# 05-cleanup.sh — Final cleanup before image export
#
# Removes build artifacts, clears logs, zeros disk for compression.
# =============================================================================
set -euo pipefail

echo "==> 05-cleanup: Cleaning up for image export..."

# ── Remove packer build user ───────────────────────────────────────
echo "  Removing packer build user..."
userdel -rf packer 2>/dev/null || true
rm -f /etc/sudoers.d/packer

# ── Remove .configured marker (wizard should run on first boot) ────
echo "  Removing .configured marker..."
rm -f /opt/zentryc/.configured

# ── Remove .env (wizard will generate it) ──────────────────────────
echo "  Removing .env..."
rm -f /opt/zentryc/.env

# ── Clear logs ─────────────────────────────────────────────────────
echo "  Clearing logs..."
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.gz" -delete
find /opt/zentryc/logs -type f -delete 2>/dev/null || true
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

# ── Remove SSH host keys (regenerated on first boot) ──────────────
echo "  Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*
# Ensure keys are regenerated on boot
systemctl enable ssh 2>/dev/null || true

# ── Clear temporary files ──────────────────────────────────────────
echo "  Clearing temporary files..."
rm -rf /tmp/*
rm -rf /var/tmp/*
rm -rf /root/.cache
rm -rf /home/*/.cache
rm -rf /var/cache/apt/archives/*.deb
apt-get clean

# ── Clear shell history ───────────────────────────────────────────
echo "  Clearing shell history..."
rm -f /root/.bash_history
rm -f /home/*/.bash_history
rm -f /home/*/.zentryc_cli_history

# ── Clear machine-id (regenerated on first boot) ──────────────────
echo "  Clearing machine-id..."
truncate -s 0 /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true

# ── Zero free disk space for better compression ───────────────────
echo "  Zeroing free disk space (this may take a moment)..."
dd if=/dev/zero of=/EMPTY bs=1M 2>/dev/null || true
rm -f /EMPTY
sync

echo "==> 05-cleanup: Done."
