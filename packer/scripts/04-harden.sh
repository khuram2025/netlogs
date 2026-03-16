#!/bin/bash
# =============================================================================
# 04-harden.sh — OS hardening for the Zentryc appliance
#
# Locks down root, hardens SSH, configures GRUB, sets up logging.
# =============================================================================
set -euo pipefail

echo "==> 04-harden: Hardening OS..."

# ── Lock root account ───────────────────────────────────────────────
echo "  Locking root account..."
passwd -l root

# ── SSH hardening ───────────────────────────────────────────────────
echo "  Hardening SSH..."
SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

# Apply hardening settings
cat > /etc/ssh/sshd_config.d/99-zentryc-hardening.conf <<'EOF'
# Zentryc Appliance SSH Hardening
PermitRootLogin no
AllowUsers zentryc maint
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
Banner /etc/issue.net
EOF

# Create maint user for emergency bash access (SSH key only)
echo "  Creating maint user..."
if ! id maint &>/dev/null; then
    useradd --create-home --shell /bin/bash maint
    mkdir -p /home/maint/.ssh
    chmod 700 /home/maint/.ssh
    touch /home/maint/.ssh/authorized_keys
    chmod 600 /home/maint/.ssh/authorized_keys
    chown -R maint:maint /home/maint/.ssh
fi

# Disable password auth for maint (key-only)
cat >> /etc/ssh/sshd_config.d/99-zentryc-hardening.conf <<'EOF'

Match User maint
    PasswordAuthentication no
    PubkeyAuthentication yes
    AllowTcpForwarding no
    X11Forwarding no
EOF

# ── GRUB configuration ──────────────────────────────────────────────
echo "  Configuring GRUB..."
if [[ -f /etc/default/grub ]]; then
    sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub
    sed -i 's/^GRUB_DISTRIBUTOR=.*/GRUB_DISTRIBUTOR="Zentryc Appliance"/' /etc/default/grub
    # Remove splash/quiet for clean console
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
    update-grub 2>/dev/null || true
fi

# ── Journald — persistent with limits ──────────────────────────────
echo "  Configuring journald..."
mkdir -p /var/log/journal
cat > /etc/systemd/journald.conf.d/zentryc.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=30day
Compress=yes
EOF

systemctl restart systemd-journald 2>/dev/null || true

# ── Unattended security updates ────────────────────────────────────
echo "  Enabling unattended security updates..."
apt-get install -y -qq unattended-upgrades > /dev/null 2>&1

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# ── Firewall ────────────────────────────────────────────────────────
echo "  Configuring firewall..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow 22/tcp comment "SSH" > /dev/null 2>&1
ufw allow 80/tcp comment "HTTP" > /dev/null 2>&1
ufw allow 443/tcp comment "HTTPS" > /dev/null 2>&1
ufw allow 514/udp comment "Syslog" > /dev/null 2>&1
ufw --force enable > /dev/null 2>&1

echo "==> 04-harden: Done."
