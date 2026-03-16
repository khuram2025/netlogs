#!/bin/bash
# =============================================================================
# 03-configure-cli.sh — Configure appliance CLI shell and auto-login
#
# Sets up the zentryc CLI as the login shell, auto-login on tty1,
# and MOTD branding.
# =============================================================================
set -euo pipefail

echo "==> 03-configure-cli: Configuring CLI shell..."

INSTALL_DIR="/opt/zentryc"
VENV_DIR="$INSTALL_DIR/venv"
CLI_SHELL="$VENV_DIR/bin/zentryc-cli"

# Ensure CLI shell exists
if [[ ! -f "$CLI_SHELL" ]]; then
    echo "  WARNING: CLI shell not found at $CLI_SHELL"
    echo "  Creating wrapper..."
    cat > "$CLI_SHELL" <<'EOF'
#!/bin/bash
exec /opt/zentryc/venv/bin/python -m fastapi_app.cli.shell.main
EOF
    chmod 755 "$CLI_SHELL"
fi

# Ensure zentryc user exists with CLI as login shell
if ! id zentryc &>/dev/null; then
    useradd --system --shell "$CLI_SHELL" --home-dir "$INSTALL_DIR" zentryc
else
    chsh -s "$CLI_SHELL" zentryc 2>/dev/null || usermod -s "$CLI_SHELL" zentryc
fi

# Add CLI shell to /etc/shells
if ! grep -q "zentryc-cli" /etc/shells; then
    echo "$CLI_SHELL" >> /etc/shells
fi

# Auto-login on tty1 via getty override
echo "  Configuring auto-login on tty1..."
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin zentryc --noclear %I \$TERM
Type=idle
EOF

# Install MOTD
echo "  Installing MOTD..."
# Disable default MOTD scripts
chmod -x /etc/update-motd.d/* 2>/dev/null || true

if [[ -f /tmp/packer-files/motd ]]; then
    cp /tmp/packer-files/motd /etc/update-motd.d/99-zentryc
    chmod 755 /etc/update-motd.d/99-zentryc
fi

# Install console banner
if [[ -f /tmp/packer-files/issue ]]; then
    cp /tmp/packer-files/issue /etc/issue
    cp /tmp/packer-files/issue /etc/issue.net
fi

# Install logrotate config
if [[ -f /tmp/packer-files/zentryc-logrotate.conf ]]; then
    cp /tmp/packer-files/zentryc-logrotate.conf /etc/logrotate.d/zentryc
fi

echo "==> 03-configure-cli: Done."
