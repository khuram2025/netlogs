#!/usr/bin/env bash
# Installs the ZenAI updater agent onto this appliance.
# Idempotent. Does NOT touch the existing Zentryc DB or code.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_HOME=/opt/zenai/updater
STATE_VAR=/var/lib/zenai/updater
USER_NAME=zenai-updater
PUBKEY_SRC="${ZENAI_PUBKEY:-/home/net/Doc/ZENAI/zentryc-zenai.pub}"

if [[ $EUID -ne 0 ]]; then
    echo "run as root (sudo)." >&2; exit 1
fi

# 1. User
if ! id "$USER_NAME" &>/dev/null; then
    useradd --system --home "$AGENT_HOME" --shell /usr/sbin/nologin "$USER_NAME"
fi

# 2. Layout
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$AGENT_HOME" "$AGENT_HOME/keys" "$AGENT_HOME/logs"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$STATE_VAR" "$STATE_VAR/staging" "$STATE_VAR/backups"

# 3. Agent binary + public key
install -o "$USER_NAME" -g "$USER_NAME" -m 0755 "$SRC_DIR/zenai-updater.py" "$AGENT_HOME/agent"
if [[ -f "$PUBKEY_SRC" ]]; then
    install -o "$USER_NAME" -g "$USER_NAME" -m 0644 "$PUBKEY_SRC" "$AGENT_HOME/keys/zentryc-zenai.pub"
else
    echo "WARN: public key not found at $PUBKEY_SRC — install it manually before starting the service." >&2
fi

# 4. Systemd unit
install -m 0644 "$SRC_DIR/zenai-updater.service" /etc/systemd/system/zenai-updater.service

# 5. Optional env file
[[ -f /etc/zenai-updater.env ]] || cat > /etc/zenai-updater.env <<'EOF'
# /etc/zenai-updater.env
# Set once, then: sudo systemctl restart zenai-updater
# ZENAI_REG_TOKEN=REPLACE_WITH_48_CHAR_HEX_FROM_OTA_ADMIN
# ZENTRYC_API=https://zentryc.com/api/v1
# ZENAI_CHECK_INTERVAL=900
EOF
chmod 0640 /etc/zenai-updater.env
chown root:"$USER_NAME" /etc/zenai-updater.env

# 6. Sudoers: agent needs to stop/start the app services and run rsync to /home/net/net-logs
cat > /etc/sudoers.d/zenai-updater <<EOF
$USER_NAME ALL=(root) NOPASSWD: /bin/systemctl
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/rsync
$USER_NAME ALL=(root) NOPASSWD: /bin/tar
EOF
chmod 0440 /etc/sudoers.d/zenai-updater
visudo -cf /etc/sudoers.d/zenai-updater

systemctl daemon-reload
echo ""
echo "zenai-updater installed."
echo "  1. Put your registration token into /etc/zenai-updater.env:"
echo "       ZENAI_REG_TOKEN=<48-char-hex>"
echo "  2. Start the service:"
echo "       sudo systemctl enable --now zenai-updater"
echo "  3. Confirm:"
echo "       sudo systemctl status zenai-updater"
echo "       sudo -u $USER_NAME /opt/zenai/updater/agent status"
