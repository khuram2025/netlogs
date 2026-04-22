#!/usr/bin/env bash
# Installs the ZenAI updater agent onto this appliance.
# Idempotent. Does NOT touch the existing Zentryc DB or code.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_HOME=/opt/zenai/updater
STATE_VAR=/var/lib/zenai/updater
USER_NAME=zenai-updater
PUBKEY_SRC="${ZENAI_PUBKEY:-/home/net/Doc/ZENAI/zentryc-zenai.pub}"
# Web user that runs the FastAPI app. The /system/updates/ tab needs
# to read state.json and invoke the agent, so this user is added to
# the zenai-updater group and granted a narrow sudoers rule.
WEB_USER="${ZENAI_WEB_USER:-net}"

if [[ $EUID -ne 0 ]]; then
    echo "run as root (sudo)." >&2; exit 1
fi

# 1. User
if ! id "$USER_NAME" &>/dev/null; then
    useradd --system --home "$AGENT_HOME" --shell /usr/sbin/nologin "$USER_NAME"
fi

# 2. Layout
# Group-traversable dirs (mode 0750) so the FastAPI web user — added
# to the zenai-updater group below — can read state.json and the log
# for the /system/updates page. Keys dir stays 0700: private-key
# material must not be readable by the web.
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$AGENT_HOME" "$AGENT_HOME/logs"
install -d -o "$USER_NAME" -g "$USER_NAME" -m 0700 "$AGENT_HOME/keys"
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

# 6. Sudoers: agent needs to stop/start app services, install OS
#    packages, and unpack release archives. Keeping the list narrow —
#    nothing else on the system should be granted through this rule.
cat > /etc/sudoers.d/zenai-updater <<EOF
# Installed by deploy/updater/install-updater.sh. Do not edit by hand.
$USER_NAME ALL=(root) NOPASSWD: /bin/systemctl
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/systemctl
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/rsync
$USER_NAME ALL=(root) NOPASSWD: /bin/tar
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/tar
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/apt-get
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/apt
$USER_NAME ALL=(root) NOPASSWD: /usr/bin/dpkg
EOF
chmod 0440 /etc/sudoers.d/zenai-updater
visudo -cf /etc/sudoers.d/zenai-updater

# 7. Let the FastAPI web user drive the agent for the /system/updates
#    tab — so an admin can "Install update" from the browser. The chain
#    is: web ($WEB_USER) --sudo--> $USER_NAME --sudo--> root (for the
#    narrow list above). Without this the UI can only show status.
if id "$WEB_USER" &>/dev/null; then
    usermod -a -G "$USER_NAME" "$WEB_USER"
    cat > /etc/sudoers.d/netlogs-web-updater <<EOF
# Installed by deploy/updater/install-updater.sh. Do not edit by hand.
# Lets the FastAPI web ($WEB_USER) trigger the ZenAI updater agent for
# the /system/updates page.
$WEB_USER ALL=($USER_NAME) NOPASSWD: $AGENT_HOME/agent
EOF
    chmod 0440 /etc/sudoers.d/netlogs-web-updater
    visudo -cf /etc/sudoers.d/netlogs-web-updater
    echo "granted $WEB_USER → sudo -u $USER_NAME $AGENT_HOME/agent"
else
    echo "WARN: web user '$WEB_USER' does not exist on this host — skipped web-updater sudoers." >&2
    echo "      Set ZENAI_WEB_USER=<your-fastapi-user> and re-run, or add the rule by hand." >&2
fi

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
echo ""
echo "Note: if the FastAPI web service was already running, restart it"
echo "so it picks up the zenai-updater group membership:"
echo "       sudo systemctl restart netlogs-web"
