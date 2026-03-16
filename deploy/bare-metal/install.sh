#!/bin/bash
# =============================================================================
# Zentryc SOAR/SIEM Platform — Bare-Metal Production Installer
#
# Installs Zentryc and all dependencies on a fresh Ubuntu 22.04/24.04 server.
#
# Usage:
#   sudo ./install.sh                              # Online install
#   sudo ./install.sh --offline /path/to/pkg.tar.gz # Air-gapped install
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="/opt/zentryc"
VENV_DIR="$INSTALL_DIR/venv"
ENV_FILE="$INSTALL_DIR/.env"
SSL_DIR="/etc/ssl/zentryc"
NGINX_CONF="/etc/nginx/sites-available/zentryc"
SYSCTL_CONF="/etc/sysctl.d/99-zentryc.conf"
INSTALL_MARKER="$INSTALL_DIR/.installed"
ZENTRYC_USER="zentryc"
ZENTRYC_GROUP="zentryc"
MIN_RAM_MB=3072
MIN_DISK_GB=15
OFFLINE_MODE=false
OFFLINE_PACKAGE=""
APPLIANCE_MODE=false

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
STEP=0

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${BLUE}━━━ Step ${STEP}: $* ━━━${NC}"
}

generate_password() {
    python3 -c "import secrets; print(secrets.token_urlsafe(16))"
}

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --offline)
            OFFLINE_MODE=true
            OFFLINE_PACKAGE="${2:-}"
            if [[ -z "$OFFLINE_PACKAGE" ]]; then
                fail "--offline requires a path to the package tarball"
            fi
            if [[ ! -f "$OFFLINE_PACKAGE" ]]; then
                fail "Offline package not found: $OFFLINE_PACKAGE"
            fi
            shift 2
            ;;
        --appliance)
            APPLIANCE_MODE=true
            shift
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--offline /path/to/package.tar.gz] [--appliance]"
            echo ""
            echo "Options:"
            echo "  --offline PATH   Install from offline package (air-gapped)"
            echo "  --appliance      Appliance mode (skip .env/DB setup, enable first-boot wizard)"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            fail "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

# =============================================================================
# Step 1: Pre-flight checks
# =============================================================================
step "Pre-flight checks"

# Must be root
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (use sudo)"
fi

# Check Ubuntu version
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        warn "This script is designed for Ubuntu. Detected: $ID $VERSION_ID"
        warn "Continuing anyway — some steps may fail."
    else
        MAJOR_VER="${VERSION_ID%%.*}"
        if [[ "$MAJOR_VER" -lt 22 ]]; then
            fail "Ubuntu 22.04 or later required. Detected: $VERSION_ID"
        fi
        ok "Ubuntu $VERSION_ID detected"
    fi
else
    warn "Cannot detect OS version, continuing anyway"
fi

# RAM check
TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
if [[ "$TOTAL_RAM_MB" -lt "$MIN_RAM_MB" ]]; then
    warn "System has ${TOTAL_RAM_MB}MB RAM (recommended: ${MIN_RAM_MB}MB+)"
else
    ok "RAM: ${TOTAL_RAM_MB}MB"
fi

# Disk check
AVAIL_DISK_GB=$(df -BG / | awk 'NR==2 {gsub("G",""); print $4}')
if [[ "$AVAIL_DISK_GB" -lt "$MIN_DISK_GB" ]]; then
    warn "Available disk: ${AVAIL_DISK_GB}GB (recommended: ${MIN_DISK_GB}GB+)"
else
    ok "Disk: ${AVAIL_DISK_GB}GB available"
fi

# Port conflict check
for port in 80 443 8000; do
    if ss -tlnp | grep -q ":${port} "; then
        warn "Port $port is already in use"
    fi
done

# Existing install check
if [[ -f "$INSTALL_MARKER" ]]; then
    warn "Zentryc is already installed at $INSTALL_DIR"
    echo ""
    echo "To upgrade, use:  sudo zentryc-upgrade"
    echo "To reinstall, remove $INSTALL_MARKER first."
    echo ""
    read -rp "Continue anyway? This will update the installation. [y/N] " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

ok "Pre-flight checks passed"

# =============================================================================
# Step 2: Install system packages
# =============================================================================
step "Installing system packages"

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq \
    python3 python3-venv python3-dev python3-pip \
    build-essential libpq-dev libffi-dev \
    nginx \
    ufw \
    openssl \
    curl wget gnupg lsb-release \
    rsync \
    > /dev/null 2>&1

ok "System packages installed"

# =============================================================================
# Step 3: Install PostgreSQL 16
# =============================================================================
step "Installing PostgreSQL 16"

if command -v psql &>/dev/null && psql --version | grep -q "16"; then
    ok "PostgreSQL 16 already installed"
else
    # Add official PostgreSQL repo
    if [[ ! -f /etc/apt/sources.list.d/pgdg.list ]]; then
        curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | \
            gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
            > /etc/apt/sources.list.d/pgdg.list
        apt-get update -qq
    fi
    apt-get install -y -qq postgresql-16 postgresql-client-16 > /dev/null 2>&1
    systemctl enable --now postgresql
    ok "PostgreSQL 16 installed"
fi

# =============================================================================
# Step 4: Install ClickHouse
# =============================================================================
step "Installing ClickHouse"

if command -v clickhouse-server &>/dev/null; then
    ok "ClickHouse already installed"
else
    curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml &>/dev/null || true
    if [[ ! -f /etc/apt/sources.list.d/clickhouse.list ]]; then
        curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml' &>/dev/null || true
        apt-get install -y -qq apt-transport-https ca-certificates > /dev/null 2>&1
        curl -fsSL 'https://packages.clickhouse.com/deb/archive.key' | \
            gpg --dearmor -o /usr/share/keyrings/clickhouse-archive-keyring.gpg 2>/dev/null
        echo "deb [signed-by=/usr/share/keyrings/clickhouse-archive-keyring.gpg] https://packages.clickhouse.com/deb stable main" \
            > /etc/apt/sources.list.d/clickhouse.list
        apt-get update -qq
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        clickhouse-server clickhouse-client clickhouse-common-static > /dev/null 2>&1
    systemctl enable --now clickhouse-server
    ok "ClickHouse installed"
fi

# =============================================================================
# Step 5: Configure PostgreSQL
# =============================================================================
step "Configuring PostgreSQL"

if [[ "$APPLIANCE_MODE" == true ]]; then
    ok "Appliance mode — PostgreSQL configuration deferred to first-boot wizard"
else
PG_PASSWORD="$(generate_password)"

# Check if zentryc DB already exists
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='zentryc'" 2>/dev/null | grep -q 1; then
    ok "Database 'zentryc' already exists"
    # Try to read existing password from .env
    if [[ -f "$ENV_FILE" ]]; then
        PG_PASSWORD=$(grep -oP '^POSTGRES_PASSWORD=\K.*' "$ENV_FILE" 2>/dev/null || echo "$PG_PASSWORD")
    fi
else
    sudo -u postgres psql -q <<EOSQL
CREATE USER zentryc WITH PASSWORD '${PG_PASSWORD}';
CREATE DATABASE zentryc OWNER zentryc;
GRANT ALL PRIVILEGES ON DATABASE zentryc TO zentryc;
EOSQL
    ok "PostgreSQL database and user created"
fi

# Ensure pg_hba allows password auth for zentryc user
PG_HBA=$(sudo -u postgres psql -tAc "SHOW hba_file" 2>/dev/null)
if [[ -n "$PG_HBA" ]] && ! grep -q "zentryc" "$PG_HBA" 2>/dev/null; then
    # Insert before the first existing rule
    sed -i "/^# IPv4 local connections/a host    zentryc    zentryc    127.0.0.1/32    scram-sha-256" "$PG_HBA"
    systemctl reload postgresql
    ok "pg_hba.conf updated"
else
    ok "pg_hba.conf already configured"
fi
fi  # end non-appliance PostgreSQL config

# =============================================================================
# Step 6: Configure ClickHouse
# =============================================================================
step "Configuring ClickHouse"

if [[ "$APPLIANCE_MODE" == true ]]; then
    ok "Appliance mode — ClickHouse configuration deferred to first-boot wizard"
else
CH_PASSWORD="$(generate_password)"

# Check if we already have a password in .env
if [[ -f "$ENV_FILE" ]]; then
    EXISTING_CH_PASS=$(grep -oP '^CLICKHOUSE_PASSWORD=\K.*' "$ENV_FILE" 2>/dev/null || echo "")
    if [[ -n "$EXISTING_CH_PASS" ]]; then
        CH_PASSWORD="$EXISTING_CH_PASS"
    fi
fi

# Create zentryc user in ClickHouse (idempotent)
clickhouse-client --query "
    CREATE USER IF NOT EXISTS zentryc
    IDENTIFIED WITH sha256_password BY '${CH_PASSWORD}';
" 2>/dev/null || true

clickhouse-client --query "
    GRANT ALL ON default.* TO zentryc;
" 2>/dev/null || true

ok "ClickHouse user configured"
fi  # end non-appliance ClickHouse config

# =============================================================================
# Step 7: Create system user and directories
# =============================================================================
step "Creating system user and directories"

if id "$ZENTRYC_USER" &>/dev/null; then
    ok "User '$ZENTRYC_USER' already exists"
else
    useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$ZENTRYC_USER"
    ok "System user '$ZENTRYC_USER' created"
fi

mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/backups" "$INSTALL_DIR/logs" "$SSL_DIR"
ok "Directories created"

# =============================================================================
# Step 8: Deploy application code
# =============================================================================
step "Deploying application code"

if [[ "$OFFLINE_MODE" == true ]]; then
    info "Extracting offline package: $OFFLINE_PACKAGE"
    EXTRACT_DIR=$(mktemp -d)
    tar -xzf "$OFFLINE_PACKAGE" -C "$EXTRACT_DIR"

    # Find the app code directory (may be nested)
    if [[ -d "$EXTRACT_DIR/app" ]]; then
        CODE_SRC="$EXTRACT_DIR/app"
    else
        CODE_SRC="$EXTRACT_DIR"
    fi

    rsync -a --delete \
        --exclude='.env' \
        --exclude='logs/' \
        --exclude='venv/' \
        --exclude='backups/' \
        --exclude='.installed' \
        --exclude='wheels/' \
        "$CODE_SRC/" "$INSTALL_DIR/"

    # Copy wheels if present
    if [[ -d "$EXTRACT_DIR/wheels" ]]; then
        cp -r "$EXTRACT_DIR/wheels" "$INSTALL_DIR/_wheels"
    fi

    rm -rf "$EXTRACT_DIR"
else
    if [[ ! -d "$REPO_DIR/fastapi_app" ]]; then
        fail "Cannot find source code at $REPO_DIR/fastapi_app"
    fi

    rsync -a --delete \
        --exclude='.env' \
        --exclude='logs/' \
        --exclude='venv/' \
        --exclude='backups/' \
        --exclude='.installed' \
        --exclude='.git/' \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        --exclude='deploy/bare-metal/' \
        "$REPO_DIR/" "$INSTALL_DIR/"
fi

ok "Application code deployed to $INSTALL_DIR"

# =============================================================================
# Step 9: Python virtual environment and dependencies
# =============================================================================
step "Setting up Python environment"

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created"
else
    ok "Virtual environment already exists"
fi

# Upgrade pip
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel -q

# Pin bcrypt for passlib compatibility
"$VENV_DIR/bin/pip" install "bcrypt==4.0.1" -q

if [[ "$OFFLINE_MODE" == true ]] && [[ -d "$INSTALL_DIR/_wheels" ]]; then
    info "Installing from offline wheels..."
    "$VENV_DIR/bin/pip" install --no-index --find-links="$INSTALL_DIR/_wheels" \
        -r "$INSTALL_DIR/fastapi_app/requirements.txt" -q
    rm -rf "$INSTALL_DIR/_wheels"
else
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/fastapi_app/requirements.txt" -q
fi

# Re-pin bcrypt after requirements install (in case it was upgraded)
"$VENV_DIR/bin/pip" install "bcrypt==4.0.1" -q

ok "Python dependencies installed"

# =============================================================================
# Step 10: Generate .env configuration
# =============================================================================
step "Generating configuration"

if [[ "$APPLIANCE_MODE" == true ]]; then
    ok "Appliance mode — .env generation deferred to first-boot wizard"
elif [[ -f "$ENV_FILE" ]]; then
    ok ".env already exists — not overwriting"
    # Re-read passwords from existing .env
    PG_PASSWORD=$(grep -oP '^POSTGRES_PASSWORD=\K.*' "$ENV_FILE" 2>/dev/null || echo "$PG_PASSWORD")
    CH_PASSWORD=$(grep -oP '^CLICKHOUSE_PASSWORD=\K.*' "$ENV_FILE" 2>/dev/null || echo "$CH_PASSWORD")
else
    SECRET_KEY="$(generate_password)$(generate_password)"

    cat > "$ENV_FILE" <<ENVEOF
# =============================================================================
# Zentryc SOAR/SIEM Platform - Production Configuration
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# =============================================================================

# --- Application ---
DEBUG=false
SECRET_KEY=${SECRET_KEY}
ALLOWED_HOSTS=*
TZ=UTC

# --- PostgreSQL ---
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=zentryc
POSTGRES_USER=zentryc
POSTGRES_PASSWORD=${PG_PASSWORD}

# --- ClickHouse ---
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_DB=default
CLICKHOUSE_USER=zentryc
CLICKHOUSE_PASSWORD=${CH_PASSWORD}

# --- Web Server ---
WORKERS=4

# --- Syslog Collector ---
SYSLOG_PORT=514
SYSLOG_BATCH_SIZE=5000
SYSLOG_FLUSH_INTERVAL=2.0
SYSLOG_CACHE_TTL=60
SYSLOG_WORKERS=4
SYSLOG_MAX_BUFFER=100000
SYSLOG_METRICS_INTERVAL=30

# --- Logging ---
LOG_LEVEL=INFO
LOG_FILE=logs/zentryc.log
ENVEOF

    chmod 600 "$ENV_FILE"
    ok ".env generated with random credentials"
fi

# =============================================================================
# Step 11: Configure Nginx
# =============================================================================
step "Configuring Nginx"

# Generate self-signed certificate if none exists
if [[ ! -f "$SSL_DIR/server.crt" ]]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/server.key" \
        -out "$SSL_DIR/server.crt" \
        -subj "/CN=zentryc/O=Zentryc/C=US" \
        2>/dev/null
    chmod 600 "$SSL_DIR/server.key"
    chmod 644 "$SSL_DIR/server.crt"
    ok "Self-signed TLS certificate generated"
else
    ok "TLS certificate already exists"
fi

# Install nginx config
cp "$SCRIPT_DIR/zentryc.nginx.conf" "$NGINX_CONF"

# Enable site
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/zentryc

# Remove default site if present
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
    ok "Nginx configured and reloaded"
else
    warn "Nginx config test failed — check $NGINX_CONF"
fi

# =============================================================================
# Step 12: Install systemd services
# =============================================================================
step "Installing systemd services"

cp "$SCRIPT_DIR/zentryc-web.service" /etc/systemd/system/
cp "$SCRIPT_DIR/zentryc-syslog.service" /etc/systemd/system/
cp "$SCRIPT_DIR/zentryc-disk-cleanup.service" /etc/systemd/system/

# Install timer from existing deploy dir (it doesn't need path changes)
if [[ -f "$INSTALL_DIR/deploy/zentryc-disk-cleanup.timer" ]]; then
    cp "$INSTALL_DIR/deploy/zentryc-disk-cleanup.timer" /etc/systemd/system/
elif [[ -f "$REPO_DIR/deploy/zentryc-disk-cleanup.timer" ]]; then
    cp "$REPO_DIR/deploy/zentryc-disk-cleanup.timer" /etc/systemd/system/
fi

systemctl daemon-reload
systemctl enable zentryc-web zentryc-syslog zentryc-disk-cleanup.timer 2>/dev/null
ok "Systemd services installed and enabled"

# =============================================================================
# Step 13: Configure firewall (UFW)
# =============================================================================
step "Configuring firewall"

if command -v ufw &>/dev/null; then
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp comment "SSH" > /dev/null 2>&1
    ufw allow 80/tcp comment "HTTP" > /dev/null 2>&1
    ufw allow 443/tcp comment "HTTPS" > /dev/null 2>&1
    ufw allow 514/udp comment "Syslog" > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
    ok "UFW configured (22/tcp, 80/tcp, 443/tcp, 514/udp)"
else
    warn "UFW not found — configure firewall manually"
fi

# =============================================================================
# Step 14: Kernel tuning (sysctl)
# =============================================================================
step "Tuning kernel parameters"

cat > "$SYSCTL_CONF" <<'SYSCTL'
# Zentryc — UDP receive buffer for high-volume syslog
net.core.rmem_max = 26214400
net.core.rmem_default = 26214400
SYSCTL

sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1
ok "UDP buffer set to 26MB"

# =============================================================================
# Step 15: Set file permissions
# =============================================================================
step "Setting file permissions"

chown -R "$ZENTRYC_USER:$ZENTRYC_GROUP" "$INSTALL_DIR"
chmod 600 "$ENV_FILE"
chmod 755 "$INSTALL_DIR"

# Syslog service runs as root (needs port 514)
# Web service runs as zentryc user

ok "Permissions configured"

# =============================================================================
# Step 16: Start services
# =============================================================================
step "Starting services"

if [[ "$APPLIANCE_MODE" == true ]]; then
    ok "Appliance mode — service start deferred to first-boot wizard"
else
info "Starting zentryc-web..."
systemctl start zentryc-web

# Wait for web service to become healthy
HEALTH_OK=false
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/api/health/simple > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    sleep 2
done

if [[ "$HEALTH_OK" == true ]]; then
    ok "Web service is healthy"
else
    warn "Web service health check timed out — check: journalctl -u zentryc-web -f"
fi

info "Starting zentryc-syslog..."
systemctl start zentryc-syslog
sleep 2

if systemctl is-active --quiet zentryc-syslog; then
    ok "Syslog collector started"
else
    warn "Syslog collector may not have started — check: journalctl -u zentryc-syslog -f"
fi

# Start disk cleanup timer
systemctl start zentryc-disk-cleanup.timer 2>/dev/null || true
fi  # end non-appliance service start

# =============================================================================
# Step 17: Health verification
# =============================================================================
step "Health verification"

if [[ "$APPLIANCE_MODE" == true ]]; then
    ok "Appliance mode — health check deferred to first-boot wizard"
else
HEALTH_RESPONSE=$(curl -sf http://127.0.0.1:8000/api/health 2>/dev/null || echo '{"status":"unreachable"}')
info "Health: $HEALTH_RESPONSE"
fi

# =============================================================================
# Step 18: Install upgrade command
# =============================================================================
step "Installing upgrade command"

cp "$SCRIPT_DIR/zentryc-upgrade.sh" /usr/local/bin/zentryc-upgrade
chmod 755 /usr/local/bin/zentryc-upgrade

ok "Upgrade command installed: sudo zentryc-upgrade"

# =============================================================================
# Step 19: Appliance CLI setup
# =============================================================================
step "Setting up appliance CLI"

# Create CLI entry point wrapper
cat > "$VENV_DIR/bin/zentryc-cli" <<'CLIEOF'
#!/bin/bash
exec /opt/zentryc/venv/bin/python -m fastapi_app.cli.shell.main
CLIEOF
chmod 755 "$VENV_DIR/bin/zentryc-cli"
ok "CLI entry point created at $VENV_DIR/bin/zentryc-cli"

# Install sudoers fragment
if [[ -f "$SCRIPT_DIR/zentryc-cli-sudoers" ]]; then
    cp "$SCRIPT_DIR/zentryc-cli-sudoers" /etc/sudoers.d/zentryc-cli
    chmod 440 /etc/sudoers.d/zentryc-cli
    # Validate sudoers syntax
    if visudo -cf /etc/sudoers.d/zentryc-cli >/dev/null 2>&1; then
        ok "Sudoers rules installed"
    else
        warn "Sudoers syntax check failed — removing to prevent lockout"
        rm -f /etc/sudoers.d/zentryc-cli
    fi
elif [[ -f "$INSTALL_DIR/deploy/bare-metal/zentryc-cli-sudoers" ]]; then
    cp "$INSTALL_DIR/deploy/bare-metal/zentryc-cli-sudoers" /etc/sudoers.d/zentryc-cli
    chmod 440 /etc/sudoers.d/zentryc-cli
    visudo -cf /etc/sudoers.d/zentryc-cli >/dev/null 2>&1 || rm -f /etc/sudoers.d/zentryc-cli
    ok "Sudoers rules installed"
fi

if [[ "$APPLIANCE_MODE" == true ]]; then
    # Set CLI as login shell for zentryc user
    chsh -s "$VENV_DIR/bin/zentryc-cli" "$ZENTRYC_USER" 2>/dev/null || true

    # Add zentryc-cli to /etc/shells if not present
    if ! grep -q "zentryc-cli" /etc/shells 2>/dev/null; then
        echo "$VENV_DIR/bin/zentryc-cli" >> /etc/shells
    fi

    # Configure SSH ForceCommand as defense-in-depth
    if ! grep -q "Match User zentryc" /etc/ssh/sshd_config 2>/dev/null; then
        cat >> /etc/ssh/sshd_config <<SSHEOF

# Zentryc appliance CLI — restrict zentryc user to CLI shell
Match User zentryc
    ForceCommand $VENV_DIR/bin/zentryc-cli
    AllowTcpForwarding no
    X11Forwarding no
SSHEOF
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    fi
    ok "Appliance CLI configured as login shell with SSH ForceCommand"

    # Enable first-boot wizard service if the service file exists
    if [[ -f "$SCRIPT_DIR/zentryc-firstboot.service" ]]; then
        cp "$SCRIPT_DIR/zentryc-firstboot.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable zentryc-firstboot 2>/dev/null || true
        ok "First-boot wizard service enabled"
    elif [[ -f "$INSTALL_DIR/deploy/bare-metal/zentryc-firstboot.service" ]]; then
        cp "$INSTALL_DIR/deploy/bare-metal/zentryc-firstboot.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable zentryc-firstboot 2>/dev/null || true
        ok "First-boot wizard service enabled"
    fi

    # Set a temporary password for zentryc user (for SSH access to CLI)
    echo "zentryc:zentryc" | chpasswd
    ok "Temporary password for 'zentryc' user: zentryc (change on first login)"
else
    ok "CLI available at: $VENV_DIR/bin/zentryc-cli"
fi

# =============================================================================
# Step 20: Write install marker
# =============================================================================
date -u +%Y-%m-%dT%H:%M:%SZ > "$INSTALL_MARKER"
VERSION=$(grep '__version__' "$INSTALL_DIR/fastapi_app/__version__.py" 2>/dev/null | cut -d'"' -f2 || echo "unknown")

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Zentryc ${VERSION} — Installation Complete${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

SERVER_IP=$(hostname -I | awk '{print $1}')

echo "  Web UI:        https://${SERVER_IP}/"
echo "  Login:         admin / changeme"
echo "  Syslog:        UDP ${SERVER_IP}:514"
echo "  Health:        https://${SERVER_IP}/api/health"
echo ""
echo "  Install dir:   $INSTALL_DIR"
echo "  Config:        $ENV_FILE"
echo "  Logs:          $INSTALL_DIR/logs/"
echo "  Backups:       $INSTALL_DIR/backups/"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status zentryc-web"
echo "    sudo systemctl status zentryc-syslog"
echo "    sudo journalctl -u zentryc-web -f"
echo "    sudo zentryc-upgrade"
echo ""
echo -e "${YELLOW}  IMPORTANT: Change the default admin password after first login!${NC}"
echo ""
