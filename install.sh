#!/usr/bin/env bash
# =============================================================================
# Zentryc SOAR/SIEM Platform — One-Command Installer
#
# Fresh server:  curl -fsSL https://raw.githubusercontent.com/khuram2025/netlogs/main/install.sh | sudo bash
# Or locally:    sudo bash install.sh
# =============================================================================
set -euo pipefail

# --- Colors & helpers --------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

REPO="https://github.com/khuram2025/netlogs.git"
INSTALL_DIR="/opt/zentryc"

# If running from inside the repo, use that path; otherwise clone to /opt/zentryc
if [[ -f "$(dirname "${BASH_SOURCE[0]:-$0}")/docker-compose.yml" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
else
    SCRIPT_DIR="$INSTALL_DIR"
fi
cd "$SCRIPT_DIR" 2>/dev/null || true

# =============================================================================
# Step 1: Pre-flight checks
# =============================================================================
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       Zentryc SOAR/SIEM Platform Installer      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root. Use: sudo ./install.sh"
fi

# OS check
if [[ "$(uname -s)" != "Linux" ]]; then
    fail "This installer only supports Linux."
fi

info "Checking system resources..."

# RAM check (minimum 4 GB)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
if [[ $TOTAL_RAM_GB -lt 3 ]]; then
    fail "Minimum 4 GB RAM required. Detected: ~${TOTAL_RAM_GB} GB"
fi
ok "RAM: ~${TOTAL_RAM_GB} GB"

# Disk check (minimum 20 GB free)
FREE_DISK_KB=$(df --output=avail /opt 2>/dev/null || df --output=avail / | tail -1 | tr -d ' ')
FREE_DISK_KB=$(echo "$FREE_DISK_KB" | tail -1 | tr -d ' ')
FREE_DISK_GB=$((FREE_DISK_KB / 1024 / 1024))
if [[ $FREE_DISK_GB -lt 20 ]]; then
    fail "Minimum 20 GB free disk required. Available: ${FREE_DISK_GB} GB"
fi
ok "Disk: ${FREE_DISK_GB} GB free"

# =============================================================================
# Step 2: Install Docker (if not present)
# =============================================================================
echo ""
info "Checking Docker installation..."

if command -v docker &>/dev/null; then
    ok "Docker already installed: $(docker --version | head -1)"
else
    info "Installing Docker via get.docker.com..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    ok "Docker installed: $(docker --version | head -1)"
fi

# Verify docker compose (v2 plugin)
if docker compose version &>/dev/null; then
    ok "Docker Compose: $(docker compose version --short)"
else
    fail "Docker Compose plugin not found. Install with: apt install docker-compose-plugin"
fi

# =============================================================================
# Step 3: Clone or update repository
# =============================================================================
echo ""
info "Setting up Zentryc source..."

if ! command -v git &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
fi

if [[ ! -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
    info "Cloning repository to $INSTALL_DIR..."
    git clone --depth 1 "$REPO" "$INSTALL_DIR" --quiet
    SCRIPT_DIR="$INSTALL_DIR"
    ok "Cloned to $INSTALL_DIR"
else
    ok "Source found at $SCRIPT_DIR"
fi

cd "$SCRIPT_DIR"

# =============================================================================
# Step 4: Generate .env
# =============================================================================
echo ""
info "Configuring environment..."

generate_password() {
    openssl rand -base64 24 | tr -d '/+=' | head -c 24
}

generate_secret_key() {
    openssl rand -hex 32
}

if [[ -f .env ]]; then
    warn ".env already exists — skipping generation (passwords unchanged)"
else
    cp .env.example .env

    PG_PASS=$(generate_password)
    CH_PASS=$(generate_password)
    SECRET=$(generate_secret_key)

    # Detect system timezone
    if command -v timedatectl &>/dev/null; then
        SYS_TZ=$(timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
    elif [[ -f /etc/timezone ]]; then
        SYS_TZ=$(cat /etc/timezone)
    else
        SYS_TZ="UTC"
    fi

    # Auto-detect workers based on CPU cores
    NCPU=$(nproc 2>/dev/null || echo 4)
    WORKERS=$(( NCPU * 2 ))
    [[ $WORKERS -gt 16 ]] && WORKERS=16

    # Replace values in .env
    sed -i "s|POSTGRES_PASSWORD=ChangeMeNow!|POSTGRES_PASSWORD=${PG_PASS}|" .env
    sed -i "s|CLICKHOUSE_PASSWORD=ChangeMeNow!|CLICKHOUSE_PASSWORD=${CH_PASS}|" .env
    sed -i "s|# SECRET_KEY=your-secret-key-here|SECRET_KEY=${SECRET}|" .env
    sed -i "s|TZ=Asia/Riyadh|TZ=${SYS_TZ}|" .env
    sed -i "s|WORKERS=4|WORKERS=${WORKERS}|" .env

    # PgBouncer: trust auth on internal Docker network (not exposed externally)
    echo "\"zentryc\" \"${PG_PASS}\"" > docker/pgbouncer-userlist.txt
    sed -i 's|auth_type = scram-sha-256|auth_type = trust|' docker/pgbouncer.ini 2>/dev/null || true
    sed -i 's|auth_type = plain|auth_type = trust|' docker/pgbouncer.ini 2>/dev/null || true

    ok "Generated .env with secure random passwords"
    ok "Timezone: ${SYS_TZ} | Workers: ${WORKERS}"
fi

# --- Free port 514 if occupied ---
if ss -ulnp 2>/dev/null | grep -q ':514 '; then
    info "Port 514/UDP in use — stopping rsyslog..."
    systemctl stop rsyslog 2>/dev/null && systemctl disable rsyslog 2>/dev/null || true
    if ss -ulnp 2>/dev/null | grep -q ':514 '; then
        warn "Port 514 still occupied. Syslog will use port 1514."
        grep -q 'SYSLOG_EXTERNAL_PORT' .env || echo 'SYSLOG_EXTERNAL_PORT=1514' >> .env
    else
        ok "Port 514 freed"
    fi
fi

# =============================================================================
# Step 5: Build & Start
# =============================================================================
echo ""
info "Building Zentryc Docker image..."
docker compose build --quiet

info "Starting all services..."
docker compose up -d

# =============================================================================
# Step 6: Wait for health
# =============================================================================
echo ""
info "Waiting for services to become healthy (up to 120s)..."

TIMEOUT=120
ELAPSED=0
INTERVAL=5

while [[ $ELAPSED -lt $TIMEOUT ]]; do
    # Count healthy services (expect 5)
    HEALTHY=$(docker compose ps --format json 2>/dev/null \
        | grep -c '"healthy"' 2>/dev/null || echo "0")

    if [[ "$HEALTHY" -ge 7 ]]; then
        ok "All services are healthy!"
        break
    fi

    printf "."
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo ""

if [[ $ELAPSED -ge $TIMEOUT ]]; then
    warn "Timeout waiting for all services. Current status:"
    docker compose ps
    echo ""
    warn "Services may still be starting. Check with: docker compose ps"
    warn "View logs with: docker compose logs -f"
fi

# =============================================================================
# Step 7: Print summary
# =============================================================================

# Auto-detect server IP
SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          Zentryc Installation Complete!          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Web UI:${NC}       https://${SERVER_IP}"
echo -e "  ${BOLD}Login:${NC}        admin / changeme"
echo -e "  ${BOLD}Syslog Port:${NC}  ${SERVER_IP}:514/UDP"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "    1. Open the URL above in a browser"
echo -e "    2. Accept the self-signed certificate warning"
echo -e "    3. Complete the setup wizard (change the admin password)"
echo -e "    4. Point your firewalls/switches to send syslog to ${SERVER_IP}:514"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "    docker compose ps            # Service status"
echo -e "    docker compose logs -f        # Live logs"
echo -e "    docker compose down           # Stop all"
echo -e "    docker compose up -d          # Start all"
echo ""
echo -e "  ${BOLD}Generated passwords saved in:${NC} ${SCRIPT_DIR}/.env"
echo ""
