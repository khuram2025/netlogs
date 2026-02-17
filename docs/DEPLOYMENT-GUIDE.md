# NetLogs SOAR/SIEM Platform — Deployment Guide

**Version:** 3.0.0
**Last Updated:** February 2026

---

## 1. Server Requirements

### Operating System

| OS | Version | Status |
|----|---------|--------|
| Ubuntu Server | 22.04 LTS or 24.04 LTS | Recommended |
| Debian | 12 (Bookworm) | Supported |
| RHEL / Rocky Linux | 8.x or 9.x | Supported |
| Any Linux with Docker | Kernel 5.10+ | Supported |

> **Windows and macOS are not supported** for production deployments.

### Hardware

| Component | Minimum | Recommended | High Volume (>50K EPS) |
|-----------|---------|-------------|------------------------|
| CPU | 4 cores | 8 cores | 16+ cores |
| RAM | 8 GB | 16 GB | 32+ GB |
| Disk | 100 GB SSD | 500 GB SSD | 1+ TB NVMe |
| Network | 1 Gbps | 1 Gbps | 10 Gbps |

> Disk usage depends on log volume and retention. Estimate ~1 GB per 10 million log entries (compressed in ClickHouse).

### Software Prerequisites

| Software | Version | Purpose |
|----------|---------|---------|
| Docker Engine | 24.0+ | Container runtime |
| Docker Compose | v2.20+ (plugin) | Service orchestration |
| Git | Any | Clone the repository |

---

## 2. Quick Start (Recommended)

On a fresh Ubuntu server with internet access:

```bash
git clone <repository-url> /opt/netlogs
cd /opt/netlogs
sudo ./install.sh
```

The install script automatically:
- Installs Docker (if not present)
- Generates secure random passwords
- Builds and starts all 5 containers
- Waits for health checks to pass
- Prints the access URL and next steps

The script is idempotent — safe to re-run. It skips Docker install if already present, and preserves `.env` if it already exists.

After installation, open `https://<server-ip>` and complete the setup wizard.

> For manual installation or customization, see the step-by-step guide below.

---

## 3. Manual Installation

### Step 1 — Install Docker

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

```bash
# RHEL/Rocky
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Verify:
```bash
docker --version        # Should be 24.0+
docker compose version  # Should be v2.20+
```

### Step 2 — Clone the Repository

```bash
git clone <repository-url> /opt/netlogs
cd /opt/netlogs
```

### Step 3 — Configure Environment

```bash
cp .env.example .env
nano .env
```

**Required changes in `.env`:**

```ini
# CHANGE THESE — do not use defaults in production
POSTGRES_PASSWORD=YourStrongPassword1!
CLICKHOUSE_PASSWORD=YourStrongPassword2!

# Set your timezone
TZ=Asia/Riyadh

# Optional: set a persistent secret key
# SECRET_KEY=generate-a-random-64-char-string
```

### Step 4 — Start the Platform

```bash
docker compose up -d
```

This starts 5 services:

| Service | Port | Description |
|---------|------|-------------|
| **nginx** | 80 (HTTP), 443 (HTTPS) | Reverse proxy with TLS |
| **web** | 8000 (internal) | FastAPI application |
| **syslog** | 514/UDP | Syslog collector |
| **postgres** | 5432 (internal) | PostgreSQL database |
| **clickhouse** | 8123 (internal) | ClickHouse log storage |

Wait ~30 seconds for all services to start, then verify:

```bash
docker compose ps          # All services should show "healthy"
curl -k https://localhost/api/health/simple   # Should return {"status":"ok"}
```

### Step 5 — First-Run Setup Wizard

1. Open `https://<server-ip>` in a browser
2. Accept the self-signed certificate warning
3. The **Setup Wizard** will appear automatically:
   - **Step 1:** Change the default admin password (default: `changeme`)
   - **Step 2:** (Optional) Configure a notification channel (email/Telegram/webhook)
   - **Step 3:** (Optional) Verify syslog data is arriving
   - **Step 4:** Review and launch

> After completing the wizard, it will never appear again.

---

## 4. Network Configuration

### Firewall Rules

Open these ports on the server firewall:

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 443 | TCP | Inbound | Web UI (HTTPS) |
| 80 | TCP | Inbound | Redirects to HTTPS |
| 514 | UDP | Inbound | Syslog from network devices |
| 22 | TCP | Inbound | SSH management (optional) |

### Configure Syslog Sources

On your firewalls/switches/routers, configure syslog forwarding:

```
# Fortinet FortiGate
config log syslogd setting
    set status enable
    set server <netlogs-server-ip>
    set port 514
    set format default
end

# Cisco ASA
logging enable
logging host inside <netlogs-server-ip>
logging trap informational

# Palo Alto
set shared log-settings syslog <profile-name> server <name> server <netlogs-server-ip>
set shared log-settings syslog <profile-name> server <name> transport UDP
set shared log-settings syslog <profile-name> server <name> port 514
```

Verify logs are arriving:
```bash
curl -k https://localhost/api/health | python3 -m json.tool
# Check "syslog" → "current_eps" — should be > 0
```

---

## 5. TLS Certificate (Production)

The platform auto-generates a self-signed certificate on first start. For production, replace it with a proper certificate:

```bash
# Place your certificate files:
docker compose cp /path/to/your/cert.pem nginx:/etc/nginx/certs/server.crt
docker compose cp /path/to/your/key.pem nginx:/etc/nginx/certs/server.key

# Or mount them via volume — create the files first:
mkdir -p certs/
cp /path/to/your/cert.pem certs/server.crt
cp /path/to/your/key.pem certs/server.key

# Then restart nginx:
docker compose restart nginx
```

The certificate volume (`netlogs-certs`) persists across restarts.

---

## 6. Backup & Restore

### Manual Backup

```bash
cd /opt/netlogs
./scripts/backup.sh
```

Output: `backups/netlogs-backup-YYYYMMDD-HHMMSS.tar.gz`

Backups include:
- PostgreSQL full dump (users, rules, devices, settings)
- ClickHouse data (audit logs, recent syslogs, IOC matches, correlation matches)
- Configuration files (.env, version info)

### Restore from Backup

```bash
# Dry-run (preview what will be restored):
./scripts/restore.sh backups/netlogs-backup-20260216-140139.tar.gz

# Execute restore:
./scripts/restore.sh backups/netlogs-backup-20260216-140139.tar.gz --confirm

# Restart services after restore:
docker compose restart
```

### Backup via Web UI

Login as admin → sidebar → **Backups** → Click "Create Backup"

---

## 7. Upgrading

```bash
cd /opt/netlogs
git pull origin main
./scripts/upgrade.sh
```

The upgrade script will:
1. Check prerequisites (Docker, disk space)
2. Create an automatic backup
3. Build the new Docker image
4. Run database migrations
5. Rolling-restart services (no downtime)
6. Verify health

### Rollback (if upgrade fails)

```bash
./scripts/rollback.sh
```

This restores from the most recent backup and restarts all services.

---

## 8. Default Credentials

| Account | Username | Default Password | Notes |
|---------|----------|-----------------|-------|
| Admin Web UI | `admin` | `changeme` | **Must be changed** on first login via setup wizard |

> The setup wizard enforces a password change. Passwords must be at least 8 characters with uppercase, lowercase, and a digit.

---

## 9. Service Management

```bash
# View all services
docker compose ps

# View logs (all services)
docker compose logs -f --tail=100

# View logs (specific service)
docker compose logs -f web
docker compose logs -f syslog

# Restart a specific service
docker compose restart web

# Stop all services
docker compose down

# Start all services
docker compose up -d

# Full health check
curl -k https://localhost/api/health | python3 -m json.tool
```

---

## 10. Exposed Ports (Customizable)

All external ports can be changed via `.env`:

```ini
HTTP_PORT=80              # Nginx HTTP
HTTPS_PORT=443            # Nginx HTTPS
SYSLOG_EXTERNAL_PORT=514  # Syslog UDP
POSTGRES_EXTERNAL_PORT=5432   # PostgreSQL (disable in production)
CLICKHOUSE_EXTERNAL_PORT=8123 # ClickHouse (disable in production)
```

> **Security:** In production, remove `POSTGRES_EXTERNAL_PORT` and `CLICKHOUSE_EXTERNAL_PORT` from `.env` or set to empty to prevent external access to databases.

---

## 11. Troubleshooting

| Problem | Solution |
|---------|----------|
| Web UI not loading | `docker compose logs web` — check for startup errors |
| No syslog data arriving | Verify UDP 514 is open: `sudo ss -ulnp \| grep 514` |
| "Setup wizard" keeps appearing | Ensure the setup was completed (check browser console for errors) |
| Certificate warning in browser | Expected with self-signed cert. Replace with real cert (Section 5) |
| High disk usage | Go to Dashboard → check storage. Configure retention in System settings |
| Containers keep restarting | `docker compose logs <service>` — check for crash loops |
| Database connection errors | Verify `.env` passwords match, run `docker compose restart` |
| Login fails after restore | Admin password reverts to backup state. Reset via setup wizard if needed |

---

## 12. Architecture Overview

```
Internet / Network Devices
         │
         │  UDP 514 (syslog)
         ▼
    ┌─────────┐     ┌───────────┐
    │ Syslog  │────▶│ ClickHouse│  (log storage, 58M+ rows)
    │Collector│     │           │
    └─────────┘     └───────────┘
                          ▲
    Browser               │
         │                │
         │  HTTPS 443     │
         ▼                │
    ┌─────────┐     ┌─────┴─────┐
    │  Nginx  │────▶│  FastAPI  │──▶ PostgreSQL
    │  (TLS)  │     │   (Web)   │   (users, rules,
    └─────────┘     └───────────┘    devices, config)
```

All services run as Docker containers on a single server.

---

*For questions or support, contact the NetLogs development team.*
