# Zentryc SOAR/SIEM - Deployment Guide

**Single-command deployment on a fresh Ubuntu 22.04/24.04 server.**

---

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS (64-bit) |
| CPU | 4 cores |
| RAM | 16 GB |
| Disk | 100 GB SSD (logs grow ~1 GB/day at 1000 EPS) |
| Network | Static IP, ports 80/443/514(UDP) reachable from firewalls |

---

## Step 1 - Install Docker

```bash
# Install Docker Engine + Compose plugin
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

Verify:
```bash
docker compose version   # must be v2.20+
```

---

## Step 2 - Clone the Repository

```bash
cd /opt
sudo git clone https://github.com/khuram2025/netlogs.git zentryc
sudo chown -R $USER:$USER zentryc
cd zentryc
```

---

## Step 3 - Configure Environment

```bash
cp .env.example .env
nano .env
```

**You MUST change these values:**

```bash
# --- Passwords (change all three) ---
POSTGRES_PASSWORD=YourStrongPassword1!
CLICKHOUSE_PASSWORD=YourStrongPassword2!
SECRET_KEY=run-this: python3 -c "import secrets; print(secrets.token_urlsafe(48))"

# --- Timezone ---
TZ=Asia/Riyadh          # Change to your timezone

# --- Network Subnets ---
# CRITICAL: These must NOT overlap with your real network ranges.
# If your internal network uses 10.x.x.x, change these:
DOCKER_SUBNET_FRONTEND=10.200.0.0/24
DOCKER_SUBNET_BACKEND=10.200.1.0/24

# --- Syslog Port ---
# Default 514. Change if the host already runs rsyslog on 514:
# SYSLOG_EXTERNAL_PORT=1514

# --- Workers (set to 2x CPU cores) ---
WORKERS=8               # For a 4-core server
```

**Update PgBouncer credentials to match:**
```bash
# Edit docker/pgbouncer-userlist.txt — must match POSTGRES_USER and POSTGRES_PASSWORD
# Format: "username" "password"
nano docker/pgbouncer-userlist.txt
```

---

## Step 4 - Build & Start

```bash
docker compose build
docker compose up -d
```

First boot takes ~60 seconds (database init, migrations, seeding).

Check all 8 services are healthy:
```bash
docker compose ps
```

Expected output — all services should show `healthy`:
```
NAME                    STATUS
net-logs-postgres-1     Up (healthy)
net-logs-clickhouse-1   Up (healthy)
net-logs-redis-1        Up (healthy)
net-logs-pgbouncer-1    Up (healthy)
net-logs-web-1          Up (healthy)
net-logs-syslog-1       Up (healthy)
net-logs-nginx-1        Up (healthy)
net-logs-prometheus-1   Up (healthy)
```

---

## Step 5 - Verify

**Web UI:**
```
http://<SERVER_IP>/
```
- Default login: `admin` / `changeme`
- **Change the admin password immediately** after first login.

**Health check:**
```bash
curl -s http://localhost/api/health/simple
# Should return: {"status":"healthy"}
```

**Syslog reception test:**
```bash
# From another machine, send a test syslog:
echo "<14>1 2026-01-01T00:00:00Z testhost testapp - - - Test message" | nc -u -w1 <SERVER_IP> 514
```
Check the Logs page — the test message should appear within a few seconds.

---

## Step 6 - Point Your Firewalls

Configure syslog forwarding on your firewalls:

| Vendor | Setting |
|---|---|
| **Palo Alto** | Device > Server Profiles > Syslog > Add server `<SERVER_IP>:514 UDP` |
| **FortiGate** | Log & Report > Log Settings > Remote Logging > Syslog `<SERVER_IP>:514 UDP` |
| **Generic** | Any device that sends RFC 3164/5424 syslog over UDP port 514 |

---

## Architecture

```
Internet/Firewalls
       |
    UDP:514 ──> [ Syslog Collector ] ──> ClickHouse (logs)
       |
   HTTP:80/443 ──> [ Nginx ] ──> [ FastAPI Web ] ──> PostgreSQL (config)
                                       |              Redis (cache)
                                       └──> ClickHouse (queries)
```

**8 containers:**

| Container | Purpose | Resource Limit |
|---|---|---|
| postgres | Users, devices, rules, EDL, config | 4 GB / 2 CPU |
| clickhouse | Log storage & analytics (billions of rows) | 8 GB / 4 CPU |
| redis | Session cache, rate limiting, pub/sub | 1 GB / 1 CPU |
| pgbouncer | PostgreSQL connection pooling | 256 MB / 0.5 CPU |
| web | FastAPI application (UI + API) | 4 GB / 2 CPU |
| syslog | UDP syslog receiver + parser | 2 GB / 2 CPU |
| nginx | Reverse proxy, TLS termination | 512 MB / 1 CPU |
| prometheus | Metrics collection | 1 GB / 1 CPU |

**Persistent volumes** (survive `docker compose down`):
- `postgres-data` — structured data
- `clickhouse-data` — log data
- `redis-data` — cache
- `zentryc-logs` — application logs
- `zentryc-credentials` — device credentials
- `zentryc-certs` — TLS certificates
- `prometheus-data` — metrics

---

## Common Operations

### View logs
```bash
docker compose logs -f web        # App logs
docker compose logs -f syslog     # Syslog collector
docker compose logs -f nginx      # Access logs
```

### Restart a service
```bash
docker compose restart web
```

### Update to latest version
```bash
cd /opt/zentryc
git pull origin main
docker compose build
docker compose up -d
```

### Backup
```bash
# PostgreSQL
docker exec net-logs-postgres-1 pg_dump -U zentryc zentryc > backup_pg_$(date +%Y%m%d).sql

# ClickHouse (export as TSV)
docker exec net-logs-clickhouse-1 clickhouse-client --query "SELECT * FROM syslogs FORMAT TabSeparated" > backup_ch_$(date +%Y%m%d).tsv
```

### Restore PostgreSQL backup
```bash
docker cp backup_pg.sql net-logs-postgres-1:/tmp/
docker exec net-logs-postgres-1 psql -U zentryc -d zentryc -f /tmp/backup_pg.sql
```

### Stop everything
```bash
docker compose down          # Stops containers, keeps data
docker compose down -v       # WARNING: Deletes all data volumes
```

---

## Ports Summary

| Port | Protocol | Service | Expose to |
|---|---|---|---|
| 80 | TCP | HTTP (redirects to HTTPS) | Analysts / Admins |
| 443 | TCP | HTTPS (Web UI + API) | Analysts / Admins |
| 514 | UDP | Syslog receiver | Firewalls only |
| 9090 | TCP | Prometheus metrics | Internal only |

---

## Troubleshooting

**Container not starting?**
```bash
docker compose logs <service-name>
```

**Port 514 already in use?**
```bash
# Check what's using it:
sudo ss -ulnp | grep 514
# If systemd-journald or rsyslog, either stop it or change SYSLOG_EXTERNAL_PORT in .env
```

**Docker subnet conflict (SSH drops after `docker compose up`)?**
```bash
# Edit .env and change subnets to ranges not used by your network:
DOCKER_SUBNET_FRONTEND=10.200.0.0/24
DOCKER_SUBNET_BACKEND=10.200.1.0/24
```

**ClickHouse out of disk?**
```bash
# Check disk usage:
docker exec net-logs-clickhouse-1 clickhouse-client --query "SELECT formatReadableSize(sum(bytes)) FROM system.parts WHERE active"
# Data is auto-purged after 3-6 months (TTL configured per table)
```

**Reset admin password?**
```bash
docker exec -it net-logs-web-1 python -c "
import asyncio
from fastapi_app.db.database import async_engine, AsyncSessionLocal
from fastapi_app.models.user import User
from passlib.context import CryptContext
from sqlalchemy import select

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

async def reset():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == 'admin'))
        user = result.scalar_one()
        user.hashed_password = pwd_context.hash('changeme')
        await db.commit()
        print('Admin password reset to: changeme')

asyncio.run(reset())
"
```

---

## Quick Start (TL;DR)

```bash
# On a fresh Ubuntu server:
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

cd /opt
sudo git clone https://github.com/khuram2025/netlogs.git zentryc
sudo chown -R $USER:$USER zentryc && cd zentryc

cp .env.example .env
# Edit .env — change passwords and subnet if needed
nano .env

docker compose build && docker compose up -d

# Wait 60s, then open http://<SERVER_IP>
# Login: admin / changeme
```
