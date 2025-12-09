# NetLogs SOAR/SIEM Platform - Complete Server Setup Guide

**Version:** 1.0
**Date:** December 2024
**Author:** System Architecture Documentation

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Server Requirements](#3-server-requirements)
4. [Step 1: Operating System Setup](#4-step-1-operating-system-setup)
5. [Step 2: PostgreSQL Installation](#5-step-2-postgresql-installation)
6. [Step 3: ClickHouse Installation](#6-step-3-clickhouse-installation)
7. [Step 4: Application Deployment](#7-step-4-application-deployment)
8. [Step 5: Nginx Reverse Proxy](#8-step-5-nginx-reverse-proxy)
9. [Step 6: Systemd Services](#9-step-6-systemd-services)
10. [Step 7: Firewall Configuration](#10-step-7-firewall-configuration)
11. [Step 8: Configure Network Devices](#11-step-8-configure-network-devices)
12. [Verification & Testing](#12-verification--testing)
13. [Maintenance & Operations](#13-maintenance--operations)
14. [Troubleshooting](#14-troubleshooting)
15. [Complete Configuration Files](#15-complete-configuration-files)

---

## 1. System Overview

NetLogs is a high-performance SOAR/SIEM platform for collecting, parsing, and analyzing firewall logs from multiple vendors including:
- **Fortinet FortiGate**
- **Palo Alto Networks**
- **Generic Syslog devices**

### Key Features
- Real-time syslog collection via UDP port 514
- High-throughput processing (100,000+ logs/minute)
- Advanced search with CIDR, IP ranges, and field operators
- Multi-firewall session flow correlation
- Per-device retention policies
- Automatic device discovery

### Components
| Component | Technology | Port | Purpose |
|-----------|------------|------|---------|
| Syslog Collector | Python AsyncIO | UDP 514 | Receive logs from firewalls |
| Web Application | FastAPI + Uvicorn | TCP 8001 | Web UI and REST API |
| Reverse Proxy | Nginx | TCP 80 | HTTP proxy and static files |
| Relational DB | PostgreSQL | TCP 5432 | Device management |
| Time-series DB | ClickHouse | TCP 8123 | Log storage and queries |

---

## 2. Architecture Diagram

```
                                    ┌─────────────────────────────────────┐
                                    │        NETWORK FIREWALLS            │
                                    │  (FortiGate, Palo Alto, Others)     │
                                    └──────────────┬──────────────────────┘
                                                   │
                                                   │ UDP Syslog (Port 514)
                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                              NETLOGS SERVER                                          │
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    SYSLOG COLLECTOR (run_syslog.py)                         │    │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────────┐  │    │
│  │  │ UDP Listener│───▶│Device Cache │───▶│Log Parser   │───▶│Batch Buffer  │  │    │
│  │  │ (Port 514)  │    │(TTL: 60s)   │    │(Multi-vendor│    │(5000 logs)   │  │    │
│  │  └─────────────┘    └──────┬──────┘    └─────────────┘    └──────┬───────┘  │    │
│  │                            │                                     │          │    │
│  │                            ▼                                     ▼          │    │
│  │                    ┌───────────────┐                    ┌────────────────┐  │    │
│  │                    │  PostgreSQL   │                    │   ClickHouse   │  │    │
│  │                    │  (Devices)    │                    │   (Logs)       │  │    │
│  │                    └───────────────┘                    └────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │                    WEB APPLICATION (run_fastapi.py)                         │    │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                      │    │
│  │  │ FastAPI     │───▶│ PostgreSQL  │    │ ClickHouse  │                      │    │
│  │  │ (Port 8001) │    │ Queries     │    │ Queries     │                      │    │
│  │  └──────┬──────┘    └─────────────┘    └─────────────┘                      │    │
│  │         │                                                                    │    │
│  │         ▼                                                                    │    │
│  │  ┌─────────────┐                                                             │    │
│  │  │   Nginx     │◀──── HTTP (Port 80) ◀──── Users/Browsers                   │    │
│  │  │(Reverse Proxy)                                                            │    │
│  │  └─────────────┘                                                             │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Server Requirements

### Minimum Hardware
| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe |
| Network | 1 Gbps | 10 Gbps |

### Software Requirements
| Software | Version | Purpose |
|----------|---------|---------|
| Ubuntu | 22.04 LTS | Operating System |
| Python | 3.10+ | Application Runtime |
| PostgreSQL | 14+ | Device Database |
| ClickHouse | 23.x+ | Log Storage |
| Nginx | 1.18+ | Reverse Proxy |

### Capacity Planning
| Logs/Day | Storage/Month | RAM Needed |
|----------|---------------|------------|
| 1 Million | ~5 GB | 8 GB |
| 10 Million | ~50 GB | 16 GB |
| 100 Million | ~500 GB | 32 GB |

---

## 4. Step 1: Operating System Setup

### 4.1 Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### 4.2 Install Essential Packages
```bash
sudo apt install -y \
    build-essential \
    python3.10 \
    python3.10-venv \
    python3-pip \
    git \
    curl \
    wget \
    htop \
    net-tools \
    ufw
```

### 4.3 Create Application User
```bash
# Create user 'net' for running the application
sudo useradd -m -s /bin/bash net
sudo passwd net

# Add to sudo group (optional, for administration)
sudo usermod -aG sudo net
```

### 4.4 Set System Limits
```bash
# Edit /etc/security/limits.conf
sudo tee -a /etc/security/limits.conf << 'EOF'
net soft nofile 65536
net hard nofile 65536
root soft nofile 65536
root hard nofile 65536
* soft nproc 65536
* hard nproc 65536
EOF

# Edit /etc/sysctl.conf for network performance
sudo tee -a /etc/sysctl.conf << 'EOF'
# Network performance tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF

sudo sysctl -p
```

---

## 5. Step 2: PostgreSQL Installation

### 5.1 Install PostgreSQL
```bash
sudo apt install -y postgresql postgresql-contrib
```

### 5.2 Start and Enable Service
```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 5.3 Create Database and User
```bash
sudo -u postgres psql << 'EOF'
-- Create database
CREATE DATABASE netlogs;

-- Create user with password
CREATE USER read WITH PASSWORD 'Read@123';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE netlogs TO read;

-- Connect to netlogs database
\c netlogs

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO read;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO read;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO read;

EOF
```

### 5.4 Configure PostgreSQL for Local Access
```bash
# Edit pg_hba.conf to allow local connections
sudo nano /etc/postgresql/14/main/pg_hba.conf

# Add this line (if not present):
# local   all             all                                     md5
# host    all             all             127.0.0.1/32            md5
```

### 5.5 Restart PostgreSQL
```bash
sudo systemctl restart postgresql
```

### 5.6 Verify Connection
```bash
psql -h localhost -U read -d netlogs -c "SELECT 1;"
# Enter password: Read@123
```

---

## 6. Step 3: ClickHouse Installation

### 6.1 Add ClickHouse Repository
```bash
sudo apt install -y apt-transport-https ca-certificates dirmngr
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 8919F6BD2B48D754

echo "deb https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
```

### 6.2 Install ClickHouse
```bash
sudo apt update
sudo apt install -y clickhouse-server clickhouse-client
```

### 6.3 Configure ClickHouse
```bash
# Set password for default user
sudo nano /etc/clickhouse-server/users.d/default-password.xml
```

Add the following content:
```xml
<?xml version="1.0"?>
<clickhouse>
    <users>
        <default>
            <password>password</password>
        </default>
    </users>
</clickhouse>
```

### 6.4 Configure ClickHouse Server
```bash
sudo nano /etc/clickhouse-server/config.d/listen.xml
```

Add the following content:
```xml
<?xml version="1.0"?>
<clickhouse>
    <listen_host>127.0.0.1</listen_host>
    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
</clickhouse>
```

### 6.5 Start and Enable ClickHouse
```bash
sudo systemctl start clickhouse-server
sudo systemctl enable clickhouse-server
```

### 6.6 Create Syslogs Table
```bash
clickhouse-client --password password << 'EOF'

CREATE TABLE IF NOT EXISTS default.syslogs (
    timestamp DateTime64(3) CODEC(DoubleDelta, LZ4),
    device_ip IPv4 CODEC(ZSTD(1)),
    facility UInt8 CODEC(T64, LZ4),
    severity UInt8 CODEC(T64, LZ4),
    message String CODEC(ZSTD(3)),
    raw String CODEC(ZSTD(3)),

    -- Dedicated columns for key parsed fields
    srcip String DEFAULT '' CODEC(ZSTD(1)),
    dstip String DEFAULT '' CODEC(ZSTD(1)),
    srcport UInt16 DEFAULT 0 CODEC(T64, LZ4),
    dstport UInt16 DEFAULT 0 CODEC(T64, LZ4),
    proto UInt8 DEFAULT 0 CODEC(T64, LZ4),
    action LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),

    -- All other parsed fields
    parsed_data Map(String, String) CODEC(ZSTD(1)),

    -- Materialized columns for fast queries
    log_date Date MATERIALIZED toDate(timestamp),
    log_hour UInt8 MATERIALIZED toHour(timestamp),

    -- Indexes for common queries
    INDEX idx_severity severity TYPE minmax GRANULARITY 4,
    INDEX idx_srcip srcip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dstip dstip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_srcport srcport TYPE minmax GRANULARITY 4,
    INDEX idx_dstport dstport TYPE minmax GRANULARITY 4,
    INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_message message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (device_ip, timestamp)
TTL timestamp + INTERVAL 3 MONTH DELETE
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10485760,
    merge_with_ttl_timeout = 86400;

EOF
```

### 6.7 Verify ClickHouse
```bash
clickhouse-client --password password -q "SELECT 'ClickHouse is working!' AS status"
```

---

## 7. Step 4: Application Deployment

### 7.1 Clone or Copy Application
```bash
# Switch to net user
sudo su - net

# Create application directory
mkdir -p /home/net/net-logs
cd /home/net/net-logs

# If copying from another server:
# scp -r user@source-server:/home/net/net-logs/* /home/net/net-logs/

# Or clone from git:
# git clone https://github.com/your-org/netlogs.git .
```

### 7.2 Create Python Virtual Environment
```bash
cd /home/net/net-logs
python3 -m venv venv
source venv/bin/activate
```

### 7.3 Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r fastapi_app/requirements.txt
```

**requirements.txt contents:**
```
# Web Framework
fastapi>=0.104.0
uvicorn[standard]>=0.24.0

# Database - PostgreSQL
sqlalchemy>=2.0.0
asyncpg>=0.29.0
psycopg2-binary>=2.9.9

# Database - ClickHouse
clickhouse-connect>=0.7.0

# Configuration
pydantic>=2.5.0
pydantic-settings>=2.1.0
python-dotenv>=1.0.0

# Template Engine
jinja2>=3.1.2

# Utilities
python-multipart>=0.0.6
lz4>=4.3.0
zstandard>=0.22.0
pytz>=2023.3

# HTTP Client
httpx>=0.25.0

# Production Server
gunicorn>=21.2.0
```

### 7.4 Create Environment Configuration
```bash
cat > /home/net/net-logs/.env << 'EOF'
# Application Settings
DEBUG=False
SECRET_KEY=your-secure-random-key-change-this-in-production
ALLOWED_HOSTS=*

# PostgreSQL Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=netlogs
POSTGRES_USER=read
POSTGRES_PASSWORD=Read@123

# ClickHouse Database
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=password
CLICKHOUSE_DB=default

# Syslog Collector
SYSLOG_PORT=514
SYSLOG_BATCH_SIZE=5000
SYSLOG_FLUSH_INTERVAL=2.0
SYSLOG_CACHE_TTL=60
SYSLOG_WORKERS=4
SYSLOG_MAX_BUFFER=100000
SYSLOG_METRICS_INTERVAL=30

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/netlogs.log
EOF

# Secure the .env file
chmod 600 /home/net/net-logs/.env
```

### 7.5 Create Log Directory
```bash
mkdir -p /home/net/net-logs/logs
chmod 755 /home/net/net-logs/logs
```

### 7.6 Initialize PostgreSQL Schema
```bash
cd /home/net/net-logs
source venv/bin/activate

# Run Python to create tables
python3 << 'EOF'
import asyncio
from fastapi_app.db.database import init_db

asyncio.run(init_db())
print("PostgreSQL tables created successfully!")
EOF
```

### 7.7 Verify ClickHouse Table
```bash
cd /home/net/net-logs
source venv/bin/activate

python3 << 'EOF'
from fastapi_app.db.clickhouse import ClickHouseClient

ClickHouseClient.ensure_table()
print("ClickHouse table verified/created successfully!")
EOF
```

### 7.8 Test Application Startup
```bash
# Test FastAPI
cd /home/net/net-logs
source venv/bin/activate
python run_fastapi.py --port 8001 &
sleep 5
curl http://localhost:8001/api/health
kill %1

# Test Syslog Collector (requires root for port 514)
exit  # Exit net user
sudo /home/net/net-logs/venv/bin/python /home/net/net-logs/run_syslog.py &
sleep 5
sudo kill %1
```

---

## 8. Step 5: Nginx Reverse Proxy

### 8.1 Install Nginx
```bash
sudo apt install -y nginx
```

### 8.2 Create Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/netlogs
```

Add the following content:
```nginx
server {
    listen 80;
    server_name _;  # Replace with your domain or IP

    # Increase timeouts for long-running queries
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;

    # Increase buffer sizes
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /home/net/net-logs/fastapi_app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8001/api/health;
    }
}
```

### 8.3 Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/netlogs /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
```

### 8.4 Test and Restart Nginx
```bash
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

---

## 9. Step 6: Systemd Services

### 9.1 Create Syslog Collector Service
```bash
sudo nano /etc/systemd/system/netlogs-syslog.service
```

Add the following content:
```ini
[Unit]
Description=NetLogs High-Performance Syslog Collector
Documentation=https://github.com/your-org/netlogs
After=network.target postgresql.service clickhouse-server.service
Wants=postgresql.service clickhouse-server.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/home/net/net-logs
Environment="PATH=/home/net/net-logs/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="PYTHONUNBUFFERED=1"

# High-performance syslog collector with tuned parameters
ExecStart=/home/net/net-logs/venv/bin/python run_syslog.py \
    --batch-size=5000 \
    --flush-interval=2.0 \
    --cache-ttl=60 \
    --workers=4

# Graceful shutdown (allow time to flush buffers)
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM

# Restart policy
Restart=always
RestartSec=5

# Resource limits for high-volume log processing
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netlogs-syslog

[Install]
WantedBy=multi-user.target
```

### 9.2 Create Web Application Service
```bash
sudo nano /etc/systemd/system/netlogs-web.service
```

Add the following content:
```ini
[Unit]
Description=NetLogs Web Application (Gunicorn)
Documentation=https://github.com/your-org/netlogs
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=notify
User=net
Group=net
WorkingDirectory=/home/net/net-logs
Environment="PATH=/home/net/net-logs/venv/bin:/usr/local/bin:/usr/bin:/bin"

# Gunicorn with optimal settings for production
ExecStart=/home/net/net-logs/venv/bin/gunicorn fastapi_app.main:app \
    --bind 0.0.0.0:8001 \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --access-logfile - \
    --error-logfile - \
    --capture-output

ExecReload=/bin/kill -s HUP $MAINPID
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM

Restart=always
RestartSec=5

# Resource limits
LimitNOFILE=65536

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netlogs-web

[Install]
WantedBy=multi-user.target
```

### 9.3 Enable and Start Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable netlogs-syslog
sudo systemctl enable netlogs-web

# Start services
sudo systemctl start netlogs-syslog
sudo systemctl start netlogs-web

# Check status
sudo systemctl status netlogs-syslog
sudo systemctl status netlogs-web
```

---

## 10. Step 7: Firewall Configuration

### 10.1 Configure UFW
```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP (Nginx)
sudo ufw allow 80/tcp

# Allow Syslog (UDP)
sudo ufw allow 514/udp

# Allow HTTPS (optional, if using SSL)
sudo ufw allow 443/tcp

# Check status
sudo ufw status verbose
```

### 10.2 Verify Ports
```bash
# Check listening ports
sudo netstat -tulpn | grep -E ':(80|514|5432|8001|8123)'
```

Expected output:
```
tcp    0.0.0.0:80       LISTEN   nginx
tcp    0.0.0.0:8001     LISTEN   gunicorn
tcp    127.0.0.1:5432   LISTEN   postgres
tcp    127.0.0.1:8123   LISTEN   clickhouse
udp    0.0.0.0:514      LISTEN   python
```

---

## 11. Step 8: Configure Network Devices

### 11.1 FortiGate Configuration

```
# Enable syslog logging
config log syslogd setting
    set status enable
    set server "YOUR_NETLOGS_SERVER_IP"
    set port 514
    set facility local7
    set format default
end

# Configure traffic logging
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic enable
    set sniffer-traffic enable
end
```

### 11.2 Palo Alto Configuration

```
# Via CLI
set deviceconfig system log-settings syslog YOUR_SYSLOG_PROFILE server YOUR_NETLOGS_SERVER_IP
set deviceconfig system log-settings syslog YOUR_SYSLOG_PROFILE transport UDP
set deviceconfig system log-settings syslog YOUR_SYSLOG_PROFILE port 514
set deviceconfig system log-settings syslog YOUR_SYSLOG_PROFILE format BSD

# Enable log forwarding for traffic logs
set shared log-settings profiles YOUR_LOG_PROFILE match-list traffic send-to-syslog YOUR_SYSLOG_PROFILE
```

### 11.3 Generic Syslog Device

Configure your device to send syslog to:
- **Server:** YOUR_NETLOGS_SERVER_IP
- **Port:** 514
- **Protocol:** UDP
- **Format:** RFC 3164 or RFC 5424

---

## 12. Verification & Testing

### 12.1 Service Status Checks
```bash
# Check all services
sudo systemctl status netlogs-syslog netlogs-web nginx postgresql clickhouse-server

# View recent logs
sudo journalctl -u netlogs-syslog -n 50 --no-pager
sudo journalctl -u netlogs-web -n 50 --no-pager
```

### 12.2 Test Syslog Reception
```bash
# Send test syslog message
echo "<134>Dec 09 12:00:00 test-device message: Test log from $(hostname)" | nc -u -w1 localhost 514

# Check collector logs
sudo journalctl -u netlogs-syslog -n 10 --no-pager
```

### 12.3 Test Web Interface
```bash
# Check API health
curl http://localhost/api/health

# Check web interface
curl -I http://localhost/
```

### 12.4 Test Database Connections
```bash
# PostgreSQL
psql -h localhost -U read -d netlogs -c "SELECT COUNT(*) FROM devices_device;"

# ClickHouse
clickhouse-client --password password -q "SELECT COUNT(*) FROM syslogs;"
```

### 12.5 Complete System Test
1. Open browser: `http://YOUR_SERVER_IP/`
2. Navigate to Devices page: `http://YOUR_SERVER_IP/devices/`
3. Approve any pending devices
4. Navigate to Logs page: `http://YOUR_SERVER_IP/logs/`
5. Verify logs are appearing

---

## 13. Maintenance & Operations

### 13.1 Daily Operations

**Check Service Health:**
```bash
# Quick status check
sudo systemctl is-active netlogs-syslog netlogs-web nginx postgresql clickhouse-server
```

**Monitor Log Ingestion Rate:**
```bash
sudo journalctl -u netlogs-syslog -f | grep METRICS
```

### 13.2 Log Rotation

Create logrotate configuration:
```bash
sudo nano /etc/logrotate.d/netlogs
```

Add:
```
/home/net/net-logs/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 net net
    postrotate
        systemctl reload netlogs-web > /dev/null 2>&1 || true
    endscript
}
```

### 13.3 Backup Procedures

**Backup PostgreSQL:**
```bash
# Full backup
pg_dump -h localhost -U read -d netlogs > /backup/netlogs_pg_$(date +%Y%m%d).sql

# Automated daily backup (add to crontab)
0 2 * * * pg_dump -h localhost -U read -d netlogs | gzip > /backup/netlogs_pg_$(date +\%Y\%m\%d).sql.gz
```

**Backup ClickHouse:**
```bash
# Export to file
clickhouse-client --password password -q "SELECT * FROM syslogs FORMAT Native" > /backup/syslogs_$(date +%Y%m%d).native

# For large datasets, use partitions
clickhouse-client --password password -q "BACKUP TABLE syslogs TO Disk('backups', 'syslogs_backup')"
```

### 13.4 Log Retention Cleanup

Run retention cleanup script:
```bash
cd /home/net/net-logs
source venv/bin/activate
python cleanup_logs.py --execute
```

Add to crontab for automatic cleanup:
```bash
# Run daily at 3 AM
0 3 * * * cd /home/net/net-logs && ./venv/bin/python cleanup_logs.py --execute >> /home/net/net-logs/logs/cleanup.log 2>&1
```

### 13.5 Performance Monitoring

**Monitor system resources:**
```bash
htop
```

**Monitor ClickHouse:**
```bash
clickhouse-client --password password -q "SELECT * FROM system.metrics LIMIT 20"
clickhouse-client --password password -q "SELECT * FROM system.asynchronous_metrics WHERE metric LIKE '%Memory%'"
```

**Monitor disk usage:**
```bash
df -h
du -sh /var/lib/clickhouse/
```

---

## 14. Troubleshooting

### 14.1 Syslog Collector Not Receiving Logs

**Check if port 514 is listening:**
```bash
sudo netstat -ulnp | grep 514
```

**Check firewall:**
```bash
sudo ufw status
sudo iptables -L -n | grep 514
```

**Test from firewall:**
```bash
# From the firewall device
logger -n YOUR_NETLOGS_SERVER_IP -P 514 "Test message"
```

### 14.2 Web Interface Not Loading

**Check Nginx:**
```bash
sudo nginx -t
sudo systemctl status nginx
sudo journalctl -u nginx -n 50
```

**Check FastAPI:**
```bash
sudo systemctl status netlogs-web
sudo journalctl -u netlogs-web -n 50
curl http://127.0.0.1:8001/api/health
```

### 14.3 Database Connection Issues

**PostgreSQL:**
```bash
sudo systemctl status postgresql
psql -h localhost -U read -d netlogs -c "SELECT 1;"
```

**ClickHouse:**
```bash
sudo systemctl status clickhouse-server
clickhouse-client --password password -q "SELECT 1"
curl "http://localhost:8123/?query=SELECT%201"
```

### 14.4 High Memory Usage

**Check ClickHouse memory:**
```bash
clickhouse-client --password password -q "SELECT formatReadableSize(sum(memory_usage)) FROM system.processes"
```

**Optimize ClickHouse:**
```bash
clickhouse-client --password password -q "OPTIMIZE TABLE syslogs FINAL"
```

### 14.5 Slow Queries

**Check slow queries:**
```bash
clickhouse-client --password password -q "SELECT * FROM system.query_log WHERE query_duration_ms > 1000 ORDER BY event_time DESC LIMIT 10"
```

### 14.6 Service Recovery

**Restart all services:**
```bash
sudo systemctl restart netlogs-syslog netlogs-web nginx
```

**Full system restart:**
```bash
sudo systemctl restart postgresql clickhouse-server
sleep 10
sudo systemctl restart netlogs-syslog netlogs-web nginx
```

---

## 15. Complete Configuration Files

### 15.1 Directory Structure
```
/home/net/net-logs/
├── .env                          # Environment configuration
├── run_fastapi.py                # FastAPI launcher
├── run_syslog.py                 # Syslog collector launcher
├── cleanup_logs.py               # Retention cleanup script
├── venv/                         # Python virtual environment
├── logs/                         # Application logs
│   └── netlogs.log
├── fastapi_app/
│   ├── main.py                   # FastAPI application
│   ├── requirements.txt          # Python dependencies
│   ├── api/                      # API routes
│   │   ├── devices.py
│   │   ├── logs.py
│   │   └── views.py
│   ├── core/
│   │   ├── config.py             # Settings
│   │   └── logging.py
│   ├── db/
│   │   ├── database.py           # PostgreSQL connection
│   │   └── clickhouse.py         # ClickHouse client
│   ├── models/
│   │   └── device.py             # Device model
│   ├── schemas/
│   │   ├── device.py
│   │   └── logs.py
│   ├── services/
│   │   ├── syslog_collector.py   # Syslog UDP receiver
│   │   └── parsers.py            # Log parsers
│   ├── static/                   # CSS, JS, images
│   └── templates/                # Jinja2 HTML templates
└── deploy/
    ├── install.sh                # Deployment script
    ├── netlogs-syslog.service    # Systemd service
    └── netlogs-web.service       # Systemd service
```

### 15.2 Quick Deployment Script

Create `/home/net/net-logs/deploy/quick-setup.sh`:
```bash
#!/bin/bash
#
# NetLogs Quick Setup Script
# Run as root: sudo bash quick-setup.sh
#

set -e

echo "=========================================="
echo "NetLogs Quick Setup"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

PROJECT_DIR="/home/net/net-logs"

# Install systemd services
echo "[1/4] Installing systemd services..."
cp $PROJECT_DIR/deploy/netlogs-syslog.service /etc/systemd/system/
cp $PROJECT_DIR/deploy/netlogs-web.service /etc/systemd/system/

# Reload systemd
echo "[2/4] Reloading systemd..."
systemctl daemon-reload

# Enable services
echo "[3/4] Enabling services..."
systemctl enable netlogs-syslog netlogs-web

# Start services
echo "[4/4] Starting services..."
systemctl start netlogs-syslog
systemctl start netlogs-web

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Services status:"
echo "  Syslog Collector: $(systemctl is-active netlogs-syslog)"
echo "  Web Application:  $(systemctl is-active netlogs-web)"
echo ""
echo "Web Interface: http://$(hostname -I | awk '{print $1}')/"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status netlogs-syslog"
echo "  sudo systemctl status netlogs-web"
echo "  sudo journalctl -fu netlogs-syslog"
echo "  sudo journalctl -fu netlogs-web"
echo ""
```

### 15.3 Health Check Script

Create `/home/net/net-logs/healthcheck.sh`:
```bash
#!/bin/bash
#
# NetLogs Health Check Script
#

echo "NetLogs Health Check"
echo "===================="
echo ""

# Check services
echo "Services:"
for service in netlogs-syslog netlogs-web nginx postgresql clickhouse-server; do
    status=$(systemctl is-active $service 2>/dev/null || echo "not-found")
    if [ "$status" = "active" ]; then
        echo "  ✓ $service: $status"
    else
        echo "  ✗ $service: $status"
    fi
done

echo ""

# Check ports
echo "Ports:"
for port in "80:HTTP" "514:Syslog" "5432:PostgreSQL" "8001:FastAPI" "8123:ClickHouse"; do
    port_num=$(echo $port | cut -d: -f1)
    port_name=$(echo $port | cut -d: -f2)
    if netstat -tuln | grep -q ":$port_num "; then
        echo "  ✓ $port_name ($port_num): listening"
    else
        echo "  ✗ $port_name ($port_num): not listening"
    fi
done

echo ""

# Check API health
echo "API Health:"
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/api/health 2>/dev/null)
if [ "$response" = "200" ]; then
    echo "  ✓ API: healthy (HTTP $response)"
else
    echo "  ✗ API: unhealthy (HTTP $response)"
fi

echo ""

# Database stats
echo "Database Stats:"
pg_count=$(psql -h localhost -U read -d netlogs -t -c "SELECT COUNT(*) FROM devices_device;" 2>/dev/null | tr -d ' ')
ch_count=$(clickhouse-client --password password -q "SELECT COUNT(*) FROM syslogs" 2>/dev/null)
echo "  PostgreSQL devices: ${pg_count:-error}"
echo "  ClickHouse logs: ${ch_count:-error}"

echo ""
echo "Health check complete."
```

---

## Summary

This guide covers the complete A-to-Z setup of the NetLogs SOAR/SIEM platform. After following all steps, you will have:

1. **Ubuntu server** with optimized system settings
2. **PostgreSQL** database for device management
3. **ClickHouse** database for high-performance log storage
4. **Syslog Collector** receiving logs on UDP 514
5. **FastAPI Web Application** serving the UI
6. **Nginx** reverse proxy for production deployment
7. **Systemd services** for automatic startup and management

### Quick Reference Commands

```bash
# Start/Stop/Restart services
sudo systemctl start|stop|restart netlogs-syslog
sudo systemctl start|stop|restart netlogs-web

# View logs
sudo journalctl -fu netlogs-syslog
sudo journalctl -fu netlogs-web

# Check status
sudo systemctl status netlogs-syslog netlogs-web

# Health check
curl http://localhost/api/health
```

### Support URLs

- Web Interface: `http://YOUR_SERVER_IP/`
- Device Management: `http://YOUR_SERVER_IP/devices/`
- Log Search: `http://YOUR_SERVER_IP/logs/`
- API Documentation: `http://YOUR_SERVER_IP/api/docs`

---

**Document Version:** 1.0
**Last Updated:** December 2024
