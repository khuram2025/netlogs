# Zentryc Enterprise Appliance — Final Shipping Plan

**Version:** 3.0
**Date:** February 2026
**Status:** Phase 1-2 Complete, Enterprise Hardening Required
**Target:** Production-ready appliance for `docker compose up -d` deployment

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Enterprise Hardening — Security](#2-enterprise-hardening--security)
3. [Enterprise Hardening — Reliability](#3-enterprise-hardening--reliability)
4. [Enterprise Hardening — Operations](#4-enterprise-hardening--operations)
5. [Upgrade & Update Framework](#5-upgrade--update-framework)
6. [Phase 3: Automation & Response](#6-phase-3-automation--response)
7. [Phase 4: Advanced Intelligence](#7-phase-4-advanced-intelligence)
8. [Quick Wins](#8-quick-wins)
9. [Implementation Order](#9-implementation-order)
10. [Verification Checklist](#10-verification-checklist)

---

## 1. Current State Assessment

### What's Done (Phases 1-2: 27/27 tasks)

| Area | Features | Status |
|------|----------|--------|
| **Authentication** | JWT sessions, cookie-based login, account lockout (5 attempts / 15 min), remember-me | Done |
| **RBAC** | ADMIN > ANALYST > VIEWER, route-level enforcement | Done |
| **Alert Engine** | Threshold, pattern, absence, anomaly rules; 10 pre-built rules; MITRE ATT&CK mapping | Done |
| **Notifications** | Email (SMTP), Telegram, Webhook channels; 10/min rate limit per channel | Done |
| **Audit Trail** | Immutable ClickHouse audit_logs; 1-year TTL; CSV export | Done |
| **API Keys** | SHA-256 hashed keys; rate limiting 100/min; expiration; permission scopes | Done |
| **Threat Intel** | 4 built-in feeds; real-time IOC matching; auto-block EDL | Done |
| **Correlation** | Multi-stage rules; 5 pre-built; ClickHouse correlation_matches table | Done |
| **NQL Parser** | Custom query language with stats/where/sort/limit pipelines | Done |
| **Custom Dashboards** | 6 widget types (counter, gauge, bar, line, doughnut, table) | Done |
| **Saved Searches** | Save/load/share with use-count tracking | Done |
| **Setup Wizard** | 4-step first-run onboarding; auto-detection of changed passwords | Done |
| **Docker Appliance** | 5-service compose; multi-stage Dockerfile; non-root user; entrypoint | Done |

### Enterprise Readiness Score: ~80% (Sprint 2 complete)

### Critical Gaps Before Shipping

| Gap | Risk | Section | Status |
|-----|------|---------|--------|
| No HTTPS/TLS | **CRITICAL** — all traffic plaintext | 2.1 | **DONE** (Sprint 1) |
| No CSRF protection | **HIGH** — cross-site form attacks | 2.2 | **DONE** (Sprint 1) |
| No backup/restore | **CRITICAL** — unrecoverable data loss | 3.1 | **DONE** (Sprint 2) |
| No upgrade mechanism | **HIGH** — customers stuck on old versions | 5.0 | **DONE** (Sprint 2) |
| No health monitoring beyond `/api/health` | **MEDIUM** — blind to service degradation | 4.2 | **DONE** (Sprint 2) |
| Hardcoded `secure=False` on session cookies | **HIGH** — cookies sent over HTTP | 2.1 | **DONE** (Sprint 1) |
| No session invalidation on logout | **MEDIUM** — JWT valid until expiry | 2.3 | **DONE** (Sprint 1) |
| No LDAP/SSO | **MEDIUM** — manual user provisioning | 2.5 | Open |
| Single-instance only | **MEDIUM** — no HA/failover | 3.3 | Open |
| No syslog TCP/TLS | **MEDIUM** — UDP only, no encrypted log transport | 4.4 | Open |

---

## 2. Enterprise Hardening — Security

### 2.1 HTTPS / TLS Enforcement — DONE

**Priority:** CRITICAL
**Effort:** 2-3 days
**Files:** `docker/nginx.conf`, `docker-compose.yml`, `docker/nginx-entrypoint.sh`, `fastapi_app/core/auth.py`

**Tasks:**

- [x] **2.1.1** HTTPS server block in `docker/nginx.conf` — TLSv1.2+1.3, strong ciphers, HSTS, security headers
- [x] **2.1.2** Certificate volume mount (`zentryc-certs`) in `docker-compose.yml`
- [x] **2.1.3** Auto-cert generation in `docker/nginx-entrypoint.sh` (10-year self-signed if none found)
- [x] **2.1.4** Session cookie `secure` flag: `secure=not settings.debug`
- [x] **2.1.5** Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- [ ] **2.1.6** Document certificate replacement procedure (Let's Encrypt or corporate CA)

### 2.2 CSRF Protection — DONE

**Priority:** HIGH
**Effort:** 1-2 days
**Files:** `fastapi_app/core/csrf.py`, `fastapi_app/main.py`, `fastapi_app/templates/base.html`

**Tasks:**

- [x] **2.2.1** CSRF middleware (`core/csrf.py`) — double-submit cookie pattern, validates header or form field, exempts API key requests and EDL feeds
- [x] **2.2.2** Auto-inject hidden `csrf_token` field into all `<form>` elements via DOMContentLoaded JS in `base.html`, `login.html`, `wizard.html`
- [x] **2.2.3** Auto-inject `X-CSRF-Token` header into all `fetch()` calls via patched `window.fetch` in `base.html`, `login.html`, `wizard.html`

### 2.3 Session Security Improvements — PARTIALLY DONE

**Priority:** HIGH
**Effort:** 1-2 days
**Files:** `fastapi_app/core/auth.py`, `fastapi_app/api/auth.py`

**Tasks:**

- [x] **2.3.1** In-memory token revocation — on logout, `jti` added to `_revoked_tokens` dict with TTL-based cleanup every 5 min
- [x] **2.3.2** Added `jti` (UUID) claim to all JWT session tokens
- [ ] **2.3.3** Implement "Logout all sessions" admin action (increment user's `token_version`, reject tokens with old version)
- [ ] **2.3.4** Add idle timeout — expire session after 30 min of inactivity (sliding window via middleware)
- [x] **2.3.5** Password complexity: min 8 chars, uppercase, lowercase, digit — enforced via `validate_password_strength()` on all user create/update/reset/setup endpoints

### 2.4 Input Validation & Sanitization — PARTIALLY DONE

**Priority:** MEDIUM
**Effort:** 2-3 days
**Files:** `fastapi_app/schemas/auth.py`, API routes

**Tasks:**

- [x] **2.4.1** Pydantic models for security-critical endpoints: `CreateUserRequest`, `ResetPasswordRequest`, `ChangePasswordRequest`, `CreateAPIKeyRequest`, `SetupStep1Request`, `SetupStep2Request` — with regex username validation, password complexity, enum role/permission validation
- [ ] **2.4.2** Sanitize all user inputs rendered in templates (Jinja2 auto-escapes by default, but verify `|safe` usage)
- [ ] **2.4.3** Add max query length and complexity limits on NQL parser (prevent ClickHouse resource exhaustion)
- [ ] **2.4.4** Validate file uploads: max size 10MB, allowed types only (CSV, JSON, XLSX)
- [x] **2.4.5** Request body size limit in nginx: `client_max_body_size 10M`

### 2.5 LDAP / SSO Integration (Future)

**Priority:** MEDIUM
**Effort:** 1-2 weeks
**Files:** New `fastapi_app/core/ldap_auth.py`, `fastapi_app/api/auth.py`

**Tasks:**

- [ ] **2.5.1** Add LDAP configuration settings to `config.py`
  ```
  LDAP_ENABLED, LDAP_SERVER, LDAP_BASE_DN, LDAP_BIND_DN,
  LDAP_BIND_PASSWORD, LDAP_USER_FILTER, LDAP_GROUP_MAPPING
  ```
- [ ] **2.5.2** Implement LDAP authentication backend (ldap3 library)
  - Bind → search → verify credentials
  - Map LDAP groups to RBAC roles (configurable)
  - Auto-create local user on first LDAP login (JIT provisioning)
- [ ] **2.5.3** Add LDAP settings page in System → Settings (admin only)
- [ ] **2.5.4** Support SAML 2.0 / OAuth 2.0 as future extension point

### 2.6 Database Connection Security

**Priority:** MEDIUM
**Effort:** 1 day
**Files:** `docker-compose.yml`, `fastapi_app/core/config.py`, `fastapi_app/db/`

**Tasks:**

- [ ] **2.6.1** Enable SSL for PostgreSQL connections (internal Docker network is trusted, but add `sslmode=prefer`)
- [ ] **2.6.2** Create dedicated database users with minimal privileges
  - Web app: SELECT, INSERT, UPDATE, DELETE on app tables only
  - Syslog collector: INSERT only on ClickHouse syslogs
- [ ] **2.6.3** Remove default ClickHouse `default` user; create dedicated `zentryc` user with password

---

## 3. Enterprise Hardening — Reliability

### 3.1 Backup & Restore — DONE

**Priority:** CRITICAL
**Effort:** 3-4 days
**Files:** `scripts/backup.sh`, `scripts/restore.sh`, `fastapi_app/api/backup.py`, `fastapi_app/templates/system/backups.html`

**Tasks:**

- [x] **3.1.1** Create `scripts/backup.sh` — automated backup script (pg_dump + ClickHouse TSV export + config + metadata → tar.gz with retention cleanup)
- [x] **3.1.2** Create `scripts/restore.sh` — restore from backup archive (dry-run mode by default, --confirm to execute; restores PG, CH, config)
- [ ] **3.1.3** Add backup scheduling via cron or APScheduler
  - Daily full backup at 02:00 (configurable)
  - Retain last 7 daily + 4 weekly + 3 monthly backups
  - `BACKUP_ENABLED`, `BACKUP_PATH`, `BACKUP_RETENTION_DAYS` env vars
- [x] **3.1.4** Add System → Backup page (admin only) — "Backup Now" button, list with size/date, download, delete
- [ ] **3.1.5** Add backup health check — alert if last backup > 48 hours old

### 3.2 Database Migrations — DONE

**Priority:** HIGH
**Effort:** 2-3 days
**Files:** `fastapi_app/db/migrations/`, `fastapi_app/db/clickhouse_migrations/`, `fastapi_app/db/migrate.py`, `scripts/migrate.sh`, `alembic.ini`

**Tasks:**

- [x] **3.2.1** Integrate Alembic for PostgreSQL schema migrations — async engine, baseline revision, auto-upgrade on startup via subprocess, auto-stamp for fresh installs
- [x] **3.2.2** Create ClickHouse migration system — versioned Python scripts in `db/clickhouse_migrations/`, version tracked in `system_settings` table, auto-run on startup
- [x] **3.2.3** Add `scripts/migrate.sh` — supports status, upgrade, downgrade, generate, and history commands

### 3.3 High Availability Considerations

**Priority:** MEDIUM (document now, implement later)
**Effort:** Documentation 1 day, implementation 2-4 weeks

**Tasks:**

- [ ] **3.3.1** Document single-instance vs HA architecture in deployment guide
- [ ] **3.3.2** Design HA architecture (for future implementation)
  ```
  ┌─────────────────────────────────────┐
  │         Load Balancer (HAProxy)     │
  └──────┬──────────────┬──────────────┘
         │              │
  ┌──────▼──────┐ ┌────▼────────┐
  │  Web Node 1 │ │ Web Node 2  │
  └──────┬──────┘ └────┬────────┘
         │              │
  ┌──────▼──────────────▼──────┐
  │   Redis (Session Store)    │
  └──────┬─────────────────────┘
         │
  ┌──────▼───────┐ ┌──────────────────┐
  │ PostgreSQL   │ │ ClickHouse       │
  │ Primary      │ │ Cluster (2+ nodes│
  │  ↓ Replica   │ │ with replication)│
  └──────────────┘ └──────────────────┘
  ```
- [ ] **3.3.3** Move session storage to Redis (allow multi-instance web tier)
  - Add `REDIS_URL` config setting
  - JWT blacklist in Redis (shared across instances)
  - Replace in-memory rate limit tracking with Redis counters
- [ ] **3.3.4** Move scheduler coordination from file-lock to Redis distributed lock
- [ ] **3.3.5** Document syslog UDP load balancing (Linux IPVS or dedicated LB)

---

## 4. Enterprise Hardening — Operations

### 4.1 System Administration UI

**Priority:** HIGH
**Effort:** 3-5 days
**Files:** Expand `fastapi_app/api/views.py` system section, new templates

**Tasks:**

- [ ] **4.1.1** System → Settings page
  - General: platform name, timezone, default language
  - Security: password policy, session timeout, failed login threshold
  - Syslog: port, batch size, buffer limits (live reload)
  - Notifications: global enable/disable, default channel
  - Storage: retention policy, cleanup thresholds
  - LDAP: connection settings, group mappings (when 2.5 is done)
- [ ] **4.1.2** System → Services page (health dashboard)
  - PostgreSQL: connection status, pool size, disk usage
  - ClickHouse: status, table sizes, query queue
  - Syslog collector: running/stopped, current EPS, buffer fill %
  - Scheduler: job list with last run time and next scheduled run
  - Threat feeds: last fetch status per feed
- [ ] **4.1.3** System → About page
  - Current version, build date, license info
  - Component versions (Python, FastAPI, PostgreSQL, ClickHouse)
  - System uptime, last restart time

### 4.2 Health Monitoring & Metrics

**Priority:** HIGH
**Effort:** 2-3 days
**Files:** `fastapi_app/api/health.py` (new), `docker-compose.yml`

**Tasks:**

- [x] **4.2.1** Enhanced `/api/health` endpoint — returns status (healthy/degraded/unhealthy), version, uptime, per-component checks (PostgreSQL latency, ClickHouse latency + row count, scheduler job count, syslog EPS). Plus `/api/health/simple` for fast Docker/LB probes. Returns 503 when unhealthy.
- [ ] **4.2.2** Add `/api/metrics` Prometheus endpoint
  - `zentryc_events_total` (counter) — total syslog events ingested
  - `zentryc_events_per_second` (gauge) — current EPS
  - `zentryc_alerts_total` (counter by severity)
  - `zentryc_active_sessions` (gauge)
  - `zentryc_clickhouse_query_duration_seconds` (histogram)
  - `zentryc_syslog_buffer_usage` (gauge, 0-1)
  - `zentryc_db_connection_pool` (gauge)
- [ ] **4.2.3** Add internal alerts for operational issues
  - Syslog buffer > 80% → warning alert
  - Database connection failure → critical alert
  - Disk usage > 85% → warning, > 95% → critical
  - ClickHouse query timeout → warning
  - Backup overdue (> 48h) → warning

### 4.3 Log Management — PARTIALLY DONE

**Priority:** MEDIUM
**Effort:** 1-2 days
**Files:** `fastapi_app/core/logging.py`, `fastapi_app/core/config.py`, `docker-compose.yml`

**Tasks:**

- [x] **4.3.1** Structured JSON logging — `JSONFormatter` class outputs structured JSON with timestamp, level, module, message, function, line, exception. Activated via `LOG_FORMAT=json` env var.
- [x] **4.3.2** Docker log rotation configured (RotatingFileHandler 10MB x 5, Docker compose prod: 50MB x 5)
- [x] **4.3.3** Per-module log level via env vars: `LOG_LEVEL_AUTH=DEBUG`, `LOG_LEVEL_SYSLOG=WARNING` etc.
- [ ] **4.3.4** Forward application logs to ClickHouse `app_logs` table (self-monitoring)

### 4.4 Syslog TCP/TLS Support

**Priority:** MEDIUM
**Effort:** 3-5 days
**Files:** `fastapi_app/services/syslog_collector.py`, `fastapi_app/core/config.py`

**Tasks:**

- [ ] **4.4.1** Add TCP syslog listener alongside UDP
  - `SYSLOG_TCP_ENABLED=true`, `SYSLOG_TCP_PORT=6514`
  - asyncio TCP server with connection pooling
  - Handle framing (octet-counting per RFC 5425)
- [ ] **4.4.2** Add TLS support for TCP syslog
  - `SYSLOG_TLS_ENABLED=true`, `SYSLOG_TLS_CERT`, `SYSLOG_TLS_KEY`
  - TLSv1.2+ only, mutual TLS optional
- [ ] **4.4.3** Update setup wizard step 3 to show TCP/TLS instructions when enabled
- [ ] **4.4.4** Add syslog forwarding (output to another SIEM)
  - Forward parsed or raw logs to external syslog server
  - `SYSLOG_FORWARD_ENABLED`, `SYSLOG_FORWARD_HOST`, `SYSLOG_FORWARD_PORT`

### 4.5 Data Retention & Archival

**Priority:** MEDIUM
**Effort:** 2-3 days
**Files:** `fastapi_app/services/retention_service.py` (new)

**Tasks:**

- [ ] **4.5.1** Per-source retention policies
  - Different retention per device/device group (e.g., firewalls 90 days, switches 30 days)
  - Configure via System → Settings UI
- [ ] **4.5.2** Cold storage archival
  - Export old partitions to compressed files before deletion
  - Optional S3/NFS mount for archive storage
  - `ARCHIVE_ENABLED`, `ARCHIVE_PATH`, `ARCHIVE_AFTER_DAYS`
- [ ] **4.5.3** Compliance-aware retention
  - Preset profiles: PCI-DSS (1 year), HIPAA (6 years), SOX (7 years)
  - Prevent deletion of logs within compliance window

---

## 5. Upgrade & Update Framework

### 5.1 Versioning Strategy — PARTIALLY DONE

**Priority:** HIGH
**Effort:** 1-2 days

**Tasks:**

- [x] **5.1.1** Semantic versioning: `fastapi_app/__version__.py` → `__version__ = "3.0.0"`, displayed in `/api/health`, topbar, and API root
- [x] **5.1.2** `CHANGELOG.md` created at repo root with versions 3.0.0, 2.0.0, 1.0.0
- [ ] **5.1.3** Add version compatibility matrix and schema version check on startup

### 5.2 Upgrade Procedure

**Priority:** HIGH
**Effort:** 3-5 days
**Files:** New `scripts/upgrade.sh`, `fastapi_app/db/migrations/`

**Tasks:**

- [x] **5.2.1** Create `scripts/upgrade.sh` — pre-flight checks (Docker, disk space), auto-backup, image build, Alembic migration, rolling restart with health-check wait, post-upgrade verification. Supports `--skip-backup` and `--force` flags.
- [x] **5.2.2** Auto-migration on startup — `run_pg_migrations()` in lifespan checks for alembic_version table, stamps baseline for fresh installs, runs `alembic upgrade head` for existing DBs. ClickHouse migrations via `run_clickhouse_migrations()` with versioned Python scripts.
- [x] **5.2.3** Rollback procedure — `scripts/rollback.sh` stops services, restores from latest (or specified) backup via `restore.sh --confirm`, restarts services, waits for health check.
- [ ] **5.2.4** Add upgrade notification in UI
  - Check for new versions via optional update API (configurable, off by default)
  - Show banner: "Zentryc v3.1.0 is available" in admin dashboard
  - System → Settings: `UPDATE_CHECK_ENABLED=false`

### 5.3 Configuration Migration

**Priority:** MEDIUM
**Effort:** 1-2 days

**Tasks:**

- [ ] **5.3.1** Add `.env` version tracking
  - When new settings are added, upgrade script appends them with defaults
  - Never remove existing settings (backward compatible)
- [ ] **5.3.2** Warn on deprecated settings
  - Log warning if old env var names are used
  - Support old names as aliases for 2 major versions

---

## 6. Phase 3: Automation & Response

> As documented in `docs/improvement-plan/03-PHASE3-AUTOMATION-RESPONSE.md`

### 6.1 Playbook Engine

- [ ] **6.1.1** Playbook database models (name, trigger, steps JSON, enabled)
- [ ] **6.1.2** Playbook execution engine — 10+ step types:
  - Enrichment: GeoIP lookup, WHOIS, DNS reverse
  - Action: block IP (add to EDL), disable user, isolate device
  - Notification: send alert via channel
  - Condition: if/else branching
  - Control: delay, loop, approval gate
- [ ] **6.1.3** Pre-built playbooks (5):
  1. Brute Force Response — block source IP, notify admin
  2. Port Scan Response — add to watchlist, enrich with GeoIP
  3. Device Offline — check connectivity, escalate if unreachable
  4. Threat Intel Match — block IOC, create incident
  5. Data Exfiltration — quarantine source, capture evidence
- [ ] **6.1.4** Playbook UI with visual step editor

### 6.2 Incident Management

- [ ] **6.2.1** Incident model (title, severity, status, assigned_to, SLA timestamps)
- [ ] **6.2.2** Incident management UI
  - Create from alert / manual
  - Timeline view with evidence attachments
  - SLA tracking: MTTA (Mean Time to Acknowledge), MTTR (Mean Time to Resolve)
  - Status workflow: New → Triaging → Investigating → Containment → Eradication → Recovery → Closed

### 6.3 Automated Reporting

- [ ] **6.3.1** Report templates: Daily Security Summary, Weekly Executive, Monthly Compliance, Device Health
- [ ] **6.3.2** Report generation service (HTML + PDF via WeasyPrint)
- [ ] **6.3.3** Scheduled report delivery via email
- [ ] **6.3.4** Report UI: generate, preview, download, schedule

---

## 7. Phase 4: Advanced Intelligence

> As documented in `docs/improvement-plan/04-PHASE4-ADVANCED-INTELLIGENCE.md`

### 7.1 AI/ML Analytics

- [ ] **7.1.1** Behavioral baselining engine (Z-score anomaly detection per IP/subnet)
- [ ] **7.1.2** Entity risk scoring (0-100 per IP/device/subnet)
- [ ] **7.1.3** Risk dashboard widget
- [ ] **7.1.4** AI investigation assistant (Claude API integration for natural language log queries)

### 7.2 Extended Firewall Support

- [ ] **7.2.1** Cisco ASA/Firepower parser
- [ ] **7.2.2** Check Point parser
- [ ] **7.2.3** Sophos XG parser
- [ ] **7.2.4** Juniper SRX parser
- [ ] **7.2.5** Auto-detection of firewall vendor from syslog format

### 7.3 Network Topology & GeoIP

- [ ] **7.3.1** Interactive network topology visualization (vis.js/D3.js)
- [ ] **7.3.2** GeoIP enrichment (MaxMind GeoLite2)
- [ ] **7.3.3** GeoIP dashboard with world map
- [ ] **7.3.4** DNS reverse lookup service

### 7.4 Policy Intelligence

- [ ] **7.4.1** Rule usage analysis (unused/shadow rules)
- [ ] **7.4.2** Communication matrix compliance checking
- [ ] **7.4.3** Policy optimization recommendations

### 7.5 API & Integration Hub

- [ ] **7.5.1** REST API v2 with consistent response format + pagination
- [ ] **7.5.2** Syslog forwarding to external SIEMs
- [ ] **7.5.3** Webhook integration framework (inbound + outbound)

---

## 8. Quick Wins

| ID | Task | Effort | Impact | Status |
|----|------|--------|--------|--------|
| QW-01 | Add favicon (stop 404 errors) | 30 min | Low | **DONE** |
| QW-02 | Log export (CSV/JSON from log viewer) | 1 day | High | Open |
| QW-03 | GeoIP country flags on dashboard IPs | 1-2 days | Medium | Open |
| QW-04 | Device health check indicators | 2 days | High | Open |
| QW-05 | Cisco ASA parser | 2-3 days | High | Open |
| QW-06 | Bulk device approve/reject | 1 day | Medium | Open |
| QW-07 | Auto-refresh toggle on dashboards | 4 hours | Medium | Open |
| QW-08 | Session flow visualization | 2 days | Medium | Open |
| QW-09 | Keyboard shortcuts (g+d=dashboard, g+l=logs, /=search) | 1 day | Low | Open |
| QW-10 | Dark/light theme toggle | 1-2 days | Low | Open |
| QW-11 | Login page: show last login time | 2 hours | Low | Open |
| QW-12 | Add "Powered by Zentryc v3.0" footer with version | 1 hour | Low | **DONE** |

---

## 9. Implementation Order

### Sprint 1: Security Hardening (Week 1-2) — COMPLETE

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 1 | 2.1 HTTPS/TLS enforcement | CRITICAL | 2-3d | **DONE** |
| 2 | 2.2 CSRF protection | HIGH | 1-2d | **DONE** |
| 3 | 2.3 Session security (revocation, password complexity) | HIGH | 1-2d | **DONE** |
| 4 | 2.4.1 Pydantic request validation on security-critical endpoints | MEDIUM | 2d | **DONE** |
| 5 | 5.1 Version tracking + CHANGELOG | HIGH | 1d | **DONE** |
| 6 | QW-01 Favicon | LOW | 30min | **DONE** |
| 7 | QW-12 Version footer | LOW | 1hr | **DONE** |

### Sprint 2: Reliability & Backup (Week 3-4) — COMPLETE

| # | Task | Priority | Effort | Status |
|---|------|----------|--------|--------|
| 8 | 3.1 Backup & restore (scripts + UI) | CRITICAL | 3-4d | **DONE** |
| 9 | 3.2 Database migrations (Alembic + ClickHouse) | HIGH | 2-3d | **DONE** |
| 10 | 5.2 Upgrade script + auto-migration | HIGH | 3d | **DONE** |
| 11 | 4.2.1 Enhanced health endpoint | HIGH | 1d | **DONE** |
| 12 | 4.3 Structured JSON logging | MEDIUM | 1d | **DONE** |

### Sprint 3: Operations & Monitoring (Week 5-6)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 13 | 4.1 System admin UI (settings, services, about) | HIGH | 3-5d |
| 14 | 4.2.2 Prometheus metrics endpoint | HIGH | 2d |
| 15 | 4.2.3 Internal operational alerts | MEDIUM | 1d |
| 16 | 2.6 Database connection security | MEDIUM | 1d |
| 17 | QW-02 Log export | HIGH | 1d |
| 18 | QW-04 Device health indicators | HIGH | 2d |

### Sprint 4: Data Management (Week 7-8)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 19 | 4.5 Data retention & archival | MEDIUM | 2-3d |
| 20 | 4.4 Syslog TCP/TLS | MEDIUM | 3-5d |
| 21 | 2.5 LDAP/SSO integration | MEDIUM | 5-7d |
| 22 | 3.3.3 Redis session store (HA prep) | MEDIUM | 2d |

### Sprint 5-7: Phase 3 — Automation & Response (Week 9-14)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 23 | 6.1 Playbook engine + pre-built playbooks | HIGH | 2-3 weeks |
| 24 | 6.2 Incident management | HIGH | 1-2 weeks |
| 25 | 6.3 Automated reporting | MEDIUM | 1 week |

### Sprint 8-12: Phase 4 — Advanced Intelligence (Week 15-24)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 26 | 7.1 ML analytics & risk scoring | MEDIUM | 2-3 weeks |
| 27 | 7.2 Extended firewall parsers | MEDIUM | 2-3 weeks |
| 28 | 7.3 GeoIP + topology | MEDIUM | 1-2 weeks |
| 29 | 7.4 Policy intelligence | LOW | 1-2 weeks |
| 30 | 7.5 API v2 + integrations | MEDIUM | 1-2 weeks |

---

## 10. Verification Checklist

### Pre-Ship Checklist (Must Pass)

**Security:**
- [x] HTTPS enabled and enforced (nginx TLS 1.2/1.3, HSTS, auto-cert)
- [x] Session cookies have `Secure` and `HttpOnly` flags (`secure=not settings.debug`)
- [x] CSRF protection active on all forms (double-submit cookie + auto-inject JS)
- [x] Default passwords must be changed (setup wizard enforces)
- [ ] SECRET_KEY is unique per deployment (auto-generated or user-set)
- [ ] No sensitive data in Docker logs
- [x] SQL injection test: all queries parameterized (SQLAlchemy + ClickHouse params)
- [x] XSS test: Jinja2 auto-escaping + Pydantic username regex blocks injection
- [x] Rate limiting active on login endpoint (5 failed attempts → 15 min lockout)

**Reliability:**
- [x] Backup script works: creates valid backup, restore succeeds (tested: 2GB archive with PG + 10.4M syslog rows)
- [x] Upgrade script works: pre-flight checks, auto-backup, rolling restart, health verification
- [x] Rollback script works: restores from backup, restarts services
- [ ] `docker compose down && up` preserves all data (volumes)
- [ ] Server restart recovers gracefully (no data loss, cache re-warms)
- [x] Health endpoint accurately reports component status (PG, CH, scheduler, syslog with latency)

**Operations:**
- [x] `docker compose up -d` starts all services in correct order
- [x] Setup wizard appears on first run, completes successfully
- [x] Setup wizard never appears after completion
- [x] All pages accessible and functional after setup
- [x] Syslog ingestion working at > 10,000 events/min
- [x] Alert engine triggering on configured rules
- [x] Notification channels delivering alerts
- [x] Audit log capturing all admin actions

**Performance:**
- [ ] Dashboard loads in < 3 seconds
- [ ] Log search returns in < 2 seconds
- [ ] Login page loads in < 1 second
- [ ] 100 concurrent users without degradation
- [ ] Syslog sustains 100,000+ events/min without loss

**Documentation:**
- [ ] Deployment guide with all env vars documented
- [ ] Backup/restore procedure documented
- [ ] Upgrade procedure documented
- [ ] Troubleshooting guide with common issues
- [ ] API documentation accessible at `/api/docs`

---

## Architecture Reference

```
┌──────────────────────────────────────────────────────────┐
│                    NGINX (Reverse Proxy)                  │
│         HTTPS/TLS, Gzip, Security Headers, CORS         │
│                   Ports: 80 → 443                        │
└──────────────┬────────────────────────────────────────────┘
               │ :8000
    ┌──────────┴──────────┐
    │                     │
┌───▼──────────┐   ┌─────▼───────────┐
│ FastAPI Web  │   │ Syslog Collector│
│ (Uvicorn)    │   │ (AsyncIO UDP)   │
│              │   │ Port 514/UDP    │
│ • Auth/RBAC  │   │ • 6514/TCP+TLS │
│ • REST API   │   │                 │
│ • Templates  │   │ • Fortinet      │
│ • Scheduler  │   │ • Cisco ASA     │
│   (locked)   │   │ • Palo Alto     │
└───┬──────────┘   └──────┬──────────┘
    │                      │
    │    ┌─────────────────┤
    │    │                 │
┌───▼────▼─────┐   ┌──────▼──────────┐
│ PostgreSQL   │   │   ClickHouse    │
│              │   │                 │
│ • users      │   │ • syslogs       │
│ • devices    │   │ • audit_logs    │
│ • alerts     │   │ • ioc_matches   │
│ • rules      │   │ • correlation   │
│ • settings   │   │ • app_logs      │
│ • edl        │   │                 │
│ • threat     │   │ Partitioned     │
│   intel      │   │ by month,       │
│ • dashboards │   │ TTL retention   │
└──────────────┘   └─────────────────┘

Background Jobs (APScheduler, file-locked):
  ├── Alert evaluation .............. every 30s
  ├── Correlation engine ........... every 60s
  ├── Threat feed updates .......... every 30min
  ├── IOC cache refresh ............ every 5min
  ├── Auto-block EDL queue ......... every 30s
  ├── Storage monitoring ........... every 15min
  ├── Disk emergency check ......... every 5min
  ├── Routing table fetch (SSH) .... every 1hr
  ├── Zone data fetch (SSH) ........ every 1hr
  └── Backup (when enabled) ........ daily 02:00

Docker Volumes:
  ├── postgres-data    (persistent)
  ├── clickhouse-data  (persistent)
  ├── logs             (mapped)
  ├── certs            (TLS certificates)
  └── backups          (backup archives)
```

---

## Release Naming

| Version | Codename | Focus |
|---------|----------|-------|
| **3.0** | Current | Phase 1-2 complete, setup wizard, Docker appliance |
| **3.1** | Sentinel | Enterprise security hardening (TLS, CSRF, sessions) |
| **3.2** | Fortress | Backup/restore, migrations, upgrade framework |
| **3.3** | Watchtower | Operations UI, metrics, health monitoring |
| **4.0** | Vanguard | Phase 3 — Playbooks, incidents, reporting |
| **5.0** | Meridian | Phase 4 — ML, GeoIP, extended parsers, topology |

---

*This plan supersedes all previous improvement plan documents. Implementation priority: Sprints 1-2 are ship blockers, Sprints 3-4 are recommended for enterprise deployment, Sprints 5+ are feature expansions.*
