# Zentryc Enterprise Transformation — Task Tracker (FINAL)

**Created:** 2026-03-30 | **Version:** 2.0 — Hybrid Go/Python | **Total Tasks:** 58 | **Estimated Effort:** ~140 dev-days

---

## Architecture Decision

**Go** = Syslog collector, HTTP ingest, stream consumer (hot path, 200K+ EPS)
**Python/FastAPI** = Web app, API, dashboards, auth, integrations (250 endpoints, 35K LOC)
**Redis** = Bridge between Go and Python (streams, sessions, cache, queue)

## Priority Legend
- P0 = Critical (security risk, data loss, or architectural foundation)
- P1 = High (enterprise requirement, competitive parity)
- P2 = Medium (differentiation, polish)
- P3 = Future (long-term roadmap)

## Status Legend
- [ ] Not started
- [~] In progress
- [x] Completed

---

## Sprint 0: Go Collector + Foundation (Week 1-3)

> **Goal:** Replace Python syslog with Go binary. Add Redis. Fix critical DB/auth issues.
> **Parallel tracks:** Go collector development + Python foundation fixes

### Track A: Go Collector (18 days)
- [ ] **0.1** Go project scaffolding + build system — `collector/` directory, go.mod, Makefile, Dockerfile [P0, 2d]
- [ ] **0.2** UDP + TCP + TLS syslog listeners — `net.ListenPacket`, `net.Listen`, `tls.Listen` [P0, 4d]
- [ ] **0.3** Port existing parsers + 6 new vendors — Fortinet, PA, Cisco, CheckPoint, Sophos, Windows, AWS, Linux, Generic [P0, 5d]
- [ ] **0.4** Redis Streams output — `XADD zentryc:logs`, batch pipeline, retry on failure [P0, 3d]
- [ ] **0.5** Stream consumer (Redis→ClickHouse) — `XREADGROUP`, batch insert, GeoIP enrichment, XACK [P0, 3d]
- [ ] **0.8** Docker integration — Multi-stage Dockerfile, docker-compose.yml changes, remove Python syslog [P0, 1d]

### Track B: Python Foundation (4 days, parallel with Track A)
- [x] **1.1** Add Redis/Valkey service — Docker container + `core/cache.py` singleton [P0, 2d] **DONE** — Valkey 7.2.4 running, docker/redis.conf, core/cache.py singleton, wired into main.py lifespan, PING/SET/GET/XADD all tested
- [x] **1.2** Replace NullPool with QueuePool — `db/database.py`, pool_size=10, pool_pre_ping=True [P0, 1d] **DONE** — AsyncAdaptedQueuePool active, size=10, overflow=20, recycle=1800, pre_ping=True
- [x] **1.3** Replace python-jose with PyJWT — `core/auth.py`, requirements.txt [P0, 1d] **DONE** — PyJWT 2.12.1 installed, python-jose uninstalled, all encode/decode/revoke tests pass

**Sprint 0 Total: ~22 days (18 Go + 4 Python in parallel = 18 calendar days)**

---

## Sprint 1: Foundation Complete (Week 3-4)

> **Goal:** Redis sessions, Docker hardening, Prometheus, Go HTTP ingest.

- [x] **1.4** Redis-backed session store — `core/auth.py`, replace in-memory dict [P0, 2d] **DONE** — Sessions stored as `session:{jti}` in Redis with TTL (8h normal, 30d remember-me). Logout deletes key. Revoked tokens return None. Falls back to stateless JWT if Redis unavailable. All functions now async (create/decode/revoke). Callers updated in api/auth.py and api/setup.py.
- [x] **1.5** Docker Compose production hardening — secrets, read-only fs, network isolation [P0, 2d] **DONE** — Split into frontend/backend networks (backend is `internal: true`), no-new-privileges on all, cap_drop ALL on syslog, Redis read-only filesystem, tmpfs on all containers, memory limits (PG:4G CH:8G Redis:1G Web:4G Syslog:2G Nginx:512M), json-file log rotation on all. Nginx cannot reach databases directly.
- [x] **1.6** Prometheus metrics for FastAPI — `core/metrics.py`, `/metrics` endpoint [P0, 2d] **DONE** — prometheus-fastapi-instrumentator on /metrics, custom metrics: login_total, active_sessions, api_key_requests, db_query_duration, alerts_fired, syslog_eps, app_info. Prometheus v2.51 container scraping web:8000 every 15s, 30d retention. Target health: UP.
- [ ] **0.6** Go HTTP/webhook ingest receiver — `POST /api/v1/ingest`, API key auth via Redis [P1, 2d]
- [ ] **0.7** Go collector Prometheus metrics — `/metrics` on ports 9090-9092 [P1, 1d]

**Sprint 1 Total: 9 days**

---

## Sprint 2: Security Hardening (Week 5-6)

> **Goal:** MFA, better password hashing, distributed rate limiting, CSP.

- [ ] **2.1** TOTP Two-Factor Authentication — `pyotp`, QR codes, recovery codes, admin-enforceable [P0, 4d]
- [ ] **2.2** Replace passlib+bcrypt with Argon2id — transparent migration on login [P1, 2d]
- [ ] **2.3** Distributed rate limiting (Redis) — sliding window with Lua script [P1, 2d]
- [ ] **2.4** Content Security Policy headers — nonce-based CSP, no `unsafe-inline` [P1, 2d]

**Sprint 2 Total: 10 days**

---

## Sprint 3: Storage Optimization (Week 7-8)

> **Goal:** ClickHouse performance tuning, materialized views, PgBouncer.

- [x] **3.1** ClickHouse schema optimization — codecs, LowCardinality, projections, skip indexes [P1, 3d] **DONE** — Added 3 projections on syslogs (src_ip, dst_ip, device_stats), 1 on pa_threat_logs, 1 on url_logs. Added minmax skip indexes on srcport/dstport, set index on severity. All materialized. 16.5x compression ratio. Top-source query: 93ms on 1.88M rows.
- [x] **3.2** Materialized views for dashboards — `mv_hourly_stats`, `mv_top_talkers` [P1, 3d] **DONE** — 4 MVs created: mv_hourly_stats (per-device hourly), mv_top_talkers_5m (5min source IPs), mv_hourly_actions (action/severity), mv_hourly_dstport (port stats). All backfilled. Dashboard queries now hit 10-8K rows vs 2M+ raw rows.
- [x] **3.3** Add PgBouncer — transaction mode, 200 client connections, pool size 20 [P1, 2d] **DONE** — edoburu/pgbouncer with SCRAM-SHA-256 auth, transaction mode, max_client_conn=200, pool_size=20. Web and syslog route through pgbouncer:6432. Verified: queries work, 957 EPS, 0 drops.
- [ ] **3.5** Tiered data retention — hot/warm/cold/archive, legal hold [P1, 4d]

**Sprint 3 Total: 12 days**

---

## Sprint 4: Enterprise Authentication (Week 9-10)

> **Goal:** SSO and LDAP — the enterprise deal-breakers.

- [ ] **2.5** SAML 2.0 / OpenID Connect SSO — Azure AD, Okta, Google, generic IdP, JIT provisioning [P1, 6d]
- [ ] **2.6** LDAP/Active Directory integration — bind auth, group sync, LDAPS [P1, 4d]

**Sprint 4 Total: 10 days**

---

## Sprint 5: Frontend Modernization (Week 11-12)

> **Goal:** TailwindCSS build pipeline, ECharts, HTMX interactivity.

- [x] **4.1** TailwindCSS + Vite build pipeline — `package.json`, vite.config.js, static/dist/ [P1, 4d] **DONE** — Vite 6 + TailwindCSS 4 + ECharts 5.6 + HTMX 2.0. 3-stage Docker build (Node→Python→Runtime). Built assets: main.css (13KB), htmx.js (61KB), echarts.js (610KB). Zentryc dark theme for ECharts. `vite_asset()` Jinja2 helper auto-registered in all templates. z-card/z-btn/z-table component classes ready.
- [x] **4.2** Replace Chart.js with Apache ECharts — all dashboard templates [P1, 5d] **DONE** — Chart.js CDN removed from both templates (logs/dashboard.html, dashboards/view.html). 5 charts on main dashboard converted: Traffic Timeline, Severity doughnut, Realtime line, Actions bar, Protocols doughnut. Custom dashboard builder widget charts (bar/line/doughnut) also converted. Zentryc dark theme applied. Zero Chart.js references remain.
- [x] **4.3** HTMX for dynamic interactivity — infinite scroll, auto-refresh, live search [P1, 4d] **DONE** — HTMX 2.0 loaded in base.html with auto CSRF injection. Created `/partials` API router with 3 endpoints: dashboard/kpis (30s auto-refresh), logs/table (infinite scroll with `hx-trigger="revealed"`), alerts/summary. Dashboard KPIs now update via HTMX replacing old JS softRefresh.

**Sprint 5 Total: 13 days**

---

## Sprint 6: Background Processing + Observability (Week 13-14)

> **Goal:** ARQ task queue, Grafana monitoring, error handling.

- [ ] **5.1** ARQ async task queue — offload alerts, feeds, reports, backups to workers [P1, 3d]
- [ ] **6.1** Grafana operational dashboards — System, Pipeline, DB, Security, Capacity [P1, 3d]
- [ ] **6.2** Request correlation IDs — UUID4 `X-Request-ID`, inject into all logs [P1, 1d]
- [ ] **6.3** Structured error handling — consistent JSON errors, error codes, optional Sentry [P1, 2d]
- [ ] **7.1** Health check improvements — startup/liveness/readiness probes [P1, 1d]

**Sprint 6 Total: 10 days**

---

## Sprint 7: Deployment & Reliability (Week 15-16)

> **Goal:** Auto-TLS, disaster recovery, audit integrity.

- [ ] **7.2** Automated TLS via Caddy — replace Nginx, auto Let's Encrypt, HTTP/3 [P1, 2d]
- [ ] **7.5** Disaster recovery automation — S3 backup, WAL archiving, automated verification [P1, 4d]
- [ ] **B.2** Immutable audit log with hash chain — SHA-256 chain, verification endpoint [P1, 3d]

**Sprint 7 Total: 9 days**

---

## Sprint 8+: Advanced Features (Week 17+)

### Frontend Enhancements
- [ ] **4.4** Alpine.js for UI state management [P2, 3d]
- [ ] **4.5** GeoIP map visualization — ECharts world map, click-to-drill [P2, 3d]
- [ ] **4.6** Network flow Sankey diagram — zone-to-zone traffic flow [P2, 2d]
- [ ] **4.7** Real-time WebSocket log streaming — Redis pub/sub → browser [P2, 3d]

### Security Enhancements
- [ ] **2.7** Fine-grained API key permissions — scoped access per resource [P2, 3d]

### Storage Enhancements
- [ ] **3.4** ClickHouse dictionaries — PG→CH lookups for device/IOC/user enrichment [P2, 2d]

### Background Processing
- [ ] **5.2** Scheduled PDF report generation — daily/weekly/monthly via WeasyPrint [P2, 5d]
- [ ] **5.3** SOAR playbook automation — trigger→action chains, auto-block, ticketing [P2, 8d]

### Observability
- [ ] **6.4** OpenTelemetry distributed tracing — Go + Python, cross-service spans [P2, 4d]

### Deployment
- [ ] **7.3** Blue-green deployment — zero-downtime, automatic rollback [P2, 3d]
- [ ] **7.4** Horizontal scaling guide + cluster config [P2, 3d]

### Compliance & Advanced
- [ ] **B.1** Compliance dashboards — PCI-DSS, SOC2, ISO 27001, NCA ECC [P2, 5d]
- [ ] **B.4** REST API v2 — cursor pagination, field selection, consistent envelope [P2, 5d]
- [ ] **B.5** Webhook receivers — AWS SNS, Azure Event Grid, generic JSON [P2, 3d]
- [ ] **B.6** NQL query language enhancement — Lark parser, autocomplete, cost estimation [P2, 5d]
- [ ] **B.3** Multi-tenancy support — org-level isolation, RLS, query rewriting [P3, 15d]

---

## Summary by Language

### Go Development (collector/)
| Task | Description | Effort |
|------|-------------|--------|
| 0.1 | Project scaffolding | 2d |
| 0.2 | UDP + TCP + TLS listeners | 4d |
| 0.3 | 9 vendor parsers | 5d |
| 0.4 | Redis Streams output | 3d |
| 0.5 | Stream consumer + GeoIP | 3d |
| 0.6 | HTTP ingest receiver | 2d |
| 0.7 | Prometheus metrics | 1d |
| 0.8 | Docker integration | 1d |
| **Total Go** | | **21 days** |

### Python Development (fastapi_app/)
| Tasks | Description | Effort |
|-------|-------------|--------|
| 1.1-1.6 | Foundation (Redis, pools, PyJWT, sessions, Docker, Prometheus) | 10d |
| 2.1-2.7 | Security (2FA, Argon2, rate limiting, CSP, SSO, LDAP, API perms) | 23d |
| 3.1-3.5 | Storage (CH optimization, mat views, PgBouncer, retention) | 14d |
| 5.1-5.3 | Background (ARQ, reports, playbooks) | 16d |
| 6.1-6.4 | Observability (Grafana, correlation IDs, errors, OTel) | 10d |
| 7.1-7.5 | Deployment (health, Caddy, deploy, scaling, DR) | 13d |
| B.1-B.6 | Bonus (compliance, audit, multi-tenant, API v2, webhooks, NQL) | 36d |
| **Total Python** | | **122 days** |

### Frontend Development (static/, templates/)
| Tasks | Description | Effort |
|-------|-------------|--------|
| 4.1-4.7 | Frontend (Tailwind, ECharts, HTMX, Alpine, GeoIP, Sankey, WS) | 24d |

---

## Technology Changes Summary

### REMOVING
| Component | Reason |
|-----------|--------|
| `python-jose` | Unmaintained since 2022 |
| `passlib` + `bcrypt==4.0.1` | Legacy, pinning issues |
| `Chart.js` | Can't handle SIEM-scale data |
| **Python syslog collector** | GIL bottleneck at 5K EPS cap |
| **Nginx** (optional) | Replaced by Caddy for auto-HTTPS |

### ADDING — Go
| Module | Purpose |
|--------|---------|
| `github.com/redis/go-redis/v9` | Redis Streams, pub/sub |
| `github.com/ClickHouse/clickhouse-go/v2` | Native ClickHouse protocol |
| `github.com/prometheus/client_golang` | Metrics |
| `github.com/oschwald/maxminddb-golang` | GeoIP enrichment |

### ADDING — Python
| Package | Purpose | Sprint |
|---------|---------|--------|
| `PyJWT>=2.8.0` | JWT (replaces python-jose) | 0 |
| `redis[hiredis]>=5.0.0` | Cache, sessions, streams, queue | 0 |
| `prometheus-fastapi-instrumentator>=7.0.0` | HTTP metrics | 1 |
| `prometheus-client>=0.20.0` | Custom metrics | 1 |
| `argon2-cffi>=23.1.0` | Password hashing | 2 |
| `pyotp>=2.9.0` | TOTP 2FA | 2 |
| `qrcode[pil]>=7.4` | QR codes for 2FA | 2 |
| `python3-saml>=1.16.0` | SAML SSO | 4 |
| `authlib>=1.3.0` | OIDC SSO | 4 |
| `ldap3>=2.9.0` | LDAP/AD auth | 4 |
| `arq>=0.26.0` | Async task queue | 6 |
| `weasyprint>=62.0` | PDF reports | 8+ |
| `lark>=1.1.0` | NQL parser | 8+ |
| `boto3>=1.34.0` | S3 backup | 7 |

### ADDING — Frontend (Node.js)
| Package | Purpose | Sprint |
|---------|---------|--------|
| `vite@6` | Build pipeline | 5 |
| `tailwindcss@4` | CSS framework | 5 |
| `echarts@5.5` | Data visualization | 5 |
| `htmx.org@2` | Server-driven interactivity | 5 |
| `alpinejs@3` | Client-side reactivity | 8+ |

### ADDING — Docker Services
| Service | Image | Purpose | Sprint |
|---------|-------|---------|--------|
| **redis** | `valkey/valkey:8-alpine` | Cache + streams + sessions + queue | 0 |
| **collector** | `zentryc-collector:latest` (Go) | Syslog UDP/TCP/TLS | 0 |
| **consumer** | `zentryc-collector:latest` (Go) | Redis→ClickHouse inserter | 0 |
| **ingest** | `zentryc-collector:latest` (Go) | HTTP log receiver | 1 |
| **arq-worker** | `zentryc:latest` (Python) | Background task worker | 6 |
| **pgbouncer** | `edoburu/pgbouncer:1.22` | Connection pooling | 3 |
| **prometheus** | `prom/prometheus:v2.51` | Metrics collection | 1 |
| **grafana** | `grafana/grafana:11` | Monitoring dashboards | 6 |
| **caddy** | `caddy:2-alpine` | Auto-HTTPS reverse proxy | 7 |

---

## Performance Targets

| Metric | Current | After Phase 0-1 | Final Target |
|--------|---------|-----------------|--------------|
| Max EPS (sustained) | ~1,100 | **100,000+** | **200,000+** |
| Parse latency | 5-10 µs | **0.1-0.5 µs** | **0.1-0.5 µs** |
| Dashboard load | 2-5s | 2-5s | **<100ms** |
| Log search (1M rows) | 3-8s | 3-8s | **<1s** |
| Data loss on crash | Possible | **Zero** | **Zero** |
| Session persistence | Lost on restart | **Persistent** | **Persistent** |
| Auth methods | 1 | 2 (password + TOTP) | **5** |
| Supported vendors | 3 | **9** | **9+** |
| Collector image | 200 MB | **15 MB** | **15 MB** |
| Max concurrent users | ~50 | **200+** | **500+** |
| Syslog protocols | UDP only | **UDP + TCP + TLS** | **UDP + TCP + TLS + HTTP** |
| Monitoring | Health endpoint | **Prometheus** | **Prometheus + Grafana** |
| Compliance | None | None | **PCI, SOC2, ISO, NCA** |

---

## Critical Path

```
Sprint 0 ─┬─► Go Collector (0.1→0.2→0.3→0.4→0.5→0.8) ──┐
           │                                                │
           └─► Redis + PyJWT + QueuePool (1.1,1.2,1.3) ───┤
                                                            ▼
Sprint 1 ───► Sessions + Docker + Prometheus (1.4-1.6) ───►
                                                            │
Sprint 2 ───► 2FA + Argon2 + Rate Limit + CSP (2.1-2.4) ─►
                                                            │
Sprint 3 ─┬─► CH Optimization + MatViews (3.1-3.2) ───────►
           └─► PgBouncer + Retention (3.3, 3.5) ──────────►
                                                            │
Sprint 4 ───► SSO + LDAP (2.5-2.6) ──────────────────────►
                                                            │
Sprint 5 ───► Tailwind + ECharts + HTMX (4.1-4.3) ──────►
                                                            │
Sprint 6 ───► ARQ + Grafana + Error Handling (5.1,6.1-6.3)►
                                                            │
Sprint 7 ───► Caddy + DR + Audit Hash (7.2,7.5,B.2) ────►
                                                            │
Sprint 8+ ──► Advanced features (P2/P3 backlog) ─────────►
```

---

*Final version. Track progress by updating checkboxes. Review after each sprint.*
