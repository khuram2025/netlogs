# Zentryc SIEM/SOAR — Enterprise Stack Transformation Plan (FINAL)

**Date:** 2026-03-30
**Version:** 2.0 — Hybrid Go/Python Architecture
**Classification:** Internal — Engineering

---

## Executive Summary

This is the **final, definitive** plan for transforming Zentryc into an enterprise-grade SIEM platform. After evaluating Python, Go, Rust, Java, and Elixir for each component, the architecture follows a **hybrid approach**:

- **Go** — Syslog collector, HTTP ingest receiver, stream consumer (hot path, 200K+ EPS)
- **Python/FastAPI** — Web application, API, dashboards, auth, integrations (250 endpoints, 35K LOC)
- **Redis/Valkey** — Bridge between Go and Python layers (streams, sessions, cache, queue)

This is what Splunk (C++ + Python), Wazuh (C + Python), and CrowdSec (Go) do. Hot path in compiled language, app layer in productive language.

**8 phases, 58 tasks, ~140 dev-days estimated.**

---

## Table of Contents

1. [Final Technology Stack](#1-final-technology-stack)
2. [Architecture (Before/After)](#2-architecture-beforeafter)
3. [Phase 0: Go Syslog Collector Rewrite](#phase-0-go-syslog-collector-rewrite)
4. [Phase 1: Foundation — Redis, DB Fixes, Security Libs](#phase-1-foundation--redis-db-fixes-security-libs)
5. [Phase 2: Security — Enterprise Auth & Access](#phase-2-security--enterprise-auth--access)
6. [Phase 3: Pipeline & Storage — ClickHouse Optimization](#phase-3-pipeline--storage--clickhouse-optimization)
7. [Phase 4: Frontend — Modern Data Visualization](#phase-4-frontend--modern-data-visualization)
8. [Phase 5: Background Processing & Task Queue](#phase-5-background-processing--task-queue)
9. [Phase 6: Observability, Monitoring & Reliability](#phase-6-observability-monitoring--reliability)
10. [Phase 7: Deployment, HA & Scalability](#phase-7-deployment-ha--scalability)
11. [Bonus Phase: Compliance & Advanced Features](#bonus-phase-compliance--advanced-features)
12. [Full Task List with Sprint Schedule](#full-task-list)
13. [Dependencies Summary](#dependencies-summary)

---

## 1. Final Technology Stack

### Decided Stack (Post-Evaluation)

| Layer | Technology | Language | Status | Why This Is Best |
|-------|-----------|----------|--------|-----------------|
| **Log Collector** | Custom binary | **Go** | NEW | 200K+ EPS, true parallel parsing, no GIL, 15MB binary |
| **HTTP Ingest** | Custom binary | **Go** | NEW | Same codebase as collector, handles webhook/agent input |
| **Stream Consumer** | Custom binary | **Go** | NEW | Redis Streams → ClickHouse batch inserter |
| **Message Buffer** | Redis Streams / Valkey 8 | — | NEW | Persistent, replay, consumer groups, crash recovery |
| **Log Storage** | ClickHouse 24+ | — | KEEP | Best analytical DB. 100-1000x faster than Elasticsearch |
| **Relational DB** | PostgreSQL 16+ | — | KEEP | Best relational DB. JSONB, RLS, partitioning |
| **Connection Pool** | PgBouncer 1.22 | — | NEW | Connection multiplexing across all workers |
| **Cache/Sessions** | Redis / Valkey 8 | — | NEW | Sessions, rate limits, cache, pub/sub, task queue |
| **Web Framework** | FastAPI | **Python** | KEEP | Best async Python framework, 250 endpoints already built |
| **ORM** | SQLAlchemy 2.0 | **Python** | KEEP | Best ORM in any language |
| **Templates** | Jinja2 | **Python** | KEEP | Powerful inheritance + macros |
| **Background Tasks** | ARQ | **Python** | NEW | Async Redis queue, lightweight |
| **Scheduler** | APScheduler | **Python** | KEEP | Cron-like triggers (enqueues to ARQ) |
| **JWT** | PyJWT 2.x | **Python** | REPLACE | Replaces unmaintained python-jose |
| **Password Hash** | argon2-cffi | **Python** | REPLACE | Replaces passlib+bcrypt. OWASP #1 |
| **SSO** | Authlib + python3-saml | **Python** | NEW | OIDC + SAML for enterprise |
| **2FA** | pyotp | **Python** | NEW | TOTP standard |
| **LDAP** | ldap3 | **Python** | NEW | Active Directory integration |
| **Frontend JS** | HTMX 2 + Alpine.js 3 | **JS** | NEW | Server-driven, minimal complexity |
| **Charts** | Apache ECharts 5.5 | **JS** | REPLACE | Replaces Chart.js. 1M+ data points, SIEM-grade |
| **CSS** | TailwindCSS 4 (via Vite) | **CSS** | NEW | Utility-first, consistent design system |
| **Reverse Proxy** | Caddy 2 or Nginx | — | UPGRADE | Auto-HTTPS (Caddy) or WAF rules (Nginx) |
| **Monitoring** | Prometheus + Grafana | — | NEW | Industry standard observability |
| **Tracing** | OpenTelemetry | — | NEW | CNCF distributed tracing standard |

### What We're Removing

| Package | Reason |
|---------|--------|
| `python-jose` | Unmaintained since 2022 — replaced by PyJWT |
| `passlib` + `bcrypt==4.0.1` | Legacy pinning nightmare — replaced by argon2-cffi |
| `Chart.js` | Can't handle SIEM-scale data — replaced by Apache ECharts |
| **Python syslog collector** | GIL-bottlenecked parsing — replaced by Go binary |

---

## 2. Architecture (Before/After)

### BEFORE (Current — All Python)
```
Firewalls ──UDP:514──► Python Syslog Collector
                        │ (in-memory deque, GIL-serialized parsing)
                        │
              ┌─────────┴──────────┐
              ▼                    ▼
         PostgreSQL           ClickHouse
         (NullPool)           (direct insert)
              │                    │
              └─────────┬──────────┘
                        ▼
                   FastAPI Web
                   (sessions in-memory)
                        │
                   Nginx (self-signed)
```

### AFTER (Enterprise — Hybrid Go/Python)
```
┌──────────────────────────────────────────────────────────┐
│                      GO DATA PLANE                        │
│                                                           │
│  Firewalls ──UDP:514──┐                                  │
│  Firewalls ──TCP:601──┤  Go Syslog Collector             │
│  Firewalls ──TLS:6514─┘  • True parallel goroutines      │
│                           • 200K+ EPS capacity            │
│  Agents ───HTTP POST──►  Go HTTP Ingest Receiver         │
│  Cloud ────Webhook────►   • API key auth via Redis        │
│                           • Rate limiting via Redis       │
│                  │                                        │
│                  ▼ XADD                                   │
│  ┌────────────────────────────────────────────────┐      │
│  │           Redis / Valkey 8                      │      │
│  │  • Log Streams (persistent, crash-safe)        │      │
│  │  • Sessions    • Cache    • Rate limits        │      │
│  │  • Pub/Sub (real-time)   • Task queue (ARQ)    │      │
│  └────────────────┬───────────────────────────────┘      │
│                   │ XREADGROUP                            │
│                   ▼                                       │
│  Go Stream Consumer ──batch insert──► ClickHouse 24+     │
│  • Consumer groups for parallel insert                    │
│  • XACK after successful insert                          │
│  • Retry failed batches automatically                    │
│  • GeoIP enrichment (maxminddb-golang)                   │
│  • Prometheus metrics                                    │
└──────────────────────────────────────────────────────────┘
                        │
┌──────────────────────────────────────────────────────────┐
│                    PYTHON APP PLANE                        │
│                                                           │
│  ┌────────────────────────────────────────────────┐      │
│  │          FastAPI Web Application                │      │
│  │  • 250 API endpoints (existing)                │      │
│  │  • 42 Jinja2 templates + HTMX + Alpine.js      │      │
│  │  • SQLAlchemy ORM (32 models)                  │      │
│  │  • PyJWT + Argon2id + TOTP 2FA                 │      │
│  │  • SAML/OIDC/LDAP SSO                         │      │
│  │  • Redis sessions + distributed rate limiting   │      │
│  │  • Apache ECharts dashboards                   │      │
│  │  • TailwindCSS (Vite build)                    │      │
│  └────────────────────────────────────────────────┘      │
│                                                           │
│  ┌────────────────────────────────────────────────┐      │
│  │          ARQ Workers (Python)                   │      │
│  │  • Alert rule evaluation                       │      │
│  │  • Threat feed updates                         │      │
│  │  • PDF report generation                       │      │
│  │  • Backup/restore                              │      │
│  │  • Email/Telegram/Webhook notifications        │      │
│  │  • SOAR playbook execution                     │      │
│  └────────────────────────────────────────────────┘      │
│                                                           │
│  PostgreSQL 16 ◄──PgBouncer──► FastAPI + ARQ Workers     │
└──────────────────────────────────────────────────────────┘
                        │
┌──────────────────────────────────────────────────────────┐
│  Caddy 2 (Auto-HTTPS, HTTP/3) or Nginx + WAF            │
├──────────────────────────────────────────────────────────┤
│  Prometheus ──► Grafana (Operational Monitoring)          │
└──────────────────────────────────────────────────────────┘

Frontend: Jinja2 SSR + HTMX + Alpine.js + TailwindCSS + Apache ECharts
```

---

## Phase 0: Go Syslog Collector Rewrite

**Goal:** Replace Python syslog collector with Go binary. 200K+ EPS, true parallel parsing, zero data loss via Redis Streams.

**Why this is Phase 0:** Everything else depends on the Go collector + Redis Streams pipeline. This is the architectural foundation.

### Task 0.1: Go Project Scaffolding & Build System
- **Priority:** P0 — Critical
- **Effort:** 2 days
- **Deliverable:** `collector/` directory with Go module, Makefile, Dockerfile
- **Structure:**
  ```
  collector/
  ├── cmd/
  │   ├── collector/main.go      # Syslog collector entry point
  │   ├── ingest/main.go         # HTTP ingest receiver entry point
  │   └── consumer/main.go       # Stream-to-ClickHouse consumer entry point
  ├── internal/
  │   ├── parser/
  │   │   ├── parser.go          # Parser interface
  │   │   ├── fortinet.go        # Fortinet FortiGate parser
  │   │   ├── paloalto.go        # Palo Alto Networks parser
  │   │   ├── cisco.go           # Cisco ASA/FTD parser
  │   │   ├── checkpoint.go      # Check Point parser
  │   │   ├── generic.go         # Generic syslog parser
  │   │   └── registry.go        # Parser auto-detection
  │   ├── buffer/
  │   │   ├── redis_stream.go    # Redis Streams XADD/XREADGROUP
  │   │   └── batch.go           # Batch accumulation logic
  │   ├── enrichment/
  │   │   ├── geoip.go           # MaxMind GeoIP lookups
  │   │   └── pipeline.go        # Enrichment chain
  │   ├── metrics/
  │   │   └── prometheus.go      # Prometheus counters/histograms
  │   ├── clickhouse/
  │   │   └── inserter.go        # Batch ClickHouse insertion
  │   └── config/
  │       └── config.go          # Environment variable configuration
  ├── go.mod
  ├── go.sum
  ├── Makefile
  └── Dockerfile                  # Multi-stage: build + scratch/alpine
  ```
- **Go modules:**
  ```
  github.com/redis/go-redis/v9
  github.com/ClickHouse/clickhouse-go/v2
  github.com/prometheus/client_golang
  github.com/oschwald/maxminddb-golang
  ```
- **Docker image:** Multi-stage build → `FROM scratch` (or alpine for TLS certs). ~15 MB final image.

### Task 0.2: UDP + TCP + TLS Syslog Listeners (Go)
- **Priority:** P0 — Critical
- **Effort:** 4 days
- **Implementation:**
  - **UDP** (port 514): `net.ListenPacket("udp", ":514")` with 26 MB socket buffer
  - **TCP** (port 601): `net.Listen("tcp", ":601")` with goroutine-per-connection
  - **TLS** (port 6514): `tls.Listen()` with configurable cert/key (RFC 5425)
  - All listeners push raw bytes + source IP to a shared Go channel
  - Channel buffer: 500K entries (matches current deque max)
  - Graceful shutdown: drain channel before exit
- **Performance advantage over Python:**
  - UDP: `ReadFromUDP()` is faster than asyncio datagram_received (no event loop overhead)
  - TCP: One goroutine per connection (Go handles 100K+ goroutines, Python can't)
  - TLS: Go's `crypto/tls` is stdlib, no external dependency, highly optimized
- **Ports to expose:** 514/UDP, 601/TCP, 6514/TCP (TLS)

### Task 0.3: Log Parsers in Go (Port Existing + Add New)
- **Priority:** P0 — Critical
- **Effort:** 5 days
- **Port from Python:**
  1. **Fortinet FortiGate** — Key-value regex (`regexp.MustCompile`, compiled once)
  2. **Palo Alto Networks** — CSV split + field mapping
  3. **Generic Syslog** — RFC 5424 priority extraction
- **Add new (Go-native):**
  4. **Cisco ASA/FTD** — `%ASA-` prefix pattern matching
  5. **Check Point** — LEA format key-value parsing
  6. **Sophos XG/XGS** — Key-value with nested fields
  7. **Windows Event Log** — JSON/XML parsing (via NXLog/Winlogbeat output)
  8. **AWS VPC Flow Logs** — Space-delimited fixed-field format
  9. **Linux auditd** — Key-value with type= prefix
- **Parser interface:**
  ```go
  type Parser interface {
      Parse(raw []byte) (map[string]string, error)
      Name() string
      Detect(raw []byte) bool  // Auto-detection
  }
  ```
- **Performance:** Go's `regexp` is RE2-based (guaranteed linear time, no catastrophic backtracking). Combined with goroutine parallelism, expect 10-50x throughput improvement.
- **Parser registry:** Auto-detect format from first few bytes if device has no configured parser.

### Task 0.4: Redis Streams Output (Go → Redis)
- **Priority:** P0 — Critical
- **Effort:** 3 days
- **Architecture:**
  ```
  Listener goroutines → parser goroutine pool → Redis XADD
  ```
- **Implementation:**
  - Parse raw log in goroutine pool (GOMAXPROCS workers)
  - Batch parsed logs (configurable: 1000 logs or 500ms, whichever first)
  - `XADD zentryc:logs MAXLEN ~10000000 * field1 value1 field2 value2 ...`
  - Pipeline multiple XADDs in single Redis round-trip
  - On Redis failure: local buffer (bounded channel) + retry with backoff
- **Stream configuration:**
  - Stream name: `zentryc:logs`
  - Max length: ~10M entries (MAXLEN approximate trimming)
  - Consumer group: `zentryc-consumers`
- **Shared with Python:** ARQ workers and FastAPI can also read from Redis (for real-time WebSocket streaming, alert evaluation, etc.)

### Task 0.5: Go Stream Consumer (Redis → ClickHouse)
- **Priority:** P0 — Critical
- **Effort:** 3 days
- **Purpose:** Separate binary that reads from Redis Streams and batch-inserts into ClickHouse.
- **Why separate:** Decouples ingestion rate from insertion rate. ClickHouse can be slow/down without affecting collection.
- **Implementation:**
  - `XREADGROUP GROUP zentryc-consumers consumer-1 COUNT 5000 BLOCK 2000 STREAMS zentryc:logs >`
  - Parse stream entries into ClickHouse column arrays
  - Batch insert via `clickhouse-go` (native protocol, faster than HTTP)
  - `XACK` after successful insert
  - Failed entries: NACK → automatic retry on next read
  - Multiple consumers for horizontal scaling (consumer-1, consumer-2, ...)
- **Enrichment (in consumer, not collector):**
  - GeoIP lookup for srcip/dstip (maxminddb-golang, O(1) mmap lookup)
  - IOC matching via Redis SET lookups
  - Device hostname resolution via Redis HASH
- **Metrics:** Insert rate, batch size, lag (pending entries), error rate

### Task 0.6: HTTP/Webhook Ingest Receiver (Go)
- **Priority:** P1 — High
- **Effort:** 2 days
- **Endpoints:**
  - `POST /api/v1/ingest` — JSON array of structured log events
  - `POST /api/v1/ingest/raw` — Raw syslog lines (one per line)
  - `POST /api/v1/ingest/json` — Single JSON event
- **Auth:** API key validation via Redis HASH lookup (shared with Python API keys)
- **Rate limiting:** Redis sliding window (shared counters with Python)
- **Output:** Same Redis Stream as syslog collector
- **Why Go for this:** High-throughput webhook receiver. Agents/cloud services may POST thousands of events per second.

### Task 0.7: Collector Prometheus Metrics (Go)
- **Priority:** P1 — High
- **Effort:** 1 day
- **Metrics endpoint:** `GET /metrics` on port 9090 (collector), 9091 (consumer), 9092 (ingest)
- **Metrics:**
  ```
  zentryc_collector_received_total{protocol="udp|tcp|tls",parser="fortinet|paloalto|..."}
  zentryc_collector_parsed_total{parser="...",status="ok|error"}
  zentryc_collector_dropped_total{reason="overflow|parse_error|redis_error"}
  zentryc_collector_buffer_size
  zentryc_collector_parse_duration_seconds{parser="..."}  (histogram)
  zentryc_collector_eps  (gauge)
  zentryc_consumer_inserted_total
  zentryc_consumer_insert_duration_seconds  (histogram)
  zentryc_consumer_batch_size  (histogram)
  zentryc_consumer_lag  (gauge — pending stream entries)
  zentryc_ingest_received_total{format="json|raw"}
  zentryc_ingest_auth_failures_total
  ```

### Task 0.8: Docker Integration for Go Services
- **Priority:** P0 — Critical
- **Effort:** 1 day
- **Dockerfiles:**
  - `collector/Dockerfile` — Multi-stage: `golang:1.22-alpine` build → `alpine:3.19` runtime
  - Final image: ~15 MB (vs 200 MB Python image)
  - Three binaries: `collector`, `consumer`, `ingest` (build all in one Dockerfile)
- **docker-compose.yml changes:**
  ```yaml
  collector:
    build:
      context: ./collector
      dockerfile: Dockerfile
    command: collector
    ports:
      - "${SYSLOG_UDP_PORT:-514}:514/udp"
      - "${SYSLOG_TCP_PORT:-601}:601"
      - "${SYSLOG_TLS_PORT:-6514}:6514"
    depends_on:
      redis: { condition: service_healthy }
    cap_add: [NET_BIND_SERVICE]
    environment:
      - REDIS_URL=redis://redis:6379
      - METRICS_PORT=9090

  consumer:
    build:
      context: ./collector
      dockerfile: Dockerfile
    command: consumer
    depends_on:
      redis: { condition: service_healthy }
      clickhouse: { condition: service_healthy }
    environment:
      - REDIS_URL=redis://redis:6379
      - CLICKHOUSE_URL=clickhouse://clickhouse:9000
      - METRICS_PORT=9091

  ingest:
    build:
      context: ./collector
      dockerfile: Dockerfile
    command: ingest
    ports:
      - "${INGEST_PORT:-8081}:8081"
    depends_on:
      redis: { condition: service_healthy }
    environment:
      - REDIS_URL=redis://redis:6379
      - METRICS_PORT=9092
  ```
- **Remove:** Python syslog service from docker-compose.yml
- **Remove:** `run_syslog.py`, syslog-related code from `services/syslog_collector.py` (keep parser tests for reference during port)

---

## Phase 1: Foundation — Redis, DB Fixes, Security Libs

**Goal:** Add Redis, fix PostgreSQL connection pool, replace insecure libraries. These are prerequisites for everything else.

### Task 1.1: Add Redis/Valkey Service
- **Priority:** P0 — Critical
- **Effort:** 2 days
- **Add:** Valkey 8 (or Redis 7) container
- **Use cases:** Sessions, rate limiting, cache, pub/sub, log streams, task queue
- **Configuration:** `maxmemory 512mb`, `appendonly yes` (AOF for streams persistence), `save 60 1000`
- **Python dependency:** `redis[hiredis]>=5.0.0`
- **Files to create:** `fastapi_app/core/cache.py` (Redis client singleton), `docker/redis.conf`
- **Files to modify:** `docker-compose.yml`, `requirements.txt`, `fastapi_app/core/config.py`

### Task 1.2: Replace NullPool with QueuePool
- **Priority:** P0 — Critical
- **Effort:** 1 day
- **Current:** `NullPool` — new TCP connection per request
- **Replace:** `AsyncAdaptedQueuePool` with `pool_size=10, max_overflow=20, pool_pre_ping=True, pool_recycle=1800`
- **Files to modify:** `fastapi_app/db/database.py`

### Task 1.3: Replace python-jose with PyJWT
- **Priority:** P0 — Critical
- **Effort:** 1 day
- **Why:** python-jose unmaintained since 2022. PyJWT is actively maintained, 50M+ downloads/month.
- **Files to modify:** `fastapi_app/core/auth.py`, `requirements.txt`

### Task 1.4: Redis-Backed Session Store
- **Priority:** P0 — Critical
- **Effort:** 2 days
- **Replace:** In-memory dict → Redis. `SET session:{jti} {user_data} EX {ttl}` on login. `DEL` on logout. Survives restarts, shared across workers.
- **Files to modify:** `fastapi_app/core/auth.py`, `fastapi_app/core/cache.py`

### Task 1.5: Docker Compose Production Hardening
- **Priority:** P0 — Critical
- **Effort:** 2 days
- **Enhancements:** Docker secrets for passwords, `read_only: true` + tmpfs, `no-new-privileges: true`, network isolation (frontend/backend/monitoring networks), resource limits on all services.
- **Files to modify:** `docker-compose.yml`, `docker-compose.prod.yml`

### Task 1.6: Prometheus Metrics for FastAPI
- **Priority:** P0 — Critical
- **Effort:** 2 days
- **Add:** `/metrics` endpoint via `prometheus-fastapi-instrumentator`. Metrics: HTTP latency, DB query count, cache hit ratio, active sessions, EPS.
- **Python dependency:** `prometheus-fastapi-instrumentator>=7.0.0`, `prometheus-client>=0.20.0`
- **Files to create:** `fastapi_app/core/metrics.py`
- **Files to modify:** `fastapi_app/main.py`

---

## Phase 2: Security — Enterprise Auth & Access

**Goal:** Enterprise SSO, MFA, zero-trust session management.

### Task 2.1: TOTP Two-Factor Authentication
- **Priority:** P0 — Critical
- **Effort:** 4 days
- **Add:** TOTP via `pyotp>=2.9.0`, QR code via `qrcode[pil]>=7.4`. Recovery codes (10 one-time-use). Admin-enforceable for all users.
- **Files to create:** `fastapi_app/api/two_factor.py`, `fastapi_app/templates/auth/two_factor_setup.html`, `fastapi_app/templates/auth/two_factor_verify.html`
- **Files to modify:** `fastapi_app/core/auth.py`, `fastapi_app/models/user.py`, `fastapi_app/api/auth.py`

### Task 2.2: Replace passlib+bcrypt with Argon2id
- **Priority:** P1 — High
- **Effort:** 2 days
- **Why:** Argon2id = OWASP #1, memory-hard, no pinning issues. Transparent migration: verify old bcrypt hashes on login, re-hash with Argon2id.
- **Files to modify:** `fastapi_app/core/auth.py`, `requirements.txt`

### Task 2.3: Distributed Rate Limiting (Redis)
- **Priority:** P1 — High
- **Effort:** 2 days
- **Replace:** In-memory per-process counter → Redis sliding window with Lua script.
- **Files to create:** `fastapi_app/core/rate_limiter.py`
- **Files to modify:** `fastapi_app/core/auth.py`, `fastapi_app/api/auth.py`

### Task 2.4: Content Security Policy Headers
- **Priority:** P1 — High
- **Effort:** 2 days
- **Add:** Nonce-based CSP. Generate nonce per request, inject into templates for script/style tags.
- **Files to modify:** `fastapi_app/core/csrf.py`, `fastapi_app/templates/base.html`

### Task 2.5: SAML 2.0 / OpenID Connect SSO
- **Priority:** P1 — High (Enterprise deal-blocker)
- **Effort:** 6 days
- **Add:** SAML via `python3-saml>=1.16.0`, OIDC via `authlib>=1.3.0`. Support Azure AD, Okta, Google Workspace, generic IdP. JIT user provisioning. Role mapping from IdP groups.
- **Files to create:** `fastapi_app/core/sso.py`, `fastapi_app/api/sso.py`, `fastapi_app/templates/auth/sso_config.html`
- **Files to modify:** `fastapi_app/api/auth.py`, `fastapi_app/models/user.py`, `fastapi_app/core/config.py`

### Task 2.6: LDAP/Active Directory Integration
- **Priority:** P1 — High
- **Effort:** 4 days
- **Add:** LDAP bind auth via `ldap3>=2.9.0`. Group sync every 15 min. Nested group resolution. LDAPS support.
- **Files to create:** `fastapi_app/core/ldap_auth.py`, `fastapi_app/templates/system/ldap_config.html`

### Task 2.7: Fine-Grained API Key Permissions
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Enhance:** Scoped permissions: `logs:read`, `devices:write`, `alerts:acknowledge`, `ingest:write`, `admin:*`, etc.
- **Files to modify:** `fastapi_app/core/auth.py`, `fastapi_app/core/permissions.py`, `fastapi_app/api/api_keys.py`

---

## Phase 3: Pipeline & Storage — ClickHouse Optimization

**Goal:** Sub-100ms dashboard queries, 30-50% less storage, automated retention.

### Task 3.1: ClickHouse Schema Optimization
- **Priority:** P1 — High
- **Effort:** 3 days
- **Optimize:**
  - Column codecs: `DateTime64 CODEC(Delta, ZSTD(3))` for timestamps
  - `LowCardinality` on action, severity, device_ip, protocol, app (90% compression)
  - Materialized columns: `toDate(timestamp)` for partition pruning
  - Projection: `ORDER BY (srcip, timestamp)` for source-based queries
  - Skip indexes: `minmax` on ports, `set(100)` on action values
- **Expected:** 2-5x faster queries, 30-50% less storage
- **Files to modify:** `fastapi_app/db/clickhouse.py`, `fastapi_app/db/clickhouse_migrations/`

### Task 3.2: ClickHouse Materialized Views for Dashboards
- **Priority:** P1 — High
- **Effort:** 3 days
- **Add:** Pre-aggregated views: `mv_hourly_stats` (SummingMergeTree), `mv_top_talkers` (AggregatingMergeTree), `mv_severity_timeline`. Dashboard queries from 2-5s → <100ms.
- **Files to create:** `fastapi_app/db/clickhouse_migrations/005_materialized_views.py`

### Task 3.3: Add PgBouncer
- **Priority:** P1 — High
- **Effort:** 2 days
- **Add:** PgBouncer container in transaction mode. Max 200 client connections, pool size 20.
- **Files to create:** `docker/pgbouncer.ini`, `docker/pgbouncer-userlist.txt`
- **Files to modify:** `docker-compose.yml`, `fastapi_app/core/config.py`

### Task 3.4: ClickHouse Dictionaries
- **Priority:** P2 — Medium
- **Effort:** 2 days
- **Add:** External dictionaries from PostgreSQL: `dict_devices`, `dict_iocs`, `dict_users`. O(1) enrichment lookups in ClickHouse.
- **Files to create:** `fastapi_app/db/clickhouse_migrations/006_dictionaries.py`

### Task 3.5: Tiered Data Retention
- **Priority:** P1 — High
- **Effort:** 4 days
- **Add:** Hot (0-30d, SSD) → Warm (30-90d, HDD) → Cold (90-365d, aggregated) → Archive (365+, S3/MinIO). Legal hold flag.
- **Files to create:** `fastapi_app/services/retention_manager.py`, `fastapi_app/db/clickhouse_migrations/007_storage_policies.py`

---

## Phase 4: Frontend — Modern Data Visualization

**Goal:** Sub-second dashboard loads, 1M+ data points, professional SIEM UI.

### Task 4.1: TailwindCSS + Vite Build Pipeline
- **Priority:** P1 — High
- **Effort:** 4 days
- **Add:** `package.json` + `vite.config.js` + `tailwind.config.js`. Build output: `static/dist/`. Migrate templates incrementally.
- **Files to create:** `package.json`, `vite.config.js`, `tailwind.config.js`, `postcss.config.js`, `static/src/main.css`
- **Files to modify:** `fastapi_app/templates/base.html`, `Dockerfile`

### Task 4.2: Replace Chart.js with Apache ECharts
- **Priority:** P1 — High
- **Effort:** 5 days
- **Why:** ECharts handles 1M+ data points. Built-in heatmaps, Sankey diagrams, geo maps, treemaps, graph networks. Dark theme. Data zoom.
- **Files to create:** `static/src/charts/index.js`, `static/src/charts/themes.js`
- **Files to modify:** All dashboard templates

### Task 4.3: HTMX for Dynamic Interactivity
- **Priority:** P1 — High
- **Effort:** 4 days
- **Add:** HTMX 2.x. Infinite scroll for logs, auto-refresh dashboards, live search, modal content loading, form submission without redirect.
- **Files to modify:** `fastapi_app/templates/base.html`, all interactive templates

### Task 4.4: Alpine.js for Client-Side Reactivity
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Add:** Alpine.js 3.x for dropdowns, tabs, modals, form validation, dark/light toggle.
- **Files to modify:** `fastapi_app/templates/base.html`, interactive templates

### Task 4.5: GeoIP Map Visualization
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Add:** ECharts world map showing attack sources/destinations. Heat intensity by event count. Click-to-drill.
- **Requires:** Go collector GeoIP enrichment (Task 0.5) + ECharts (Task 4.2)
- **Files to create:** `fastapi_app/templates/dashboards/geo_map.html`, `fastapi_app/api/geo_analytics.py`

### Task 4.6: Network Flow Sankey Diagram
- **Priority:** P2 — Medium
- **Effort:** 2 days
- **Add:** ECharts Sankey: Source Zone → Source IP → Dest IP → Dest Zone → Action
- **Files to create:** `fastapi_app/templates/dashboards/flow_diagram.html`

### Task 4.7: Real-Time WebSocket Log Streaming
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Add:** FastAPI WebSocket at `/ws/logs`. Go collector publishes to Redis pub/sub → WebSocket pushes to browser.
- **Files to create:** `fastapi_app/api/websocket.py`
- **Files to modify:** `fastapi_app/templates/logs/log_list.html`

---

## Phase 5: Background Processing & Task Queue

**Goal:** Distributed task execution, reliable scheduling, horizontal scaling.

### Task 5.1: ARQ Async Task Queue
- **Priority:** P1 — High
- **Effort:** 3 days
- **Add:** ARQ for distributed task execution. Offload: alert evaluation, feed updates, reports, backups, SSH polling, notifications.
- **New dependency:** `arq>=0.26.0`
- **Files to create:** `fastapi_app/services/task_worker.py`, `fastapi_app/services/tasks/`
- **Files to modify:** `fastapi_app/services/scheduler.py`, `docker-compose.yml` (add arq-worker service)

### Task 5.2: Scheduled PDF Report Generation
- **Priority:** P2 — Medium
- **Effort:** 5 days
- **Add:** Daily/weekly/monthly reports via `weasyprint>=62.0`. Jinja2 report templates. Email delivery.
- **Files to create:** `fastapi_app/services/report_generator.py`, `fastapi_app/templates/reports/`, `fastapi_app/api/reports.py`

### Task 5.3: SOAR Playbook Automation
- **Priority:** P2 — Medium
- **Effort:** 8 days
- **Add:** Trigger → action chain playbooks. Auto-block via EDL, create tickets, enrich alerts, quarantine devices.
- **Files to create:** `fastapi_app/models/playbook.py`, `fastapi_app/services/playbook_engine.py`, `fastapi_app/api/playbooks.py`, `fastapi_app/templates/playbooks/`

---

## Phase 6: Observability, Monitoring & Reliability

**Goal:** Full system visibility for both Go and Python components.

### Task 6.1: Grafana Operational Dashboards
- **Priority:** P1 — High
- **Effort:** 3 days
- **Add:** Grafana container with pre-built dashboards: System Overview, Syslog Pipeline (Go metrics), Database Health, Security Events, Capacity Planning.
- **Files to create:** `docker/grafana/`, `docker/grafana/dashboards/*.json`, `docker/grafana/provisioning/`
- **Files to modify:** `docker-compose.yml`

### Task 6.2: Request Correlation IDs
- **Priority:** P1 — High
- **Effort:** 1 day
- **Add:** UUID4 `X-Request-ID` header on every request. Inject into all log records and ClickHouse query comments.
- **Files to create:** `fastapi_app/core/request_id.py`
- **Files to modify:** `fastapi_app/core/logging.py`, `fastapi_app/main.py`

### Task 6.3: Structured Error Handling
- **Priority:** P1 — High
- **Effort:** 2 days
- **Add:** Global exception handler with consistent JSON error format, error codes, optional Sentry integration.
- **Files to create:** `fastapi_app/core/error_handler.py`
- **Files to modify:** `fastapi_app/main.py`

### Task 6.4: OpenTelemetry Distributed Tracing
- **Priority:** P2 — Medium
- **Effort:** 4 days
- **Add:** OTel SDK for both Go (collector) and Python (FastAPI). Auto-instrument FastAPI, SQLAlchemy, Redis, httpx. Trace spans across Go → Redis → Python.
- **Go:** `go.opentelemetry.io/otel`
- **Python:** `opentelemetry-api>=1.24.0`, `opentelemetry-sdk>=1.24.0`, `opentelemetry-instrumentation-fastapi>=0.45b0`
- **Files to create:** `fastapi_app/core/tracing.py`, `collector/internal/tracing/tracing.go`

---

## Phase 7: Deployment, HA & Scalability

**Goal:** Zero-downtime deployments, horizontal scaling, disaster recovery.

### Task 7.1: Health Check Improvements
- **Priority:** P1 — High
- **Effort:** 1 day
- **Add:** Startup probe (`/api/health/startup`), liveness probe (`/api/health/live`), readiness probe (`/api/health/ready`).
- **Files to modify:** `fastapi_app/api/health.py`

### Task 7.2: Automated TLS (Caddy)
- **Priority:** P1 — High
- **Effort:** 2 days
- **Replace Nginx with Caddy 2:** Automatic HTTPS via Let's Encrypt, HTTP/3 support, simpler config.
- **Files to create:** `docker/Caddyfile`
- **Files to modify:** `docker-compose.yml`

### Task 7.3: Blue-Green Deployment Script
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Add:** Zero-downtime deploy: build new → health check → switch traffic → drain old → rollback on failure.
- **Files to create:** `scripts/deploy.sh`

### Task 7.4: Horizontal Scaling Guide
- **Priority:** P2 — Medium
- **Effort:** 3 days
- **Add:** Multi-node config: N web containers, multiple Go collectors, ClickHouse cluster (ReplicatedMergeTree), PostgreSQL read replicas, Redis Sentinel.
- **Files to create:** `docs/scaling.md`, `docker-compose.cluster.yml`

### Task 7.5: Disaster Recovery Automation
- **Priority:** P1 — High
- **Effort:** 4 days
- **Add:** Automated daily backups via ARQ. Backup verification. Offsite to S3/MinIO (`boto3>=1.34.0`). WAL archiving for PostgreSQL PITR.
- **Files to create:** `fastapi_app/services/backup_manager.py`
- **Files to modify:** `scripts/backup.sh`

---

## Bonus Phase: Compliance & Advanced Features

### Task B.1: Compliance Dashboards
- **Priority:** P2 — Medium | **Effort:** 5 days
- **Add:** PCI-DSS, SOC2, ISO 27001, NCA ECC pre-built dashboards.

### Task B.2: Immutable Audit Log (Hash Chain)
- **Priority:** P1 — High | **Effort:** 3 days
- **Add:** SHA-256 hash chain for tamper detection. Verification endpoint.

### Task B.3: Multi-Tenancy
- **Priority:** P3 — Future | **Effort:** 15 days
- **Add:** Organization-based isolation (PostgreSQL RLS, ClickHouse query rewriting).

### Task B.4: REST API v2
- **Priority:** P2 — Medium | **Effort:** 5 days
- **Add:** Cursor pagination, field selection, consistent envelope format.

### Task B.5: Webhook Receivers
- **Priority:** P2 — Medium | **Effort:** 3 days
- **Add:** AWS SNS, Azure Event Grid, generic JSON, PagerDuty callbacks.

### Task B.6: NQL Query Enhancement
- **Priority:** P2 — Medium | **Effort:** 5 days
- **Add:** Proper parser via `lark>=1.1.0`. Syntax highlighting, auto-complete, cost estimation.

---

## Full Task List

### Priority: P0 = Critical | P1 = High | P2 = Medium | P3 = Future

| # | Phase | Task | Language | Priority | Effort | Dependencies |
|---|-------|------|----------|----------|--------|--------------|
| 0.1 | Go Collector | Project scaffolding + build system | Go | P0 | 2d | — |
| 0.2 | Go Collector | UDP + TCP + TLS listeners | Go | P0 | 4d | 0.1 |
| 0.3 | Go Collector | Port parsers + 6 new vendors | Go | P0 | 5d | 0.1 |
| 0.4 | Go Collector | Redis Streams output | Go | P0 | 3d | 0.2, 1.1 |
| 0.5 | Go Collector | Stream consumer (Redis→CH) + GeoIP | Go | P0 | 3d | 0.4 |
| 0.6 | Go Collector | HTTP ingest receiver | Go | P1 | 2d | 0.4 |
| 0.7 | Go Collector | Prometheus metrics | Go | P1 | 1d | 0.2 |
| 0.8 | Go Collector | Docker integration | Go | P0 | 1d | 0.2-0.5 |
| 1.1 | Foundation | Add Redis/Valkey service | Infra | P0 | 2d | — |
| 1.2 | Foundation | Replace NullPool with QueuePool | Python | P0 | 1d | — |
| 1.3 | Foundation | Replace python-jose with PyJWT | Python | P0 | 1d | — |
| 1.4 | Foundation | Redis-backed sessions | Python | P0 | 2d | 1.1 |
| 1.5 | Foundation | Docker Compose hardening | Infra | P0 | 2d | — |
| 1.6 | Foundation | Prometheus metrics (FastAPI) | Python | P0 | 2d | — |
| 2.1 | Security | TOTP 2FA | Python | P0 | 4d | — |
| 2.2 | Security | Argon2id password hashing | Python | P1 | 2d | — |
| 2.3 | Security | Distributed rate limiting | Python | P1 | 2d | 1.1 |
| 2.4 | Security | CSP headers | Python | P1 | 2d | — |
| 2.5 | Security | SAML/OIDC SSO | Python | P1 | 6d | — |
| 2.6 | Security | LDAP/AD integration | Python | P1 | 4d | — |
| 2.7 | Security | API key scoped permissions | Python | P2 | 3d | — |
| 3.1 | Storage | ClickHouse schema optimization | SQL | P1 | 3d | — |
| 3.2 | Storage | Materialized views | SQL | P1 | 3d | 3.1 |
| 3.3 | Storage | PgBouncer | Infra | P1 | 2d | — |
| 3.4 | Storage | ClickHouse dictionaries | SQL | P2 | 2d | 3.1 |
| 3.5 | Storage | Tiered data retention | Python | P1 | 4d | 3.1 |
| 4.1 | Frontend | TailwindCSS + Vite | JS/CSS | P1 | 4d | — |
| 4.2 | Frontend | Apache ECharts (replace Chart.js) | JS | P1 | 5d | 4.1 |
| 4.3 | Frontend | HTMX integration | JS | P1 | 4d | — |
| 4.4 | Frontend | Alpine.js | JS | P2 | 3d | 4.3 |
| 4.5 | Frontend | GeoIP map visualization | JS | P2 | 3d | 0.5, 4.2 |
| 4.6 | Frontend | Sankey flow diagram | JS | P2 | 2d | 4.2 |
| 4.7 | Frontend | WebSocket real-time logs | Python+JS | P2 | 3d | 1.1 |
| 5.1 | Background | ARQ task queue | Python | P1 | 3d | 1.1 |
| 5.2 | Background | PDF report generation | Python | P2 | 5d | 5.1 |
| 5.3 | Background | SOAR playbooks | Python | P2 | 8d | 5.1 |
| 6.1 | Observability | Grafana dashboards | Infra | P1 | 3d | 1.6, 0.7 |
| 6.2 | Observability | Request correlation IDs | Python | P1 | 1d | — |
| 6.3 | Observability | Error handling | Python | P1 | 2d | — |
| 6.4 | Observability | OpenTelemetry tracing | Go+Python | P2 | 4d | — |
| 7.1 | Deployment | Health check improvements | Python | P1 | 1d | — |
| 7.2 | Deployment | Caddy auto-TLS | Infra | P1 | 2d | — |
| 7.3 | Deployment | Blue-green deploy | Infra | P2 | 3d | 1.5 |
| 7.4 | Deployment | Horizontal scaling guide | Docs | P2 | 3d | 1.1, 1.4 |
| 7.5 | Deployment | Disaster recovery automation | Python | P1 | 4d | 5.1 |
| B.1 | Bonus | Compliance dashboards | Python | P2 | 5d | — |
| B.2 | Bonus | Immutable audit log | Python | P1 | 3d | — |
| B.3 | Bonus | Multi-tenancy | Python | P3 | 15d | Many |
| B.4 | Bonus | REST API v2 | Python | P2 | 5d | — |
| B.5 | Bonus | Webhook receivers | Go | P2 | 3d | 0.6 |
| B.6 | Bonus | NQL enhancement | Python | P2 | 5d | — |

**Totals:** 58 tasks | P0: 14 tasks (~29d) | P1: 25 tasks (~67d) | P2: 16 tasks (~57d) | P3: 3 tasks

---

## Dependencies Summary

### Go (collector/go.mod)
```
github.com/redis/go-redis/v9           # Redis Streams, pub/sub
github.com/ClickHouse/clickhouse-go/v2  # Native ClickHouse protocol
github.com/prometheus/client_golang     # Metrics
github.com/oschwald/maxminddb-golang    # GeoIP (MaxMind)
go.opentelemetry.io/otel               # Tracing (Phase 6)
```

### Python (requirements.txt changes)
```
# REMOVE
python-jose[cryptography]    # Unmaintained
passlib[bcrypt]              # Replace with argon2
bcrypt==4.0.1                # No longer needed

# ADD — Core
PyJWT>=2.8.0                 # JWT (replaces python-jose)
argon2-cffi>=23.1.0          # Password hashing (replaces passlib)
redis[hiredis]>=5.0.0        # Cache, sessions, streams, queue
arq>=0.26.0                  # Async task queue

# ADD — Security
pyotp>=2.9.0                 # TOTP 2FA
qrcode[pil]>=7.4             # QR codes for 2FA
python3-saml>=1.16.0         # SAML SSO
authlib>=1.3.0               # OIDC SSO
ldap3>=2.9.0                 # LDAP/AD

# ADD — Observability
prometheus-fastapi-instrumentator>=7.0.0
prometheus-client>=0.20.0
opentelemetry-api>=1.24.0
opentelemetry-sdk>=1.24.0
opentelemetry-instrumentation-fastapi>=0.45b0

# ADD — Reporting & Cloud
weasyprint>=62.0             # PDF generation
lark>=1.1.0                  # NQL parser
boto3>=1.34.0                # S3 backup (optional)
```

### Node.js (package.json — new)
```json
{
  "devDependencies": {
    "vite": "^6.0.0",
    "tailwindcss": "^4.0.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0"
  },
  "dependencies": {
    "echarts": "^5.5.0",
    "htmx.org": "^2.0.0",
    "alpinejs": "^3.14.0"
  }
}
```

### Docker Services (docker-compose.yml)
```yaml
# EXISTING (keep)
postgres:     postgres:16-alpine
clickhouse:   clickhouse/clickhouse-server:24-alpine
web:          zentryc:latest (Python FastAPI)

# REPLACE
# syslog (Python) → collector (Go)
# nginx → caddy:2-alpine

# NEW
redis:        valkey/valkey:8-alpine
pgbouncer:    edoburu/pgbouncer:1.22
collector:    zentryc-collector:latest (Go — syslog)
consumer:     zentryc-collector:latest (Go — stream→CH)
ingest:       zentryc-collector:latest (Go — HTTP receiver)
arq-worker:   zentryc:latest (Python — background tasks)
prometheus:   prom/prometheus:v2.51
grafana:      grafana/grafana:11
caddy:        caddy:2-alpine
```

---

## Performance Targets

| Metric | Current | Target | How |
|--------|---------|--------|-----|
| Max EPS (sustained) | ~1,100 | **200,000+** | Go collector + parallel goroutines |
| Parse latency | 5-10 µs (GIL) | **0.1-0.5 µs** | Go regexp (no GIL, true parallel) |
| Dashboard load | 2-5s | **<100ms** | ClickHouse materialized views |
| Log search (1M rows) | 3-8s | **<1s** | Schema optimization + projections |
| Data loss on crash | Possible | **Zero** | Redis Streams (persistent + XACK) |
| Session persistence | Lost on restart | **Persistent** | Redis-backed sessions |
| Max concurrent users | ~50 | **500+** | QueuePool + PgBouncer |
| Auth methods | 1 (password) | **5** | Password, TOTP, SAML, OIDC, LDAP |
| Supported vendors | 3 | **9+** | Go parsers (Fortinet, PA, Cisco, CP, Sophos, Win, AWS, Linux, Generic) |
| Collector container | 200 MB | **15 MB** | Go static binary |
| Monitoring | Health endpoint | **Full stack** | Prometheus + Grafana (Go + Python metrics) |
| Compliance | None | **4 frameworks** | PCI-DSS, SOC2, ISO 27001, NCA ECC |

---

## Sprint Schedule (Recommended)

### Sprint 0 (Week 1-3): Go Collector + Foundation
- Tasks 0.1-0.5, 0.8 (Go collector core — 18 days)
- Tasks 1.1-1.3 (Redis + NullPool + PyJWT — 4 days, parallel with Go work)

### Sprint 1 (Week 3-4): Foundation Complete
- Tasks 1.4-1.6 (Sessions, Docker hardening, Prometheus — 6 days)
- Task 0.6-0.7 (Go HTTP ingest + metrics — 3 days)

### Sprint 2 (Week 5-6): Security Hardening
- Tasks 2.1-2.4 (TOTP, Argon2, rate limiting, CSP — 10 days)

### Sprint 3 (Week 7-8): Storage & Enterprise Auth
- Tasks 3.1-3.3 (CH optimization, mat views, PgBouncer — 8 days)
- Task 2.5 starts (SAML/OIDC — 6 days, spans into Sprint 4)

### Sprint 4 (Week 9-10): Enterprise Auth + Frontend Start
- Tasks 2.5-2.6 complete (SSO + LDAP — remaining days)
- Tasks 4.1, 4.3 (Tailwind + HTMX — 8 days)

### Sprint 5 (Week 11-12): Frontend + Background
- Tasks 4.2 (ECharts — 5 days)
- Task 5.1 (ARQ — 3 days)
- Task 6.1 (Grafana — 3 days)

### Sprint 6 (Week 13-14): Polish & Observability
- Tasks 6.2-6.3 (Correlation IDs, error handling — 3 days)
- Tasks 7.1-7.2 (Health checks, Caddy — 3 days)
- Tasks 3.5, B.2 (Retention, audit hash chain — 7 days)

### Sprint 7+ (Week 15+): Advanced Features
- Remaining P2 tasks (GeoIP maps, Sankey, WebSocket, reports, playbooks, compliance, API v2, NQL)

---

*This is the FINAL plan. Version 2.0 incorporates the Go hybrid architecture decision.*
*Document generated: 2026-03-30*
*Next review: After Sprint 0 completion*
