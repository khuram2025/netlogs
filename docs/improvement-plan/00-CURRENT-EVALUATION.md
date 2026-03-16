# Zentryc Platform - Current System Evaluation

## Overall Score: 6.5 / 10

## Detailed Scoring by Area

### Strengths

| Area | Score | Details |
|------|-------|---------|
| Log Ingestion | 8/10 | High-performance async UDP collector, 100K+ logs/min, batch inserts, multi-worker architecture |
| Firewall Parsing | 7/10 | Fortinet + Palo Alto + Generic parsers with deep field extraction (40+ fields) |
| Dashboard | 7/10 | Real-time stats, traffic timeline, severity breakdown, threat tables, device activity |
| Storage Management | 8/10 | Quota system, auto-cleanup, TTL, monthly partitioning, emergency disk handling |
| EDL Management | 9/10 | Full CRUD, feed endpoints, bulk import/export, token auth, multi-format support |
| Policy Builder | 8/10 | Log-to-CLI generation for Fortinet & Palo Alto, communication matrix policies |
| Device Management | 7/10 | Approval workflow, SSH integration, routing tables, zone collection, VDOM support |
| Project/Comm Matrix | 7/10 | Excel import/export, policy generation from matrix, active/inactive tracking |
| Search & Filtering | 6/10 | Good field filters, CIDR/wildcard/negation support, but lacks saved searches |
| UI/UX | 6/10 | Clean dark theme, Chart.js visualizations, some inconsistency between pages |

### Weaknesses / Critical Gaps

| Area | Score | Gap Description |
|------|-------|-----------------|
| Authentication & RBAC | 0/10 | No login system, no user roles, no access control |
| Alerting & Notifications | 0/10 | No real-time alert rules, no notifications |
| Incident Management | 0/10 | No case/ticket tracking, no incident lifecycle |
| Threat Intelligence | 2/10 | EDL exists but no IOC matching on live logs |
| Automated Response (SOAR) | 2/10 | Policy builder exists but no automated playbooks |
| AI/ML Analytics | 0/10 | No anomaly detection, no behavioral analysis |
| Compliance & Reporting | 1/10 | No scheduled reports, no compliance templates |
| Audit Logging | 0/10 | No tracking of user/admin actions |
| API Security | 1/10 | No API authentication or rate limiting |
| Multi-vendor Support | 4/10 | Only Fortinet + Palo Alto (missing Cisco, Check Point, Sophos, Juniper) |

---

## Current Feature Inventory

### 1. Core Infrastructure
- FastAPI v2.0.0 with async/await
- PostgreSQL (device config, projects, credentials, EDLs)
- ClickHouse (high-volume log storage, time-series queries)
- Background scheduler (APScheduler)
- Static file serving
- Health check endpoint (`/api/health`)

### 2. Log Ingestion Pipeline
- Async UDP syslog receiver on port 514
- 4 worker processes (configurable)
- 5,000 log batch inserts (configurable)
- 2-second flush interval
- 100,000 log buffer capacity
- Device cache with 60s TTL
- Performance metrics (logs/sec, cache hit rate)

### 3. Firewall Parsers
- **Fortinet FortiGate**: Traffic, UTM (IPS, AV, DLP), Event logs
- **Palo Alto Networks**: Traffic, Threat, System logs
- **Generic Syslog**: RFC3164/5424 parsing
- 40+ extracted fields across parsers

### 4. Dashboard (Real-time)
- 6 KPI cards (Total Events, EPS, Allowed, Blocked, Critical, Active Devices)
- Traffic timeline (24h line chart)
- Real-time traffic (1h per-minute)
- Severity distribution (doughnut chart)
- Firewall actions (bar chart)
- Protocol distribution (doughnut chart)
- Top Source IPs table
- Potential Threats (denied sources) table
- Top Destination Ports table
- Device Activity table
- Recent Events table (15 entries)
- 60-second auto-refresh

### 5. Log Viewer
- Advanced filtering: device, severity, time range
- Network filters: srcip, dstip, srcport, dstport, protocol
- Policy filters: policyname, log_type, threat_id
- Traffic filters: application, session_end_reason
- Infrastructure filters: src_zone, dst_zone
- Full-text search with CIDR, wildcard, negation support
- Pagination (configurable per page)
- Log detail expansion

### 6. Device Management
- Device list with status indicators (Pending/Approved/Rejected)
- Approve/reject/block workflow
- Per-device storage stats
- SSH credential management (add, test, delete)
- VDOM configuration for FortiGate
- Routing table collection via SSH
- Zone/interface data collection
- Route change tracking and history
- 30-second auto-refresh

### 7. Policy Builder
- Generate Fortinet CLI from log data or communication matrix
- Generate Palo Alto CLI from log data or communication matrix
- Address objects, service objects, policy rules
- Zone auto-matching via device IP lookup
- Copy-to-clipboard functionality
- Per-rule and bulk CLI export

### 8. Project & Communication Matrix
- Project CRUD with status management
- Communication matrix entries (src, dst, port, protocol, type)
- Excel import/export with templates
- Policy generation from matrix entries
- Active/inactive entry management

### 9. EDL (External Dynamic Lists)
- List types: IP, Domain, URL, Hash
- CRUD for lists and entries
- Bulk import (file upload, text paste)
- Export formats: TXT, CSV, JSON
- Feed endpoints for firewall consumption:
  - Per-list feeds
  - Aggregated feeds by type (all IPs, all domains, etc.)
- Token-based feed authentication
- Entry expiration support
- Bulk operations (delete, toggle)

### 10. System Monitoring
- Disk usage display with status badges
- ClickHouse storage analytics (per-table)
- Partition information
- Storage quota management UI
- Manual and auto cleanup triggers
- Cleanup history tracking
- Cleanup impact estimation

### 11. Storage Management
- Configurable max size (default 600GB)
- Auto-cleanup on threshold
- Minimum retention days enforcement
- Emergency cleanup on critical disk usage
- Per-device retention policies (7-365 days or forever)
- 3-month TTL on ClickHouse data

### 12. SSH Integration
- SSH connection pooling
- Multi-VDOM support
- Routing table parsing (static, VLAN, BGP, OSPF)
- Zone/interface discovery
- Connection testing
- Credential encryption

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Web Framework | FastAPI 0.104+ | Async REST API + HTML views |
| Template Engine | Jinja2 3.1+ | Server-side HTML rendering |
| ORM | SQLAlchemy 2.0+ (async) | PostgreSQL data access |
| PostgreSQL Driver | asyncpg 0.29+ | Async PostgreSQL connections |
| ClickHouse Client | clickhouse-connect 0.7+ | Log storage and analytics |
| SSH Client | paramiko 3.4+ / asyncssh 2.14+ | Firewall SSH integration |
| Scheduler | APScheduler 3.10+ | Background job scheduling |
| Charting | Chart.js | Dashboard visualizations |
| CSS | Custom (no framework) | Dark-themed UI |
| Process Model | Uvicorn + 4 workers | Multi-process serving |

---

## Comparison with Industry Leaders

| Feature | Zentryc | Splunk | FortiSIEM | Elastic SIEM | QRadar |
|---------|---------|--------|-----------|-------------|--------|
| Log Collection | Yes | Yes | Yes | Yes | Yes |
| Multi-vendor Parse | Partial | Full | Full | Full | Full |
| Real-time Alerts | **No** | Yes | Yes | Yes | Yes |
| User Auth/RBAC | **No** | Yes | Yes | Yes | Yes |
| Threat Intel | Partial | Yes | Yes | Yes | Yes |
| SOAR Playbooks | **No** | Yes | Yes | Partial | Yes |
| AI/ML Detection | **No** | Yes | Yes | Yes | Yes |
| Incident Mgmt | **No** | Yes | Yes | Yes | Yes |
| Compliance Reports | **No** | Yes | Yes | Yes | Yes |
| MITRE ATT&CK | **No** | Yes | Yes | Yes | Yes |
| Custom Dashboards | **No** | Yes | Yes | Yes | Yes |
| EDL/Block Lists | **Yes** | Partial | Yes | Partial | Partial |
| Policy Builder | **Yes** | No | Partial | No | No |
| Routing Tables | **Yes** | No | Partial | No | No |
| Comm Matrix | **Yes** | No | No | No | No |

**Key Differentiators** (Features competitors lack):
1. Policy Builder (log-to-CLI generation)
2. Communication Matrix with policy generation
3. Integrated EDL management with firewall feeds
4. Routing table collection and change tracking
5. Zone/interface auto-discovery

These differentiators should be preserved and enhanced as we add the missing features.
