# Fastvue Feature Gap Analysis & Implementation Plan

> **Date:** 2026-03-16
> **Scope:** Compare Fastvue Reporter features against Zentryc platform, identify gaps, and plan additions/improvements.

---

## Table of Contents

1. [Fastvue Reporter Feature Inventory](#1-fastvue-reporter-feature-inventory)
2. [Zentryc Current Feature Inventory](#2-zentryc-current-feature-inventory)
3. [Feature Gap Matrix](#3-feature-gap-matrix)
4. [Detailed Gap Analysis](#4-detailed-gap-analysis)
5. [Implementation Plan](#5-implementation-plan)

---

## 1. Fastvue Reporter Feature Inventory

### 1.1 Real-Time Dashboards
| Feature | Description |
|---------|-------------|
| Bandwidth Dashboard | Live bandwidth usage by user, department, application |
| Productivity Dashboard | Real-time productivity scoring per user/group |
| Security Dashboard | Threat events, blocked sites, keyword alerts in real-time |
| Top Users Widget | Current top bandwidth consumers |
| Top Sites Widget | Most visited websites right now |
| Top Applications Widget | Top applications by usage |
| Blocked Activity Widget | Currently blocked requests |
| Threat Events Widget | Active threats and security events |

### 1.2 Report Types
| Report Type | Description |
|-------------|-------------|
| **Internet Usage Report** | Top users, most-visited sites, search terms, productivity info, blocked sites |
| **Safeguarding Report** | Keyword-matched searches, YouTube titles, access to unacceptable sites (for schools/compliance) |
| **IT Network & Security Report** | Bandwidth issues, detected threats, VPN activity, firewall policy analysis |
| **User Overview Report** | Per-user filtered version of overview report |
| **Activity Timeline Report** | Forensic log-level detail grouped by browsing sessions, chronological activity |

### 1.3 Report Features
| Feature | Description |
|---------|-------------|
| Scheduled Reports | Auto-send daily, weekly, or monthly via email |
| Report Filtering | Filter by department, security group, office, subnet, user |
| Report Sharing | Share reports with non-technical managers |
| Report Export | Export to PDF, CSV, HTML |
| Custom Date Ranges | Any time period selection |
| Per-Department Reports | Auto-filter and route to department managers |

### 1.4 Site Clean
| Feature | Description |
|---------|-------------|
| URL Simplification | Strips tracking parameters, simplifies complex URLs for readability |
| Friendly Site Names | Shows human-readable names instead of raw domains |
| Category Enrichment | Adds category context to URLs (social media, news, etc.) |
| Manager-Friendly Output | Makes reports understandable for non-technical staff |

### 1.5 Keyword Detection
| Feature | Description |
|---------|-------------|
| Suicide & Self-Harm Keywords | Detects searches related to self-harm |
| Extremism & Radicalization | Flags radical/extremist search terms |
| Racism Keywords | Detects racist/hate search content |
| Drug-Related Keywords | Flags drug-related searches |
| Pornography Keywords | Detects explicit content searches |
| Profanity Detection | Flags profane language in searches |
| Custom Keyword Lists | User-defined keyword watchlists |
| Continuously Updated Database | Keyword database updated by Fastvue |
| Low False Positives | Intelligent matching to reduce noise |
| YouTube Video Title Matching | Scans YouTube video titles for keywords |
| Search Term Extraction | Extracts actual search queries from URLs |

### 1.6 Productivity Assessment
| Feature | Description |
|---------|-------------|
| Productivity Scoring | Score users based on browsing habits |
| Custom Productivity Guidelines | Define what's productive vs. unproductive per org |
| Category-Based Assessment | Rate URL categories (productive/neutral/unproductive) |
| Time Tracking | Track time spent on productive vs. unproductive sites |
| Department Comparison | Compare productivity across departments |
| Good Digital Citizenship Tracking | Reward positive browsing behavior |

### 1.7 Alerts
| Feature | Description |
|---------|-------------|
| Real-Time Alerts | Instant notification on trigger |
| Keyword Match Alerts | Alert when user searches flagged keywords |
| Bandwidth Threshold Alerts | Alert on large uploads/downloads |
| Threat Detection Alerts | Alert on detected network threats |
| Blocked Site Alerts | Alert when users access blocked sites |
| Email Notifications | Send alerts via email |
| Customizable Triggers | Define custom alert conditions |

### 1.8 User Identity & Tracking
| Feature | Description |
|---------|-------------|
| Active Directory Integration | Map IPs to usernames via AD |
| LDAP Integration | User identity from LDAP |
| Department/Group Mapping | Map users to departments and security groups |
| Subnet-to-Location Mapping | Associate IP ranges with office locations |
| User Activity Timeline | Full chronological browsing history per user |
| Browsing Session Grouping | Group related requests into sessions |
| Cross-Device User Tracking | Track same user across multiple IPs |

### 1.9 Bandwidth Analysis
| Feature | Description |
|---------|-------------|
| Top Bandwidth Users | Who's consuming the most bandwidth |
| Bandwidth by Application | Which apps use the most bandwidth |
| Bandwidth by Category | Bandwidth by URL category |
| Upload vs. Download | Distinguish upload and download traffic |
| Bandwidth Over Time | Historical bandwidth trends |
| Large Transfer Detection | Flag unusually large uploads/downloads |

### 1.10 VPN Reporting
| Feature | Description |
|---------|-------------|
| VPN Session Summary | Active/historical VPN sessions |
| VPN User Activity | What VPN users are accessing |
| VPN Bandwidth | Bandwidth consumed via VPN |
| VPN Duration | Session duration tracking |

### 1.11 Firewall Policy Analysis
| Feature | Description |
|---------|-------------|
| Policy Hit Count | Which policies are triggered most |
| Policy Blocking/Allowing | Identify what each policy blocks or allows |
| Unused Policy Detection | Find policies that are never matched |
| Policy-to-Traffic Mapping | See what traffic matches each policy |

### 1.12 Supported Firewalls
- Palo Alto Networks
- Fortinet FortiGate
- Cisco Firepower
- Cisco Umbrella SIG
- SonicWall
- Sophos Firewall
- Sophos Web Appliance
- Barracuda
- ContentKeeper

### 1.13 Deployment
| Feature | Description |
|---------|-------------|
| Windows Server | Native Windows deployment |
| Docker (Linux) | Container-based deployment |
| Self-Hosted | On-premises, private cloud |
| Data Privacy | Data never leaves your infrastructure |
| Elasticsearch Backend | Full-text search engine |

---

## 2. Zentryc Current Feature Inventory

### 2.1 Dashboards & Analytics
| Feature | Status | Files |
|---------|--------|-------|
| Main Dashboard with KPIs | **EXISTS** | `api/views.py`, `templates/logs/dashboard.html` |
| Traffic Timeline Charts | **EXISTS** | `api/views.py` (traffic_timeline) |
| Severity Distribution | **EXISTS** | `api/views.py` (severity_distribution) |
| Top Sources/Destinations | **EXISTS** | `db/clickhouse.py` (get_dashboard_stats) |
| Device Activity | **EXISTS** | `api/views.py` (device_counts) |
| Action Breakdown | **EXISTS** | `db/clickhouse.py` |
| Protocol Distribution | **EXISTS** | `db/clickhouse.py` |
| Top Ports | **EXISTS** | `db/clickhouse.py` |
| Custom Dashboards & Widgets | **EXISTS** | `api/dashboards.py`, `templates/dashboards/` |
| URL/DNS KPIs (threat dashboard) | **EXISTS** | `api/threat_dashboard.py`, `api/views.py` |

### 2.2 Log Management & Search
| Feature | Status | Files |
|---------|--------|-------|
| High-Performance Syslog Collector (500+ EPS) | **EXISTS** | `services/syslog_collector.py` |
| Full-Text Log Search | **EXISTS** | `api/logs.py` (search) |
| NQL Query Language | **EXISTS** | `services/nql_parser.py` |
| Advanced Filters (CIDR, ranges, wildcards) | **EXISTS** | `api/logs.py` |
| Log Detail with Parsed Fields | **EXISTS** | `api/logs.py` (detail) |
| Session Flow Tracing (multi-firewall) | **EXISTS** | `api/logs.py` (session-flow) |
| Saved Searches | **EXISTS** | `api/saved_searches.py` |
| Log View / Aggregate View Toggle | **EXISTS** | `templates/logs/log_list.html` |
| Storage Stats & Timeline | **EXISTS** | `api/logs.py` (storage) |

### 2.3 Threat Detection & Security
| Feature | Status | Files |
|---------|--------|-------|
| Alert Rules (threshold/pattern/anomaly/absence) | **EXISTS** | `services/alert_engine.py` |
| Alert Dashboard | **EXISTS** | `api/alerts.py`, `templates/alerts/` |
| Multi-Channel Notifications (email/Telegram/webhook) | **EXISTS** | `services/notification_service.py` |
| MITRE ATT&CK Mapping | **EXISTS** | `api/correlation.py` (mitre_map) |
| Threat Intel Feeds (CSV/JSON/STIX) | **EXISTS** | `api/threat_intel.py` |
| IOC Matching (IP/domain/URL/hash) | **EXISTS** | `services/ioc_matcher.py` |
| IOC Match Tracking | **EXISTS** | `api/threat_intel.py` (matches) |
| Correlation Engine (multi-stage) | **EXISTS** | `services/correlation_engine.py` |
| AI-Powered Alert Summary | **EXISTS** | `api/alerts.py` (ai-summary) |

### 2.4 URL/DNS Analysis
| Feature | Status | Files |
|---------|--------|-------|
| URL Filtering Logs | **EXISTS** | `api/threat_dashboard.py` (url-logs) |
| DNS Security Logs | **EXISTS** | `api/threat_dashboard.py` (dns-logs) |
| URL Category Breakdown | **EXISTS** | `api/threat_dashboard.py` (url-categories) |
| Top Threat Signatures | **EXISTS** | `api/threat_dashboard.py` (top-threats) |
| Source IP Drill-Down | **EXISTS** | `api/threat_dashboard.py` (source-detail) |
| URL Category Drill-Down | **EXISTS** | `api/threat_dashboard.py` (url-category-detail) |
| Threat Signature Drill-Down | **EXISTS** | `api/threat_dashboard.py` (threat-sig-detail) |
| Fortinet + PA UNION ALL Queries | **EXISTS** | `api/threat_dashboard.py` (_combined_cte) |

### 2.5 Device Management
| Feature | Status | Files |
|---------|--------|-------|
| Device CRUD | **EXISTS** | `api/devices.py` |
| Auto-Discovery & Approval | **EXISTS** | `services/syslog_collector.py` |
| Parser Type Selection | **EXISTS** | `models/device.py` |
| Per-Device Storage Stats | **EXISTS** | `api/devices.py` |
| Device Credentials (SSH) | **EXISTS** | `models/credential.py` |
| Retention Policy per Device | **EXISTS** | `models/device.py` |

### 2.6 Policy & Compliance
| Feature | Status | Files |
|---------|--------|-------|
| Policy Builder (FortiGate + PA) | **EXISTS** | `services/policy_builder_service.py` |
| Policy Lookup | **EXISTS** | `templates/logs/policy_lookup.html` |
| External Dynamic Lists (EDL) | **EXISTS** | `api/edl.py` |
| Address Object Management | **EXISTS** | `api/address_objects.py` |
| Communication Matrix (Projects) | **EXISTS** | `api/projects.py` |
| FortiGate Policy Export | **EXISTS** | `templates/logs/log_list.html` (aggregate) |

### 2.7 System Administration
| Feature | Status | Files |
|---------|--------|-------|
| Health Monitoring | **EXISTS** | `api/health.py` |
| Backup & Restore | **EXISTS** | `api/backup.py`, `scripts/` |
| Audit Logging (ClickHouse) | **EXISTS** | `services/audit_service.py` |
| RBAC (Admin/Analyst/Viewer) | **EXISTS** | `core/permissions.py` |
| API Key Management | **EXISTS** | `api/api_keys.py` |
| CSRF Protection | **EXISTS** | `core/csrf.py` |
| Setup Wizard | **EXISTS** | `api/setup.py` |
| Alembic Migrations | **EXISTS** | `db/migrations/` |
| Docker Deployment | **EXISTS** | `Dockerfile`, `docker-compose.yml` |

---

## 3. Feature Gap Matrix

### Legend
- **HAVE** = Feature exists in Zentryc
- **PARTIAL** = Partially implemented, needs enhancement
- **GAP** = Not implemented, should be added
- **N/A** = Not applicable or not needed for our use case

| # | Fastvue Feature | Zentryc Status | Priority | Effort |
|---|----------------|----------------|----------|--------|
| | **DASHBOARDS** | | | |
| 1 | Bandwidth Dashboard (real-time) | **PARTIAL** - have traffic stats, no per-user bandwidth | HIGH | M |
| 2 | Productivity Dashboard | **GAP** | MEDIUM | L |
| 3 | Security Dashboard | **HAVE** - threat dashboard exists | - | - |
| 4 | Top Users Widget (bandwidth) | **GAP** - have top source IPs, no user identity | HIGH | M |
| 5 | Top Sites Widget | **HAVE** - url-categories exists | - | - |
| 6 | Top Applications Widget | **PARTIAL** - have app data, no dedicated widget | LOW | S |
| | **REPORTS** | | | |
| 7 | Internet Usage Report (generated) | **GAP** | HIGH | L |
| 8 | Safeguarding Report | **GAP** | LOW | L |
| 9 | IT Network & Security Report | **GAP** | HIGH | L |
| 10 | User Overview Report | **GAP** | HIGH | L |
| 11 | Activity Timeline Report | **GAP** | MEDIUM | L |
| 12 | Scheduled Report Delivery (email) | **GAP** | HIGH | M |
| 13 | Report Export (PDF/CSV/HTML) | **PARTIAL** - CSV export in audit logs only | HIGH | M |
| 14 | Report Filtering (dept/group/subnet) | **GAP** | MEDIUM | M |
| 15 | Per-Department Auto-Reports | **GAP** | MEDIUM | M |
| | **SITE CLEAN** | | | |
| 16 | URL Simplification | **GAP** | MEDIUM | S |
| 17 | Friendly Site Names | **GAP** | MEDIUM | S |
| 18 | Category Enrichment | **PARTIAL** - have PA/Forti categories | LOW | S |
| | **KEYWORD DETECTION** | | | |
| 19 | Search Term Extraction from URLs | **GAP** | HIGH | M |
| 20 | Keyword Watchlists (custom) | **PARTIAL** - have IOC watchlists, not keyword-based | HIGH | M |
| 21 | Keyword Categories (self-harm, extremism, etc.) | **GAP** | MEDIUM | M |
| 22 | YouTube Video Title Matching | **GAP** | LOW | M |
| 23 | Keyword Alert Triggers | **PARTIAL** - have alert rules, not keyword-specific | MEDIUM | S |
| | **PRODUCTIVITY** | | | |
| 24 | Productivity Scoring per User | **GAP** | MEDIUM | L |
| 25 | Category Productivity Classification | **GAP** | MEDIUM | M |
| 26 | Time-on-Site Tracking | **GAP** | MEDIUM | L |
| 27 | Department Productivity Comparison | **GAP** | LOW | M |
| | **USER IDENTITY** | | | |
| 28 | Active Directory / LDAP Integration | **GAP** | HIGH | L |
| 29 | IP-to-User Mapping | **PARTIAL** - have src_user from firewalls | HIGH | M |
| 30 | Department/Group Mapping | **GAP** | HIGH | M |
| 31 | Subnet-to-Location Mapping | **GAP** | MEDIUM | S |
| 32 | Browsing Session Grouping | **GAP** | MEDIUM | L |
| 33 | User Activity Timeline (per-user page) | **GAP** | HIGH | L |
| | **BANDWIDTH** | | | |
| 34 | Top Bandwidth Users | **PARTIAL** - have bytes data, no per-user aggregation | HIGH | M |
| 35 | Bandwidth by Application | **PARTIAL** - have app field, no bandwidth breakdown | MEDIUM | M |
| 36 | Bandwidth by Category | **GAP** | MEDIUM | M |
| 37 | Upload vs. Download Split | **PARTIAL** - have sentbyte/rcvdbyte, no aggregation views | MEDIUM | S |
| 38 | Bandwidth Over Time (trends) | **PARTIAL** - have traffic timeline, not bandwidth-specific | MEDIUM | M |
| 39 | Large Transfer Detection & Alert | **GAP** | HIGH | S |
| | **VPN** | | | |
| 40 | VPN Session Summary | **GAP** | MEDIUM | M |
| 41 | VPN User Activity | **GAP** | MEDIUM | M |
| 42 | VPN Bandwidth | **GAP** | LOW | S |
| | **FIREWALL POLICY** | | | |
| 43 | Policy Hit Count | **PARTIAL** - can search by policy, no hit count view | MEDIUM | M |
| 44 | Unused Policy Detection | **GAP** | MEDIUM | M |
| 45 | Policy-to-Traffic Mapping | **PARTIAL** - have policy lookup | MEDIUM | M |
| | **MULTI-FIREWALL** | | | |
| 46 | Palo Alto Networks Support | **HAVE** | - | - |
| 47 | Fortinet FortiGate Support | **HAVE** | - | - |
| 48 | Cisco Firepower Support | **GAP** | LOW | L |
| 49 | SonicWall Support | **GAP** | LOW | L |
| 50 | Sophos Support | **GAP** | LOW | L |

---

## 4. Detailed Gap Analysis

### 4.1 CRITICAL GAPS (Must Have)

#### GAP-01: Scheduled Report Engine
**What Fastvue has:** Automated daily/weekly/monthly reports emailed to managers, filtered by department.
**What we lack:** No report generation engine. No PDF/HTML report templates. No scheduling for report delivery.
**Impact:** This is Fastvue's core value proposition. Without it, Zentryc is a SIEM, not a reporting tool.
**Files to create/modify:**
- NEW: `fastapi_app/services/report_engine.py` — Report generation service
- NEW: `fastapi_app/models/report.py` — Report templates, schedules, recipients
- NEW: `fastapi_app/api/reports.py` — Report CRUD, schedule management, generation API
- NEW: `fastapi_app/templates/reports/` — Report management UI + report output templates
- MODIFY: `fastapi_app/services/scheduler.py` — Add report scheduling jobs

#### GAP-02: User Identity Management (AD/LDAP)
**What Fastvue has:** AD/LDAP integration to map IPs to users, users to departments, track user activity.
**What we lack:** We only get usernames from firewall logs (src_user field). No central user directory. No IP-to-user mapping. No department/group concept.
**Impact:** Can't do per-user reporting, productivity tracking, or department-based analytics.
**Files to create/modify:**
- NEW: `fastapi_app/services/identity_service.py` — AD/LDAP connector, IP-to-user cache
- NEW: `fastapi_app/models/identity.py` — NetworkUser, Department, UserGroup, IPMapping models
- NEW: `fastapi_app/api/identity.py` — Identity management API + user lookup page
- NEW: `fastapi_app/templates/identity/` — User directory, department management UI
- MODIFY: `fastapi_app/db/clickhouse.py` — Add user identity enrichment to log queries

#### GAP-03: User Activity Timeline (Per-User Page)
**What Fastvue has:** Click a user to see their complete browsing history, sessions, searched terms, visited sites, bandwidth.
**What we lack:** No per-user view. Can filter logs by src_ip but no unified user activity page.
**Impact:** Core use case for HR, compliance, and IT investigations.
**Files to create/modify:**
- NEW: `fastapi_app/api/user_activity.py` — Per-user activity API
- NEW: `fastapi_app/templates/user_activity/` — User activity timeline page
- MODIFY: `fastapi_app/api/threat_dashboard.py` — Add user-centric URL/DNS views

#### GAP-04: Search Term Extraction & Keyword Detection
**What Fastvue has:** Extracts search queries from Google/Bing/YouTube URLs, matches against keyword watchlists (self-harm, extremism, etc.), alerts on matches.
**What we lack:** We store full URLs but don't extract search terms. No keyword watchlist system beyond IOCs.
**Impact:** Major compliance/safeguarding gap, especially for education and regulated industries.
**Files to create/modify:**
- NEW: `fastapi_app/services/search_term_extractor.py` — Extract search queries from URLs
- NEW: `fastapi_app/services/keyword_matcher.py` — Keyword watchlist matching engine
- NEW: `fastapi_app/models/keyword.py` — KeywordList, KeywordCategory models
- NEW: `fastapi_app/api/keywords.py` — Keyword management API
- MODIFY: `fastapi_app/services/syslog_collector.py` — Integrate keyword matching in pipeline

### 4.2 HIGH-PRIORITY GAPS

#### GAP-05: Bandwidth Analysis Views
**What Fastvue has:** Dedicated bandwidth dashboard showing top users by bandwidth, bandwidth by app/category, upload/download split, trends over time.
**What we have:** Raw bytes data in logs (sentbyte/rcvdbyte), but no aggregated bandwidth views.
**Files to create/modify:**
- NEW: `fastapi_app/api/bandwidth.py` — Bandwidth analytics API
- NEW: `fastapi_app/templates/bandwidth/` — Bandwidth dashboard page
- MODIFY: `fastapi_app/db/clickhouse.py` — Add bandwidth aggregation queries

#### GAP-06: Report Export (PDF/HTML/CSV)
**What Fastvue has:** Export any report to PDF, CSV, HTML with professional formatting.
**What we have:** CSV export only in audit logs. No PDF. No formatted HTML reports.
**Files to create/modify:**
- NEW: `fastapi_app/services/export_service.py` — PDF (WeasyPrint/ReportLab), HTML, CSV generation
- NEW: `fastapi_app/templates/report_templates/` — Printable report HTML templates
- MODIFY: Multiple API files — Add export endpoints

#### GAP-07: Large Transfer / Anomalous Bandwidth Alerts
**What Fastvue has:** Alerts on large uploads/downloads.
**What we have:** Alert engine exists but no bandwidth-specific rules.
**Files to modify:**
- MODIFY: `fastapi_app/services/alert_engine.py` — Add bandwidth threshold rule type
- MODIFY: Alert rule templates — Add pre-built bandwidth rules

### 4.3 MEDIUM-PRIORITY GAPS

#### GAP-08: Productivity Scoring
**What Fastvue has:** Category-based productivity scoring, time tracking per site, department comparisons.
**What we lack:** No productivity concept at all.
**Files to create/modify:**
- NEW: `fastapi_app/models/productivity.py` — ProductivityCategory, ProductivityScore models
- NEW: `fastapi_app/api/productivity.py` — Productivity API and dashboard
- NEW: `fastapi_app/templates/productivity/` — Productivity dashboard page

#### GAP-09: Site Clean (URL Simplification)
**What Fastvue has:** Makes URLs human-readable, strips tracking params, shows friendly names.
**What we lack:** We display raw URLs.
**Files to create/modify:**
- NEW: `fastapi_app/services/site_clean.py` — URL simplification engine
- MODIFY: `fastapi_app/api/threat_dashboard.py` — Apply site clean to URL display

#### GAP-10: VPN Reporting
**What Fastvue has:** VPN session tracking, VPN user activity, VPN bandwidth.
**What we lack:** No VPN-specific views despite having VPN log data.
**Files to create/modify:**
- NEW: `fastapi_app/api/vpn.py` — VPN analytics API
- NEW: `fastapi_app/templates/vpn/` — VPN dashboard page

#### GAP-11: Browsing Session Grouping
**What Fastvue has:** Groups individual HTTP requests into browsing sessions with timeline view.
**What we lack:** Each log entry is standalone, no session concept for web browsing.
**Files to create/modify:**
- NEW: `fastapi_app/services/session_builder.py` — Group logs into browsing sessions
- MODIFY: `fastapi_app/api/user_activity.py` — Session-based activity view

#### GAP-12: Firewall Policy Analytics
**What Fastvue has:** Policy hit counts, unused policy detection, policy-traffic mapping.
**What we have:** Policy lookup exists but no analytics views.
**Files to create/modify:**
- NEW: `fastapi_app/api/policy_analytics.py` — Policy usage analytics
- MODIFY: `fastapi_app/templates/logs/policy_lookup.html` — Add analytics views

### 4.4 LOWER-PRIORITY GAPS

| Gap | Description | Effort |
|-----|-------------|--------|
| GAP-13 | YouTube video title enrichment | M |
| GAP-14 | Subnet-to-location mapping | S |
| GAP-15 | Department productivity comparison | M |
| GAP-16 | Cisco Firepower parser | L |
| GAP-17 | SonicWall parser | L |
| GAP-18 | Sophos parser | L |

---

## 5. Implementation Plan

### Phase 1: Report Engine & Export (Weeks 1-3) — HIGH IMPACT

The report engine is Fastvue's core differentiator. This phase delivers the ability to generate, schedule, and export professional reports.

#### Sprint 1.1: Report Infrastructure (Week 1)
| Task | Description | Files |
|------|-------------|-------|
| 1.1.1 | Create Report model (template, schedule, recipients, filters) | `models/report.py` |
| 1.1.2 | Create Report API (CRUD, generate, download, schedule) | `api/reports.py` |
| 1.1.3 | Create Report management UI (list, create/edit, schedule config) | `templates/reports/` |
| 1.1.4 | Alembic migration for report tables | `db/migrations/` |

#### Sprint 1.2: Report Generation Engine (Week 2)
| Task | Description | Files |
|------|-------------|-------|
| 1.2.1 | Build report engine service (query → aggregate → render) | `services/report_engine.py` |
| 1.2.2 | Internet Usage report template (top users, top sites, blocked, searches) | `templates/report_templates/internet_usage.html` |
| 1.2.3 | Security report template (threats, blocked, VPN, policy hits) | `templates/report_templates/security.html` |
| 1.2.4 | User Overview report template (per-user activity summary) | `templates/report_templates/user_overview.html` |

#### Sprint 1.3: Export & Scheduling (Week 3)
| Task | Description | Files |
|------|-------------|-------|
| 1.3.1 | PDF export service (WeasyPrint or xhtml2pdf) | `services/export_service.py` |
| 1.3.2 | CSV and HTML export | `services/export_service.py` |
| 1.3.3 | Scheduled report delivery (APScheduler + email) | `services/scheduler.py`, `services/notification_service.py` |
| 1.3.4 | Report history tracking and download management | `api/reports.py` |

**Deliverables:**
- 3 report types (Internet Usage, Security, User Overview)
- PDF/CSV/HTML export for all reports
- Scheduled daily/weekly/monthly email delivery
- Report management UI with schedule configuration

---

### Phase 2: User Identity & Activity (Weeks 4-6) — HIGH IMPACT

This phase adds user identity resolution and per-user activity views — the foundation for productivity tracking and compliance.

#### Sprint 2.1: Identity Infrastructure (Week 4)
| Task | Description | Files |
|------|-------------|-------|
| 2.1.1 | Create NetworkUser, Department, UserGroup models | `models/identity.py` |
| 2.1.2 | IP-to-User mapping table and cache | `models/identity.py`, `services/identity_service.py` |
| 2.1.3 | Manual user directory (CRUD API + UI) | `api/identity.py`, `templates/identity/` |
| 2.1.4 | Firewall src_user extraction and normalization | `services/identity_service.py` |

#### Sprint 2.2: AD/LDAP Integration (Week 5)
| Task | Description | Files |
|------|-------------|-------|
| 2.2.1 | LDAP connector (python-ldap3) — query users, groups, OUs | `services/ldap_service.py` |
| 2.2.2 | Periodic AD sync job (pull users, groups, department info) | `services/scheduler.py` |
| 2.2.3 | DHCP lease / ARP table import for IP-to-user mapping | `services/identity_service.py` |
| 2.2.4 | AD configuration UI (server, base DN, bind credentials, sync interval) | `templates/identity/ad_config.html` |

#### Sprint 2.3: User Activity Page (Week 6)
| Task | Description | Files |
|------|-------------|-------|
| 2.3.1 | User Activity API (per-user log aggregation, top sites, bandwidth, timeline) | `api/user_activity.py` |
| 2.3.2 | User Activity Timeline page (full-page, same style as log viewer) | `templates/user_activity/timeline.html` |
| 2.3.3 | User list/search page with activity summary per user | `templates/user_activity/user_list.html` |
| 2.3.4 | "View User Activity" links from log viewer, threat dashboard, etc. | Multiple templates |

**Deliverables:**
- User directory with AD/LDAP sync
- IP-to-user resolution in log queries
- Per-user activity timeline page
- Department/group management
- User list with activity summaries

---

### Phase 3: Bandwidth & Keyword Analysis (Weeks 7-9) — MEDIUM-HIGH IMPACT

#### Sprint 3.1: Bandwidth Dashboard (Week 7)
| Task | Description | Files |
|------|-------------|-------|
| 3.1.1 | Bandwidth aggregation queries (by user, app, category, time) | `db/clickhouse.py` |
| 3.1.2 | Bandwidth API (top users, top apps, trends, upload/download split) | `api/bandwidth.py` |
| 3.1.3 | Bandwidth dashboard page (same style as log viewer) | `templates/bandwidth/dashboard.html` |
| 3.1.4 | Large transfer alert rule type | `services/alert_engine.py` |

#### Sprint 3.2: Search Term & Keyword Engine (Week 8)
| Task | Description | Files |
|------|-------------|-------|
| 3.2.1 | Search term extractor (Google, Bing, YouTube, DuckDuckGo URL parsing) | `services/search_term_extractor.py` |
| 3.2.2 | Keyword watchlist model and CRUD API | `models/keyword.py`, `api/keywords.py` |
| 3.2.3 | Pre-built keyword categories (violence, self-harm, drugs, profanity) | `services/keyword_matcher.py` |
| 3.2.4 | Integrate keyword matching into syslog pipeline (for URL logs) | `services/syslog_collector.py` |

#### Sprint 3.3: Keyword Dashboard & Alerts (Week 9)
| Task | Description | Files |
|------|-------------|-------|
| 3.3.1 | Keyword match dashboard (matches by category, user, time) | `templates/keywords/dashboard.html` |
| 3.3.2 | Keyword alert integration (alert on keyword match) | `services/alert_engine.py` |
| 3.3.3 | Keyword management UI (lists, categories, import/export) | `templates/keywords/` |
| 3.3.4 | Search term analytics in URL/DNS logs page | `api/threat_dashboard.py` |

**Deliverables:**
- Bandwidth dashboard with top users, apps, trends
- Large transfer alerts
- Search term extraction from URLs
- Keyword watchlist system with pre-built categories
- Keyword match alerts and dashboard

---

### Phase 4: Productivity & Site Clean (Weeks 10-11) — MEDIUM IMPACT

#### Sprint 4.1: Site Clean & Productivity Engine (Week 10)
| Task | Description | Files |
|------|-------------|-------|
| 4.1.1 | URL simplification service (strip trackers, friendly names) | `services/site_clean.py` |
| 4.1.2 | Productivity category model (productive/neutral/unproductive per URL category) | `models/productivity.py` |
| 4.1.3 | Productivity scoring engine (score per user based on browsing) | `services/productivity_service.py` |
| 4.1.4 | Apply Site Clean to all URL displays (threat dashboard, reports) | Multiple files |

#### Sprint 4.2: Productivity Dashboard (Week 11)
| Task | Description | Files |
|------|-------------|-------|
| 4.2.1 | Productivity API (per-user scores, department comparison, trends) | `api/productivity.py` |
| 4.2.2 | Productivity dashboard page | `templates/productivity/dashboard.html` |
| 4.2.3 | Productivity section in scheduled reports | `services/report_engine.py` |
| 4.2.4 | Productivity guidelines configuration UI | `templates/productivity/settings.html` |

**Deliverables:**
- URL simplification across all views
- Productivity scoring system
- Productivity dashboard
- Productivity data in reports

---

### Phase 5: VPN, Policy Analytics & Sessions (Weeks 12-14) — MEDIUM IMPACT

#### Sprint 5.1: VPN Reporting (Week 12)
| Task | Description | Files |
|------|-------------|-------|
| 5.1.1 | VPN log type detection and parsing | `services/parsers/` |
| 5.1.2 | VPN analytics API (sessions, users, bandwidth, duration) | `api/vpn.py` |
| 5.1.3 | VPN dashboard page | `templates/vpn/dashboard.html` |

#### Sprint 5.2: Firewall Policy Analytics (Week 13)
| Task | Description | Files |
|------|-------------|-------|
| 5.2.1 | Policy hit count aggregation queries | `db/clickhouse.py` |
| 5.2.2 | Policy analytics API (hit counts, unused policies, top policies) | `api/policy_analytics.py` |
| 5.2.3 | Policy analytics dashboard | `templates/policy_analytics/` |

#### Sprint 5.3: Browsing Session Grouping (Week 14)
| Task | Description | Files |
|------|-------------|-------|
| 5.3.1 | Session builder (group URL logs into browsing sessions by user+time) | `services/session_builder.py` |
| 5.3.2 | Session timeline view in user activity page | `api/user_activity.py` |
| 5.3.3 | Activity Timeline report template (session-based forensic view) | `templates/report_templates/activity_timeline.html` |

**Deliverables:**
- VPN session dashboard
- Firewall policy usage analytics
- Browsing session grouping
- Activity Timeline report type

---

## Summary: What We Have vs. What We're Adding

### Already Ahead of Fastvue (Our Advantages)
| Zentryc Feature | Fastvue Equivalent |
|----------------|-------------------|
| NQL Query Language | No equivalent — Fastvue is GUI-only |
| Multi-Stage Correlation Engine | No equivalent |
| Threat Intelligence Feeds (STIX/TAXII) | No equivalent |
| IOC Matching (IP/domain/URL/hash) | No equivalent |
| MITRE ATT&CK Mapping | No equivalent |
| Custom Dashboards & Widgets | No equivalent |
| Session Flow Tracing (multi-firewall) | No equivalent |
| Policy Builder (generate CLI commands) | No equivalent |
| Communication Matrix | No equivalent |
| EDL Management | No equivalent |
| Address Object Import | No equivalent |
| AI-Powered Alert Summary | No equivalent |
| API Key Management | No equivalent |
| Webhook Notifications | Limited |

### What Fastvue Has That We're Adding
| Feature | Phase | Priority |
|---------|-------|----------|
| Scheduled Report Engine (PDF/email) | Phase 1 | CRITICAL |
| Report Export (PDF/CSV/HTML) | Phase 1 | CRITICAL |
| AD/LDAP User Identity | Phase 2 | HIGH |
| Per-User Activity Timeline | Phase 2 | HIGH |
| Bandwidth Dashboard | Phase 3 | HIGH |
| Search Term Extraction | Phase 3 | HIGH |
| Keyword Watchlists & Alerts | Phase 3 | HIGH |
| Productivity Scoring | Phase 4 | MEDIUM |
| Site Clean (URL simplification) | Phase 4 | MEDIUM |
| VPN Reporting | Phase 5 | MEDIUM |
| Firewall Policy Analytics | Phase 5 | MEDIUM |
| Browsing Session Grouping | Phase 5 | MEDIUM |

### Timeline Summary
| Phase | Weeks | Focus | Impact |
|-------|-------|-------|--------|
| Phase 1 | 1-3 | Report Engine & Export | CRITICAL |
| Phase 2 | 4-6 | User Identity & Activity | HIGH |
| Phase 3 | 7-9 | Bandwidth & Keywords | HIGH |
| Phase 4 | 10-11 | Productivity & Site Clean | MEDIUM |
| Phase 5 | 12-14 | VPN, Policy, Sessions | MEDIUM |

**Total estimated timeline: 14 weeks (3.5 months)**

---

## Sources

- [Fastvue Reporter Overview](https://www.fastvue.co/reporter-overview/)
- [Fastvue Reporter Features](https://www.fastvue.co/reporter-features/)
- [Fastvue Reporter for Palo Alto Networks](https://www.fastvue.co/paloaltonetworks/)
- [Fastvue Reporter for Fortinet FortiGate](https://www.fastvue.co/fortinet/)
- [Fastvue Reporter for Cisco Firepower](https://www.fastvue.co/ciscofirepower/)
- [Palo Alto Networks & Fastvue Tech Brief](https://www.paloaltonetworks.com/resources/techbriefs/palo-alto-networks-and-fastvue)
- [Cisco Security & Fastvue](https://www.cisco.com/c/en/us/products/security/technical-alliance-partners/fastvue.html)
- [Fastvue Blog: Understanding Report Types](https://www.fastvue.co/fastvue/blog/fastvue-reporter-understanding-internet-usage-safeguarding-it-network-and/)
- [Fastvue Blog: New Report Types](https://www.fastvue.co/fastvue/blog/fastvue-reporter-with-faster-reports-and-new-report-types-is-now-available/)
