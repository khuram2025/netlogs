# Palo Alto Threat & URL Filtering Log Integration Plan

## Executive Summary

Integrate Palo Alto NGFW Threat logs (virus, spyware, vulnerability, wildfire, scan, flood, data, file) and URL Filtering logs (subtype `url` of THREAT type) into Zentryc's syslog pipeline with dedicated ClickHouse storage, full-field parsing, professional analytics UI, and deep correlation capabilities.

**Key insight**: URL Filtering logs are NOT a separate log type. They are THREAT logs with `log_subtype = "url"`. Both share the same CSV field structure (up to 120 fields in PAN-OS 10.2+). Certain fields (`user_agent`, `content_type`, `xff`, `referrer`, `http_method`, `reason`, `justification`) are only populated for the `url` subtype.

---

## Architecture Overview

```
PA Firewall ──UDP 514──► SyslogCollector
                              │
                    ┌─────────┴──────────┐
                    │ parse_syslog_message│
                    │  PaloAltoParser     │
                    └─────────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
         log_type=TRAFFIC  log_type=THREAT  Others
              │               │
              ▼               ▼
        syslogs table    pa_threat_logs table
        (existing)       (NEW - dedicated)
              │               │
              ▼               ▼
        Log Viewer       Threat Dashboard
        (existing)       URL Analytics
                         Correlation Engine
                         Alert Rules
```

**Design principle**: Threat/URL logs get BOTH:
1. A summary row in the existing `syslogs` table (for unified search, NQL, correlation)
2. A full-detail row in the new `pa_threat_logs` table (all 80+ fields for deep analysis)

This avoids bloating the main table while enabling full-field threat analytics.

---

## Phase 1: Storage Layer (ClickHouse Schema)

### Task 1.1: Create `pa_threat_logs` Table

Dedicated MergeTree table optimized for threat/URL log queries.

**File**: `fastapi_app/db/clickhouse.py` — add `ensure_pa_threat_tables()` method

```sql
CREATE TABLE IF NOT EXISTS pa_threat_logs (
    -- Timestamps
    timestamp           DateTime64(3),
    receive_time        DateTime64(3),
    generated_time      DateTime64(3),

    -- Device Identity
    serial_number       String,
    device_name         LowCardinality(String),
    vsys                LowCardinality(String),
    vsys_name           LowCardinality(String),
    device_ip           IPv4,

    -- Log Classification
    log_subtype         LowCardinality(String),  -- virus, spyware, vulnerability, url, wildfire, flood, scan, data, file
    severity            LowCardinality(String),  -- informational, low, medium, high, critical
    direction           LowCardinality(String),  -- client-to-server, server-to-client
    action              LowCardinality(String),  -- alert, allow, deny, drop, reset-client, reset-server, reset-both, block-url

    -- Network 5-Tuple
    src_ip              String,
    dest_ip             String,
    src_port            UInt16,
    dest_port           UInt16,
    transport            LowCardinality(String),  -- tcp, udp, icmp

    -- NAT
    src_translated_ip   String,
    dest_translated_ip  String,
    src_translated_port UInt16,
    dest_translated_port UInt16,

    -- Zones & Interfaces
    src_zone            LowCardinality(String),
    dest_zone           LowCardinality(String),
    src_interface        LowCardinality(String),
    dest_interface       LowCardinality(String),

    -- Identity
    src_user            String,
    dest_user           String,
    application         LowCardinality(String),

    -- Policy
    rule                LowCardinality(String),
    rule_uuid           String,
    log_forwarding_profile LowCardinality(String),

    -- Threat Details
    threat_id           String,       -- "HTTP Trojan.Gen(30001)" format
    threat_name         String,       -- extracted name portion
    threat_numeric_id   UInt64,       -- extracted numeric ID
    threat_category     LowCardinality(String),
    category            LowCardinality(String),  -- URL category or WildFire verdict

    -- URL Filtering Fields (populated when log_subtype = 'url')
    url                 String,       -- from misc field
    content_type        LowCardinality(String),
    user_agent          String,
    http_method         LowCardinality(String),
    xff                 String,       -- X-Forwarded-For
    xff_ip              String,       -- Parsed XFF IP (PAN-OS 10.0+)
    referrer            String,
    reason              String,       -- URL filtering action reason
    justification       String,       -- User continue/override justification

    -- File & WildFire Fields
    file_name           String,       -- from misc field (non-url subtypes)
    file_hash           String,       -- SHA256 for WildFire
    file_type           LowCardinality(String),
    cloud_address       String,
    report_id           String,

    -- Email Fields (WildFire)
    sender              String,
    subject             String,
    recipient           String,

    -- Session
    session_id          UInt64,
    repeat_count        UInt16,
    session_flags       String,
    pcap_id             String,

    -- Geo Location
    src_location        LowCardinality(String),
    dest_location       LowCardinality(String),

    -- Sequence & Versioning
    sequence_number     UInt64,
    action_flags        String,
    content_version     String,

    -- Tunnel (GTP/GPRS)
    tunnel_id           String,
    tunnel_type         LowCardinality(String),

    -- EDL (PAN-OS 10.0+)
    src_edl             String,
    dest_edl            String,

    -- Dynamic Groups (PAN-OS 10.0+)
    dynusergroup_name   String,
    src_dag              String,
    dest_dag             String,

    -- App Metadata (PAN-OS 10.2+)
    subcategory_of_app  LowCardinality(String),
    category_of_app     LowCardinality(String),
    technology_of_app   LowCardinality(String),
    risk_of_app         UInt8,
    is_saas             UInt8,
    sanctioned_state    UInt8,

    -- Device-ID (PAN-OS 10.2+)
    src_dvc_category    LowCardinality(String),
    src_dvc_model       String,
    src_dvc_vendor      LowCardinality(String),
    src_dvc_os          LowCardinality(String),
    src_hostname        String,
    src_mac             String,
    dest_dvc_category   LowCardinality(String),
    dest_dvc_model      String,
    dest_dvc_vendor     LowCardinality(String),
    dest_dvc_os         LowCardinality(String),
    dest_hostname       String,
    dest_mac            String,

    -- URL Category List (PAN-OS 10.0+, up to 4 categories)
    url_category_list   String,

    -- HTTP/2
    http2_connection    UInt32,

    -- Materialized for performance
    log_date            Date MATERIALIZED toDate(timestamp),
    log_hour            UInt8 MATERIALIZED toHour(timestamp),

    -- Indexes
    INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dest_ip dest_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_threat_id threat_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_url url TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_category category TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_rule rule TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_severity severity TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_subtype log_subtype TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_user src_user TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_application application TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_file_hash file_hash TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_zone src_zone TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dest_zone dest_zone TYPE bloom_filter(0.01) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (log_subtype, severity, timestamp)
TTL timestamp + INTERVAL 6 MONTH DELETE
SETTINGS index_granularity = 8192
```

**Column compression codecs** (add after column type):
- `timestamp/receive_time/generated_time`: `CODEC(DoubleDelta, LZ4)`
- `url, user_agent, referrer, raw strings`: `CODEC(ZSTD(3))`
- `UInt16/UInt8 ports`: `CODEC(T64, LZ4)`
- `LowCardinality(String)` fields: auto-optimized by ClickHouse

### Task 1.2: Create Materialized View for Hourly Aggregates

For dashboard performance — pre-aggregate threat stats per hour.

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS pa_threat_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, log_subtype, severity, action, category)
TTL hour + INTERVAL 12 MONTH DELETE
AS SELECT
    toStartOfHour(timestamp) AS hour,
    log_subtype,
    severity,
    action,
    category,
    count() AS event_count,
    uniqExact(src_ip) AS unique_sources,
    uniqExact(dest_ip) AS unique_destinations,
    uniqExact(threat_name) AS unique_threats
FROM pa_threat_logs
GROUP BY hour, log_subtype, severity, action, category
```

### Task 1.3: Create Materialized View for Top Attackers

Rolling window of top threat sources for fast lookup.

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS pa_threat_top_sources_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, src_ip, log_subtype)
TTL day + INTERVAL 3 MONTH DELETE
AS SELECT
    toDate(timestamp) AS day,
    src_ip,
    log_subtype,
    count() AS event_count,
    uniqExact(threat_name) AS unique_threats,
    uniqExact(dest_ip) AS targets_count
FROM pa_threat_logs
GROUP BY day, src_ip, log_subtype
```

**Deliverables**:
- [ ] `ensure_pa_threat_tables()` in clickhouse.py
- [ ] Table creation called from `main.py` lifespan startup
- [ ] Materialized views for hourly aggregates and top sources

---

## Phase 2: Parser Enhancement

### Task 2.1: Rewrite PaloAltoParser Threat/URL CSV Extraction

**File**: `fastapi_app/services/parsers.py` — enhance `PaloAltoParser`

The current parser does basic field extraction. The enhanced parser must:

1. **Detect THREAT log type** from CSV position 4 (`log_type = "THREAT"`)
2. **Extract all 80+ fields** by CSV position (not by name — PA logs are positional CSV)
3. **Parse the threat ID** into name + numeric components:
   - Input: `"HTTP Trojan.Gen Command and Control Traffic(30001)"`
   - Output: `threat_name = "HTTP Trojan.Gen Command and Control Traffic"`, `threat_numeric_id = 30001`
4. **Handle URL vs non-URL subtypes** — route `misc` field to `url` or `file_name`
5. **Parse timestamps** from PA format (`2024/03/15 14:30:22`) to DateTime64
6. **Handle variable field counts** — PAN-OS versions have different field counts (71-120)
7. **Normalize severity** to numeric syslog severity for the `syslogs` table:
   - `informational` → 6, `low` → 5, `medium` → 4, `high` → 3, `critical` → 2

**CSV Parsing strategy**:
```python
# PA CSV has quoted fields that may contain commas
import csv
from io import StringIO

def parse_pa_threat_csv(csv_line: str) -> dict:
    reader = csv.reader(StringIO(csv_line))
    fields = next(reader)
    # Map by position — PA docs define exact positions
    return {
        'receive_time': fields[1] if len(fields) > 1 else '',
        'serial_number': fields[2] if len(fields) > 2 else '',
        'log_type': fields[3] if len(fields) > 3 else '',
        'log_subtype': fields[4] if len(fields) > 4 else '',
        # ... all 80+ fields
    }
```

**Performance requirement**: Parsing must add < 50μs per log at 1000+ EPS.

### Task 2.2: Dual-Write Logic in SyslogCollector

**File**: `fastapi_app/services/syslog_collector.py`

When a parsed log has `log_type = "THREAT"`:
1. Write summary to `syslogs` table (existing flow — srcip, dstip, ports, action, threat_id, severity)
2. Write full record to `pa_threat_logs` table (all extracted fields)

```python
# In flush_to_clickhouse():
threat_batch = []
syslog_batch = []

for log in batch:
    syslog_batch.append(log.to_syslog_row())
    if log.log_type == 'THREAT':
        threat_batch.append(log.to_threat_row())

client.insert('syslogs', syslog_batch, column_names=SYSLOG_COLUMNS)
if threat_batch:
    client.insert('pa_threat_logs', threat_batch, column_names=THREAT_COLUMNS)
```

### Task 2.3: Backfill Existing Threat Logs

For historical PA threat logs already in the `syslogs` table that have `log_type = 'THREAT'`, parse their `raw` or `message` field and insert into `pa_threat_logs`.

**File**: `fastapi_app/db/clickhouse.py` — add `backfill_pa_threat_logs()` method

```python
async def backfill_pa_threat_logs():
    """Re-parse existing THREAT logs from syslogs into pa_threat_logs."""
    client = ClickHouseClient.get_client()
    # Process in chunks of 10,000
    offset = 0
    while True:
        rows = client.query(
            "SELECT raw, device_ip, timestamp FROM syslogs "
            "WHERE log_type = 'THREAT' ORDER BY timestamp "
            "LIMIT 10000 OFFSET %(offset)s",
            parameters={"offset": offset}
        )
        if not rows.result_rows:
            break
        # Parse each raw message and batch insert
        ...
        offset += 10000
```

**Deliverables**:
- [ ] Enhanced `PaloAltoParser.parse_threat_csv()` with all 80+ fields
- [ ] Threat ID decomposition (name + numeric ID)
- [ ] Timestamp parsing from PA format
- [ ] Variable field count handling (PAN-OS 8.x through 11.x)
- [ ] Dual-write logic in syslog collector
- [ ] Backfill script for historical data
- [ ] Unit tests with sample PA threat/URL CSV lines

---

## Phase 3: Query & NQL Integration

### Task 3.1: Extend NQL Valid Fields

**File**: `fastapi_app/services/nql_parser.py`

Add threat/URL-specific fields to `VALID_FIELDS`:

```python
VALID_FIELDS = {
    # Existing fields...
    'srcip', 'dstip', 'srcport', 'dstport', 'proto', 'action',
    'severity', 'policyname', 'log_type', 'application',
    'src_zone', 'dst_zone', 'threat_id',

    # New threat/URL fields
    'log_subtype', 'threat_name', 'threat_category',
    'category',            # URL category or WildFire verdict
    'url',                 # URL for url subtype
    'user_agent',
    'http_method',
    'xff',                 # X-Forwarded-For
    'referrer',
    'content_type',
    'file_hash',
    'file_name',
    'file_type',
    'direction',
    'src_user', 'dest_user',
    'src_location', 'dest_location',
    'rule',
    'serial_number',
    'device_name',
    'src_dvc_category', 'dest_dvc_category',
    'risk_of_app',
    'subcategory_of_app', 'category_of_app',
}
```

### Task 3.2: Add Query Router for Threat Table

When NQL query targets threat-specific fields, route to `pa_threat_logs` table instead of `syslogs`.

```python
THREAT_ONLY_FIELDS = {
    'url', 'user_agent', 'http_method', 'xff', 'referrer',
    'content_type', 'file_hash', 'file_name', 'file_type',
    'threat_name', 'threat_category', 'direction', 'category',
    'src_user', 'dest_user', 'src_location', 'dest_location',
    'log_subtype', 'src_dvc_category', 'dest_dvc_category',
    'risk_of_app', 'reason', 'justification',
}

def get_target_table(query_fields: set) -> str:
    if query_fields & THREAT_ONLY_FIELDS:
        return 'pa_threat_logs'
    return 'syslogs'
```

### Task 3.3: Threat-Specific NQL Examples

Document and test these queries:

```nql
# URL Filtering
log_subtype:url AND category:social-networking
log_subtype:url AND action:block-url AND url:*facebook*
log_subtype:url AND category:malware AND src_user:john.doe

# Threat Detection
severity:critical AND log_subtype:vulnerability
threat_name:*trojan* AND action:alert
log_subtype:spyware AND direction:server-to-client

# WildFire
log_subtype:wildfire AND category:malicious
file_hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# App Risk
risk_of_app:>=4 AND action:allow
category_of_app:peer-to-peer

# Cross-table correlation via NQL pipeline
log_subtype:url AND category:malware | stats count by src_ip | where count > 5
```

**Deliverables**:
- [ ] Extended VALID_FIELDS in NQL parser
- [ ] Query router logic (syslogs vs pa_threat_logs)
- [ ] NQL compiler support for threat table columns
- [ ] Example queries documented and tested

---

## Phase 4: Correlation Rules

### Task 4.1: Pre-Built Threat Correlation Rules

**File**: `fastapi_app/services/correlation_engine.py` + seed data

#### Rule 1: Malware Download Followed by C2 Communication
```python
{
    "name": "Malware Download → C2 Communication",
    "stages": [
        {
            "name": "Malware/Virus Detected",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": ["virus", "wildfire", "wildfire-virus"], "action": "alert"},
            "group_by": "src_ip",
            "threshold": 1,
            "window": 300,
        },
        {
            "name": "C2 Callback Attempt",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "spyware", "threat_category": "command-and-control", "src_ip": "$stage1.src_ip"},
            "threshold": 1,
            "window": 3600,
        }
    ],
    "severity": "critical",
    "mitre_tactic": "Command and Control",
    "mitre_technique": "T1071 - Application Layer Protocol"
}
```

#### Rule 2: Brute Force via URL (Login Page Hammering)
```python
{
    "name": "Brute Force Login Attempts",
    "stages": [
        {
            "name": "Repeated Login Page Access",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "url", "url": "*login*|*signin*|*auth*", "http_method": "POST"},
            "group_by": "src_ip",
            "threshold": 20,
            "window": 300,
        }
    ],
    "severity": "high",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110 - Brute Force"
}
```

#### Rule 3: Reconnaissance → Exploit → Data Exfiltration Chain
```python
{
    "name": "Kill Chain: Recon → Exploit → Exfil",
    "stages": [
        {
            "name": "Port Scan / Vulnerability Probe",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": ["scan", "vulnerability"], "action": ["alert", "deny"]},
            "group_by": "src_ip",
            "threshold": 5,
            "window": 600,
        },
        {
            "name": "Successful Exploit",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "vulnerability", "action": "allow", "src_ip": "$stage1.src_ip"},
            "threshold": 1,
            "window": 1800,
        },
        {
            "name": "Data Exfiltration",
            "table": "syslogs",
            "filter": {"srcip": "$stage1.src_ip", "action": "allow", "dstport": "443|80|53|8080"},
            "threshold": 1,
            "window": 3600,
        }
    ],
    "severity": "critical",
    "mitre_tactic": "Exfiltration",
    "mitre_technique": "T1041 - Exfiltration Over C2 Channel"
}
```

#### Rule 4: Phishing URL Access → Credential Theft
```python
{
    "name": "Phishing Site Access",
    "stages": [
        {
            "name": "Phishing URL Detected",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "url", "category": "phishing"},
            "group_by": "src_ip",
            "threshold": 1,
            "window": 300,
        },
        {
            "name": "Credential Submission",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "url", "http_method": "POST", "src_ip": "$stage1.src_ip"},
            "threshold": 1,
            "window": 300,
        }
    ],
    "severity": "critical",
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1598 - Phishing for Information"
}
```

#### Rule 5: WildFire Malicious Verdict with Allowed Traffic
```python
{
    "name": "WildFire Malicious File Allowed",
    "stages": [
        {
            "name": "WildFire Malicious Verdict",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "wildfire", "category": "malicious", "action": ["alert", "allow"]},
            "group_by": "src_ip",
            "threshold": 1,
            "window": 60,
        }
    ],
    "severity": "critical",
    "mitre_tactic": "Execution",
    "mitre_technique": "T1204 - User Execution"
}
```

#### Rule 6: Internal Lateral Movement via Threat Alerts
```python
{
    "name": "Lateral Movement - Internal Threat Spread",
    "stages": [
        {
            "name": "Internal Source Threat Alert",
            "table": "pa_threat_logs",
            "filter": {"severity": ["high", "critical"], "src_location": "Internal"},
            "group_by": "src_ip",
            "threshold": 3,
            "window": 600,
        },
        {
            "name": "Same Source Targets Multiple Internal Hosts",
            "table": "pa_threat_logs",
            "filter": {"src_ip": "$stage1.src_ip", "dest_location": "Internal"},
            "group_by": "dest_ip",
            "threshold": 3,
            "window": 1800,
        }
    ],
    "severity": "critical",
    "mitre_tactic": "Lateral Movement",
    "mitre_technique": "T1210 - Exploitation of Remote Services"
}
```

#### Rule 7: DNS Tunneling Detection
```python
{
    "name": "DNS Tunneling Suspected",
    "stages": [
        {
            "name": "High-Volume DNS with Threat Signatures",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "spyware", "dest_port": "53", "threat_category": "dns-security"},
            "group_by": "src_ip",
            "threshold": 10,
            "window": 300,
        }
    ],
    "severity": "high",
    "mitre_tactic": "Exfiltration",
    "mitre_technique": "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"
}
```

#### Rule 8: Unauthorized SaaS / Shadow IT
```python
{
    "name": "Unsanctioned SaaS Application Usage",
    "stages": [
        {
            "name": "Unsanctioned SaaS App Access",
            "table": "pa_threat_logs",
            "filter": {"log_subtype": "url", "is_saas": "1", "sanctioned_state": "0"},
            "group_by": "src_user",
            "threshold": 5,
            "window": 3600,
        }
    ],
    "severity": "medium",
    "mitre_tactic": "Collection",
    "mitre_technique": "T1530 - Data from Cloud Storage"
}
```

### Task 4.2: Cross-Table Correlation Support

Extend the correlation engine to support `table` parameter in stage filters, allowing rules to correlate events across `syslogs` and `pa_threat_logs`.

**Deliverables**:
- [ ] 8 pre-built correlation rules seeded on startup
- [ ] Cross-table correlation support in engine
- [ ] MITRE ATT&CK mapping for all rules
- [ ] Unit tests for each rule with sample data

---

## Phase 5: Alert Rules (Threshold-Based)

### Task 5.1: Pre-Built Threat Alert Rules

Seed these alert rules targeting `pa_threat_logs`:

| Rule | Condition | Window | Severity |
|------|-----------|--------|----------|
| Critical Threat Burst | severity:critical count > 10 | 5 min | Critical |
| Malware Outbreak | log_subtype:virus count > 5 group by threat_name | 15 min | Critical |
| URL Category Block Spike | action:block-url count > 50 | 5 min | High |
| WildFire Malicious Upload | log_subtype:wildfire AND category:malicious count > 1 | 1 min | Critical |
| Vulnerability Exploit Wave | log_subtype:vulnerability AND severity:high\|critical count > 20 | 10 min | Critical |
| Single Host Multi-Threat | count > 5 group by src_ip where unique(threat_name) > 3 | 10 min | High |
| Spyware C2 Communication | log_subtype:spyware AND threat_category:command-and-control count > 1 | 5 min | Critical |
| High-Risk App Allowed | risk_of_app >= 4 AND action:allow count > 10 | 15 min | Medium |
| Data Leak Detection | log_subtype:data count > 1 | 5 min | Critical |
| Phishing URL Access | log_subtype:url AND category:phishing count > 1 | 5 min | High |

### Task 5.2: Extend Alert Engine for Threat Table

Add `pa_threat_logs` as a query target in the alert evaluation engine so rules can query threat-specific fields.

**Deliverables**:
- [ ] 10 pre-built alert rules
- [ ] Alert engine extended to query pa_threat_logs
- [ ] Alert enrichment with threat-specific context (threat_name, URL, file_hash)

---

## Phase 6: API Endpoints

### Task 6.1: Threat Log API

**File**: `fastapi_app/api/threat_logs.py` (new file)

```
GET  /api/threats/search          — Search threat logs (NQL + filters)
GET  /api/threats/stats            — Dashboard statistics
GET  /api/threats/timeline         — Event timeline (hourly/daily)
GET  /api/threats/top-threats      — Top threats by count
GET  /api/threats/top-sources      — Top source IPs by threat count
GET  /api/threats/top-destinations — Top destination IPs
GET  /api/threats/top-urls         — Top URLs (url subtype only)
GET  /api/threats/top-categories   — Top URL categories
GET  /api/threats/severity-breakdown — Severity distribution
GET  /api/threats/geo              — Geographic distribution (src/dest locations)
GET  /api/threats/{id}             — Single threat log detail (by sequence_number)
GET  /api/threats/ioc-extract      — Extract IOCs (IPs, hashes, URLs) from threat logs
```

### Task 6.2: URL Filtering API

```
GET  /api/url-filtering/search     — Search URL logs (log_subtype=url)
GET  /api/url-filtering/stats      — URL filtering statistics
GET  /api/url-filtering/categories — Category breakdown with counts
GET  /api/url-filtering/top-users  — Top users by URL access
GET  /api/url-filtering/top-domains — Top domains accessed
GET  /api/url-filtering/blocked    — Blocked URLs with reasons
GET  /api/url-filtering/user-activity/{username} — Per-user URL history
```

### Task 6.3: Threat Intelligence Integration

```
GET  /api/threats/ioc-match        — Match threat log IOCs against loaded threat intel feeds
POST /api/threats/hunt             — Threat hunting: search for specific IOCs across all threat logs
```

**Deliverables**:
- [ ] Threat log search API with pagination, sorting, filtering
- [ ] URL filtering API with category and user analytics
- [ ] IOC extraction and matching endpoints
- [ ] All endpoints use RBAC (VIEWER for read, ANALYST for hunting)

---

## Phase 7: UI — Threat Dashboard

### Task 7.1: Threat Overview Dashboard

**File**: `fastapi_app/templates/threats/dashboard.html`

**Route**: `/threats/`

**Layout**:
```
┌─────────────────────────────────────────────────────────┐
│  THREAT DASHBOARD                        [1h][24h][7d]  │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Total    │ Critical │ High     │ Blocked  │ Unique      │
│ Events   │ Threats  │ Threats  │ URLs     │ Sources     │
│ 12,483   │ 23       │ 156      │ 892      │ 341         │
├──────────┴──────────┴──────────┴──────────┴─────────────┤
│                                                         │
│  [Threat Timeline Chart - Stacked Area by Severity]     │
│  ████████████████████████████████████████████████        │
│                                                         │
├────────────────────────┬────────────────────────────────┤
│ Top Threats            │ Severity Breakdown             │
│ ┌────────────────────┐ │ ┌────────────────────────────┐ │
│ │ Trojan.Gen    342  │ │ │ ██ Critical   23  (1.8%)   │ │
│ │ Exploit.CVE   218  │ │ │ ████ High    156  (12.5%)  │ │
│ │ Spyware.Gen   156  │ │ │ ██████ Med   892  (71.4%)  │ │
│ │ SQL Injection  89  │ │ │ ██ Low      178  (14.3%)   │ │
│ └────────────────────┘ │ └────────────────────────────┘ │
├────────────────────────┼────────────────────────────────┤
│ Top Attackers (srcip)  │ Top Targets (dstip)            │
│ 10.1.5.23       589   │ 192.168.1.50       445         │
│ 10.1.5.45       234   │ 192.168.1.51       312         │
│ 172.16.0.89     178   │ 10.0.0.1           289         │
├────────────────────────┴────────────────────────────────┤
│ Recent Critical/High Threats (live table)               │
│ Time   │ Source   │ Dest     │ Threat      │ Action     │
│ 14:32  │ 10.1.5… │ 192.168… │ Trojan.Gen  │ ⬤ alert   │
│ 14:31  │ 172.16… │ 10.0.0…  │ CVE-2024-…  │ ⬤ drop    │
└─────────────────────────────────────────────────────────┘
```

### Task 7.2: Threat Log Search & Detail View

**File**: `fastapi_app/templates/threats/search.html`

**Route**: `/threats/search/`

- Full-text search with NQL support
- Column-level filters (severity, subtype, action, category, source, dest)
- Time range selector
- Expandable row detail showing ALL parsed fields
- Export to CSV
- "Hunt this IOC" button (searches across all log types)

**Detail View** (`/threats/detail/{sequence_number}`):
- Complete field display in organized sections:
  - **Network**: 5-tuple, NAT, zones, interfaces
  - **Threat**: ID, name, category, severity, direction
  - **Identity**: src_user, dest_user, application
  - **URL** (if url subtype): URL, referrer, user_agent, http_method, content_type
  - **File** (if wildfire/virus): file_name, file_hash, file_type, cloud, report_id
  - **Geo**: source/destination locations
  - **Device-ID**: source/destination device info
  - **Policy**: rule name, UUID, log forwarding profile
  - **Raw**: full raw syslog message

### Task 7.3: URL Filtering Dashboard

**File**: `fastapi_app/templates/threats/url_filtering.html`

**Route**: `/threats/url-filtering/`

**Layout**:
```
┌─────────────────────────────────────────────────────────┐
│  URL FILTERING ANALYTICS                 [1h][24h][7d]  │
├──────────┬──────────┬──────────┬────────────────────────┤
│ Total    │ Blocked  │ Allowed  │ Categories             │
│ URLs     │ URLs     │ URLs     │ Tracked                │
│ 45,891   │ 2,341    │ 43,550   │ 67                     │
├──────────┴──────────┴──────────┴────────────────────────┤
│                                                         │
│  [URL Access Timeline - Stacked by Action]              │
│                                                         │
├──────────────────────────┬──────────────────────────────┤
│ Top Categories           │ Top Blocked Categories       │
│ ┌──────────────────────┐ │ ┌──────────────────────────┐ │
│ │ search-engines 12034 │ │ │ malware          342     │ │
│ │ business       9823  │ │ │ phishing         218     │ │
│ │ social-net     8712  │ │ │ adult-content    156     │ │
│ │ cloud-apps     7234  │ │ │ gambling          89     │ │
│ └──────────────────────┘ │ └──────────────────────────┘ │
├──────────────────────────┼──────────────────────────────┤
│ Top Users by Activity    │ Top Blocked Users             │
│ john.doe     3,421       │ guest-user     145            │
│ jane.smith   2,987       │ contractor1     89            │
│ admin        1,543       │ temp-user        67           │
├──────────────────────────┼──────────────────────────────┤
│ Top Domains Accessed     │ User Agents                   │
│ google.com    8,912      │ Chrome 120     65.2%          │
│ microsoft.com 5,432      │ Firefox 121    18.7%          │
│ office365.com 3,211      │ Safari 17      11.3%          │
├──────────────────────────┴──────────────────────────────┤
│ URL Filtering Log Table (searchable, sortable)          │
│ Time│User│URL│Category│Action│HTTP│User-Agent│Referrer  │
└─────────────────────────────────────────────────────────┘
```

### Task 7.4: Threat Investigation View

**File**: `fastapi_app/templates/threats/investigation.html`

**Route**: `/threats/investigate/{src_ip}`

Single-page investigation view for a source IP:
- **Timeline**: All threat events from this IP ordered by time
- **Threat summary**: Unique threats, categories, severity distribution
- **Target map**: All destination IPs this source targeted
- **URL history**: All URLs accessed (if url subtype)
- **File activity**: Files/hashes associated with this IP
- **Cross-reference**: Related traffic logs from `syslogs` table
- **IOC panel**: Extracted indicators (IPs, domains, hashes) with threat intel match status

### Task 7.5: Navigation Integration

**File**: `fastapi_app/templates/base.html`

Add to SECURITY sidebar section:
```html
<a href="/threats/" class="sb-item" data-tip="Threat Logs" data-path="/threats">
    <span class="sb-item-icon"><svg><!-- shield-alert icon --></svg></span>
    <span class="sb-item-label">Threat Logs</span>
</a>
```

**Deliverables**:
- [ ] Threat dashboard with real-time stats and charts
- [ ] Threat log search page with full NQL support
- [ ] Threat detail view showing all parsed fields
- [ ] URL filtering analytics dashboard
- [ ] Threat investigation view (per-IP deep dive)
- [ ] Sidebar navigation link
- [ ] All pages use dark theme, Chart.js, consistent with existing UI

---

## Phase 8: Performance Optimization

### Task 8.1: Batch Insert Optimization

- Separate batch buffers for `syslogs` and `pa_threat_logs`
- Flush both in single tick (avoid double-latency)
- Async insert settings for ClickHouse:
  ```python
  client.insert(..., settings={
      'async_insert': 1,
      'wait_for_async_insert': 0,
  })
  ```

### Task 8.2: Query Performance

- PREWHERE on indexed columns (severity, log_subtype, action, timestamp)
- Materialized view for dashboard (avoid full-scan aggregations)
- Query timeout: 30 seconds max
- Result limit: 10,000 rows max per query
- Use `log_date` materialized column for date-range partition pruning

### Task 8.3: Memory-Efficient Parsing

- Use `csv.reader` with `StringIO` (not regex) for CSV parsing
- Pre-allocate column name lists as module-level constants
- Avoid dict copies — build insert row as list directly
- Profile with `cProfile` at 1000 EPS to verify < 50μs per parse

**Deliverables**:
- [ ] Separate batch buffers for dual-write
- [ ] PREWHERE optimization in all threat queries
- [ ] Materialized views for dashboard aggregates
- [ ] Parse performance validated at 1000+ EPS

---

## Phase 9: Testing & Validation

### Task 9.1: Sample Log Generator

Create a script that generates realistic PA THREAT/URL CSV logs for testing:

**File**: `scripts/generate_pa_threat_logs.py`

- Generates valid CSV with all field positions
- Configurable: EPS rate, duration, threat mix (virus/spyware/url/etc.)
- Sends via UDP to syslog port for end-to-end testing
- Includes edge cases: empty fields, quoted commas, unicode URLs

### Task 9.2: Parser Unit Tests

**File**: `tests/test_pa_threat_parser.py`

- Test each subtype: virus, spyware, vulnerability, url, wildfire, scan, flood, data, file
- Test variable field counts (PAN-OS 8.1 through 11.x)
- Test quoted CSV fields with embedded commas
- Test threat ID decomposition
- Test timestamp parsing
- Test field normalization (severity string → numeric)

### Task 9.3: Integration Tests

- End-to-end: send UDP → verify in ClickHouse `pa_threat_logs`
- Verify dual-write: same event appears in both `syslogs` and `pa_threat_logs`
- Verify NQL queries work against threat table
- Verify correlation rules trigger correctly
- Verify dashboard API returns correct aggregates

**Deliverables**:
- [ ] Sample log generator script
- [ ] Parser unit tests (all subtypes)
- [ ] Integration tests (end-to-end pipeline)
- [ ] Performance benchmark at 1000 EPS

---

## Implementation Order

| Order | Phase | Task | Effort | Dependencies |
|-------|-------|------|--------|--------------|
| 1 | Phase 1 | ClickHouse table + materialized views | 2h | None |
| 2 | Phase 2 | Parser enhancement (all 80+ fields) | 4h | Phase 1 |
| 3 | Phase 2 | Dual-write in syslog collector | 1h | Phase 2 |
| 4 | Phase 3 | NQL field extension + query router | 2h | Phase 1 |
| 5 | Phase 6 | Threat log API endpoints | 3h | Phase 1, 2 |
| 6 | Phase 7 | Threat dashboard UI | 4h | Phase 6 |
| 7 | Phase 7 | URL filtering dashboard UI | 3h | Phase 6 |
| 8 | Phase 7 | Threat search + detail view | 3h | Phase 6 |
| 9 | Phase 7 | Investigation view | 2h | Phase 6 |
| 10 | Phase 5 | Alert rules for threat table | 2h | Phase 1, 2 |
| 11 | Phase 4 | Correlation rules (8 rules) | 3h | Phase 1, 2, 4 |
| 12 | Phase 8 | Performance optimization | 2h | Phase 2 |
| 13 | Phase 2 | Backfill historical data | 1h | Phase 1, 2 |
| 14 | Phase 9 | Testing & validation | 3h | All |

---

## File Changes Summary

### New Files
| File | Purpose |
|------|---------|
| `fastapi_app/api/threat_logs.py` | API routes + page handlers |
| `fastapi_app/templates/threats/dashboard.html` | Threat overview dashboard |
| `fastapi_app/templates/threats/search.html` | Threat log search |
| `fastapi_app/templates/threats/detail.html` | Single threat event detail |
| `fastapi_app/templates/threats/url_filtering.html` | URL filtering analytics |
| `fastapi_app/templates/threats/investigation.html` | Per-IP investigation |
| `scripts/generate_pa_threat_logs.py` | Test data generator |

### Modified Files
| File | Changes |
|------|---------|
| `fastapi_app/services/parsers.py` | Enhanced PA threat CSV parser |
| `fastapi_app/services/syslog_collector.py` | Dual-write logic for threat logs |
| `fastapi_app/services/nql_parser.py` | Extended fields + query router |
| `fastapi_app/services/correlation_engine.py` | Cross-table support + 8 rules |
| `fastapi_app/services/alert_engine.py` | Threat table query support |
| `fastapi_app/db/clickhouse.py` | `ensure_pa_threat_tables()` + backfill |
| `fastapi_app/main.py` | Router include + table init |
| `fastapi_app/templates/base.html` | Sidebar nav link |

---

## PA Threat Log CSV Field Reference (Quick Lookup)

### Core Fields (Positions 1-36)
| Pos | Field | Type | Key For |
|-----|-------|------|---------|
| 4 | log_type | string | Always "THREAT" |
| 5 | log_subtype | string | virus/spyware/vulnerability/url/wildfire/scan/flood/data/file |
| 8 | src_ip | IP | Network source |
| 9 | dest_ip | IP | Network destination |
| 12 | rule | string | Security policy |
| 13 | src_user | string | Identity |
| 15 | app | string | Application |
| 25 | src_port | int | Source port |
| 26 | dest_port | int | Destination port |
| 31 | action | string | alert/allow/deny/drop/reset/block-url |
| 32 | misc | string | **URL** (url subtype) or **filename** (others) |
| 33 | threat | string | Threat ID + name |
| 34 | category | string | URL category or WildFire verdict |
| 35 | severity | string | informational/low/medium/high/critical |

### URL-Specific Fields
| Pos | Field | Populated When |
|-----|-------|---------------|
| 42 | content_type | subtype = url |
| 47 | user_agent | subtype = url |
| 49 | xff | subtype = url |
| 50 | referrer | subtype = url |
| 64 | http_method | subtype = url |
| 89 | reason | subtype = url (PAN-OS 10.0+) |
| 90 | justification | subtype = url (PAN-OS 10.0+) |

### WildFire-Specific Fields
| Pos | Field | Populated When |
|-----|-------|---------------|
| 44 | file_hash | subtype = wildfire |
| 45 | cloud_address | subtype = wildfire |
| 48 | file_type | subtype = wildfire |
| 51 | sender | subtype = wildfire (email) |
| 52 | subject | subtype = wildfire (email) |
| 53 | recipient | subtype = wildfire (email) |
| 54 | report_id | subtype = wildfire |
