# Phase 4: Advanced Intelligence & Scale

**Timeline:** 8-12 weeks
**Priority:** Medium (Differentiating features)
**Dependencies:** Phase 1-3

---

## 4.1 AI/ML Analytics

### Description
Add machine learning capabilities for behavioral baselining, anomaly detection, and intelligent triage. These features move NetLogs from rule-based detection to adaptive, intelligent threat detection.

### Tasks

#### Task 4.1.1: Behavioral Baselining Engine
**Description:** Learn normal traffic patterns and detect deviations.

**Subtasks:**
- [ ] Create `fastapi_app/services/ml/baseline_engine.py`
- [ ] Add `scikit-learn`, `numpy`, `pandas` to requirements
- [ ] **Traffic volume baselines:**
  - Calculate hourly/daily EPS averages per device
  - Segment by: hour of day, day of week, device
  - Store baselines in PostgreSQL
  - Update weekly with rolling 4-week window
- [ ] **Protocol distribution baselines:**
  - Normal protocol ratios per device (TCP/UDP/ICMP)
  - Port usage patterns (top ports per device)
  - Application distribution
- [ ] **Geographic baselines:**
  - Normal source countries per device
  - New country detection
- [ ] **Anomaly detection algorithms:**
  - Z-score for volume anomalies (>3 standard deviations)
  - IQR method for distribution anomalies
  - Rolling average comparison
- [ ] Scheduled baseline calculation (weekly, configurable)
- [ ] Anomaly alerts integration with alert engine

**Schema:**
```sql
-- Baselines stored in PostgreSQL
CREATE TABLE traffic_baselines (
    id SERIAL PRIMARY KEY,
    device_ip VARCHAR(50),
    metric_name VARCHAR(100),      -- eps, deny_rate, protocol_tcp_pct, etc.
    hour_of_day INTEGER,           -- 0-23
    day_of_week INTEGER,           -- 0-6
    mean FLOAT NOT NULL,
    std_dev FLOAT NOT NULL,
    median FLOAT,
    p95 FLOAT,
    sample_count INTEGER,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(device_ip, metric_name, hour_of_day, day_of_week)
);
```

**Verification:**
- [ ] Baseline calculation completes for all devices
- [ ] Baselines vary by hour of day (business hours vs. night)
- [ ] Baselines vary by day of week (weekday vs. weekend)
- [ ] Z-score anomaly triggers when traffic > 3x normal
- [ ] Normal traffic does NOT trigger anomaly
- [ ] Baseline updates weekly without data loss
- [ ] Performance: Baseline calculation for 1 week of data completes in < 5 min

---

#### Task 4.1.2: Entity Risk Scoring
**Description:** Calculate cumulative risk scores for IPs, devices, and users.

**Subtasks:**
- [ ] Create `fastapi_app/services/ml/risk_scoring.py`
- [ ] **Risk score components:**
  - Alert count (weighted by severity): Critical=10, High=5, Medium=2, Low=1
  - IOC matches: +20 per match
  - Denied traffic ratio: High deny rate = higher risk
  - Anomaly score: Recent anomalies increase risk
  - Geographic risk: Connections from high-risk countries
  - Behavioral deviation: Deviation from baseline
- [ ] **Risk categories:**
  - 0-20: Low risk (green)
  - 21-50: Medium risk (yellow)
  - 51-80: High risk (orange)
  - 81-100: Critical risk (red)
- [ ] Per-IP risk scoring (updated hourly)
- [ ] Per-device risk scoring (aggregated from connected IPs)
- [ ] Risk score history (trend over time)
- [ ] Risk score decay (scores decrease over time without new events)

**Schema (ClickHouse):**
```sql
CREATE TABLE risk_scores (
    timestamp DateTime,
    entity_type String,     -- ip, device, subnet
    entity_value String,
    risk_score UInt8,
    components Map(String, Float32),
    alert_count UInt32,
    ioc_matches UInt32,
    anomaly_score Float32,
    deny_ratio Float32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (entity_type, entity_value, timestamp)
TTL timestamp + INTERVAL 6 MONTH DELETE;
```

**Verification:**
- [ ] Risk score calculates correctly based on components
- [ ] High-activity malicious IPs get critical risk scores
- [ ] Benign IPs get low risk scores
- [ ] Scores decay over time without new events
- [ ] Risk history shows trend over time
- [ ] Device risk aggregates from connected IP scores
- [ ] Performance: Scoring 10,000 entities in < 2 minutes

---

#### Task 4.1.3: Risk Dashboard Widget
**Description:** Display risk scores on dashboard and device pages.

**Subtasks:**
- [ ] Add risk score card to main dashboard:
  - Top 10 highest risk IPs
  - Risk score gauge for overall network
  - Risk trend chart (7 days)
- [ ] Add risk score to device detail page:
  - Device risk gauge
  - Contributing factors breakdown
  - Risk timeline
- [ ] Add risk-based sorting to log viewer:
  - Sort results by source IP risk score
  - Risk indicator next to IP addresses
- [ ] Color-code IPs by risk level throughout UI

**Verification:**
- [ ] Dashboard shows top risk IPs correctly
- [ ] Risk gauge displays correct overall score
- [ ] Device risk shows contributing factors
- [ ] Risk colors appear consistently across pages
- [ ] Risk trend chart shows correct history

---

#### Task 4.1.4: AI Investigation Assistant (Future)
**Description:** Natural language query interface for log investigation.

**Subtasks:**
- [ ] Create `fastapi_app/services/ml/ai_assistant.py`
- [ ] Integrate with Claude API or local LLM
- [ ] **Query translation:**
  - "Show me all denied traffic from Russia today" → NQL query
  - "What was the top threat this week?" → Dashboard summary
  - "Why was 10.0.0.5 blocked?" → Log analysis
- [ ] **Alert summarization:**
  - Generate human-readable summaries of alerts
  - Explain why an alert triggered
  - Suggest investigation steps
- [ ] **Incident summary generation:**
  - Auto-generate incident description from related logs
  - Timeline narrative generation
  - Remediation recommendations
- [ ] Chat interface in sidebar or dedicated page
- [ ] Query history and favorites

**Verification:**
- [ ] Natural language queries translate to correct NQL
- [ ] Alert summaries are accurate and readable
- [ ] Incident summaries capture key events
- [ ] Recommendations are actionable
- [ ] Chat history persists during session
- [ ] API rate limits are respected

---

## 4.2 Extended Firewall Support

### Description
Add parsers and integrations for additional firewall vendors to increase market coverage.

### Tasks

#### Task 4.2.1: Cisco ASA/Firepower Parser
**Description:** Parse Cisco ASA and Firepower threat defense logs.

**Subtasks:**
- [ ] Create parser in `fastapi_app/services/parsers.py`
- [ ] Parse ASA syslog format:
  - `%ASA-severity-message_id: message`
  - Traffic logs (106001-106100 series)
  - Denied connections (106001, 106006, 106007, 106015)
  - VPN events (713000 series)
  - Failover events (104001 series)
- [ ] Extract fields: srcip, dstip, srcport, dstport, protocol, action, interface
- [ ] Map ASA severity to standard levels
- [ ] Add "CISCO" to parser enum
- [ ] Add Cisco SSH integration for routing tables

**Verification:**
- [ ] Sample Cisco ASA logs parse correctly
- [ ] All common message IDs are handled
- [ ] Action field maps correctly (deny, permit, drop)
- [ ] VPN events extract tunnel info
- [ ] Severity maps to standard levels (0-7)
- [ ] Unknown message IDs don't crash parser (graceful fallback)

---

#### Task 4.2.2: Check Point Parser
**Description:** Parse Check Point SmartDefense/SmartEvent logs.

**Subtasks:**
- [ ] Parse Check Point log format (LEA/OPSEC)
- [ ] Support both text and CEF format
- [ ] Extract fields: src, dst, service, action, rule, blade
- [ ] Map Check Point actions (accept, drop, reject, encrypt)
- [ ] Add "CHECKPOINT" to parser enum
- [ ] Handle SmartDefense events (IPS, anti-bot, anti-virus)

**Verification:**
- [ ] Check Point logs parse correctly in text and CEF format
- [ ] All blade types handled (FW, IPS, AB, AV)
- [ ] Rule names extracted correctly
- [ ] Action mapping is accurate

---

#### Task 4.2.3: Sophos XG/XGS Parser
**Description:** Parse Sophos XG Firewall logs.

**Subtasks:**
- [ ] Parse Sophos structured syslog format (key=value pairs)
- [ ] Extract fields: srcip, dstip, srcport, dstport, proto, status
- [ ] Handle log types: Firewall, IPS, Web, Email, ATP
- [ ] Map Sophos statuses (Allow, Deny, Drop)
- [ ] Add "SOPHOS" to parser enum

**Verification:**
- [ ] Sophos key=value logs parse correctly
- [ ] All log types handled
- [ ] Status mapping is accurate

---

#### Task 4.2.4: Juniper SRX Parser
**Description:** Parse Juniper SRX structured syslog.

**Subtasks:**
- [ ] Parse Juniper structured-data syslog format
- [ ] Support RT_FLOW logs (FLOW_SESSION_CREATE, FLOW_SESSION_CLOSE, FLOW_SESSION_DENY)
- [ ] Extract fields: source-address, destination-address, source-port, destination-port, protocol-id
- [ ] Map Juniper policies and zones
- [ ] Add "JUNIPER" to parser enum

**Verification:**
- [ ] Juniper RT_FLOW logs parse correctly
- [ ] Session create/close/deny events handled
- [ ] Zone names extracted correctly

---

#### Task 4.2.5: Auto-Detection of Firewall Vendor
**Description:** Automatically identify the firewall vendor from log format.

**Subtasks:**
- [ ] Create `fastapi_app/services/parser_detector.py`
- [ ] Detection rules:
  - Fortinet: Contains `logid=` and `devname=`
  - Palo Alto: CSV format with TRAFFIC/THREAT/SYSTEM type
  - Cisco ASA: Starts with `%ASA-`
  - Check Point: Contains `product=` and `action=`
  - Sophos: Contains `device_name=` and `log_type=`
  - Juniper: Contains `RT_FLOW` or `[junos`
- [ ] Auto-assign parser on first log from new device
- [ ] Allow manual override
- [ ] Log detection confidence

**Verification:**
- [ ] Correctly identifies each vendor from sample logs
- [ ] New device auto-detects parser type
- [ ] Manual override persists
- [ ] Unknown format falls back to GENERIC
- [ ] Detection runs in < 1ms per log

---

## 4.3 Network Topology & Visualization

### Description
Build an interactive network topology view using routing table data, zone information, and log traffic to visualize the network and security posture.

### Tasks

#### Task 4.3.1: Topology Data Service
**Description:** Build network topology from existing routing and zone data.

**Subtasks:**
- [ ] Create `fastapi_app/services/topology_service.py`
- [ ] **Node discovery:**
  - Firewalls (from approved devices)
  - Subnets (from routing tables)
  - Zones (from zone data)
  - External networks (from log destinations)
- [ ] **Edge discovery:**
  - Routing table entries (device → subnet via interface)
  - Zone-to-zone traffic flows (from logs)
  - Cross-firewall paths (routing hops)
- [ ] **Node metadata:**
  - Device: IP, hostname, vendor, health status, log count
  - Subnet: CIDR, connected interfaces, traffic volume
  - Zone: Name, interfaces, policy count
- [ ] **Edge metadata:**
  - Traffic volume (last 24h)
  - Deny count
  - Policy names
- [ ] Cache topology data (refresh every 15 minutes)
- [ ] Export topology as JSON for frontend rendering

**Verification:**
- [ ] All approved devices appear as nodes
- [ ] Routing entries create correct edges
- [ ] Zone assignments are accurate
- [ ] Traffic volumes on edges match log data
- [ ] Cache refreshes correctly
- [ ] JSON export is valid and complete

---

#### Task 4.3.2: Interactive Topology UI
**Description:** Interactive network map visualization.

**Subtasks:**
- [ ] Add `vis.js` (network visualization) or `D3.js` to static files
- [ ] Create `fastapi_app/templates/topology/network_map.html`
- [ ] **Node rendering:**
  - Firewall icons with vendor-specific styling
  - Subnet circles with CIDR labels
  - Zone boxes containing interfaces
  - Color-coding by health/risk
- [ ] **Edge rendering:**
  - Line thickness by traffic volume
  - Color by traffic type (green=allowed, red=denied)
  - Animated flow direction
- [ ] **Interactions:**
  - Click node: Show device details, recent logs
  - Click edge: Show traffic stats, policies
  - Hover: Quick tooltip with key metrics
  - Zoom/pan/drag
  - Search: Find node by IP or name
- [ ] **Overlays:**
  - Traffic heat map (toggle)
  - Risk score overlay (toggle)
  - Alert indicators (pulsing red on alerting nodes)
- [ ] Layout algorithms: Hierarchical, force-directed, manual
- [ ] Add "Topology" to navigation menu

**Verification:**
- [ ] Map renders all discovered nodes and edges
- [ ] Click interactions show correct details
- [ ] Traffic volume reflects real log data
- [ ] Risk color coding matches risk scores
- [ ] Search finds nodes correctly
- [ ] Map handles 50+ nodes without performance issues
- [ ] Layout is readable and organized

---

#### Task 4.3.3: Zone Traffic Matrix
**Description:** Cross-zone traffic visualization.

**Subtasks:**
- [ ] Create `fastapi_app/templates/topology/zone_matrix.html`
- [ ] **Zone-to-zone matrix:**
  - Rows: source zones
  - Columns: destination zones
  - Cells: traffic volume + deny count
  - Color intensity by volume
  - Click cell: View logs for that zone pair
- [ ] **Policy coverage indicator:**
  - Green: Traffic covered by communication matrix
  - Red: Traffic not in communication matrix
  - Yellow: Partially covered
- [ ] Filter by device, time range
- [ ] Export as CSV

**Verification:**
- [ ] Matrix shows all zone combinations
- [ ] Traffic counts match log data
- [ ] Click drill-down shows correct logs
- [ ] Policy coverage colors are accurate
- [ ] Export contains all data

---

## 4.4 GeoIP & Enrichment

### Description
Add geographic, DNS, and organizational context to IP addresses throughout the platform.

### Tasks

#### Task 4.4.1: GeoIP Integration
**Description:** Enrich IPs with geographic data.

**Subtasks:**
- [ ] Add `geoip2` and `maxminddb` to requirements
- [ ] Download GeoLite2-City database (free with registration)
- [ ] Create `fastapi_app/services/enrichment/geoip_service.py`
- [ ] **Lookup capabilities:**
  - Country name and code
  - City
  - Latitude/longitude
  - ASN (Autonomous System Number)
  - ISP/Organization name
- [ ] In-memory database loading for performance
- [ ] Automatic database updates (monthly)
- [ ] Skip private/RFC1918 IPs
- [ ] Cache results (1-hour TTL)

**Verification:**
- [ ] Known public IPs return correct country
- [ ] Private IPs return "Private/Internal"
- [ ] ASN lookup returns ISP name
- [ ] Cache prevents redundant lookups
- [ ] Database loads in < 5 seconds
- [ ] Lookup completes in < 1ms per IP

---

#### Task 4.4.2: GeoIP Dashboard Integration
**Description:** Add geographic data to dashboards and log viewer.

**Subtasks:**
- [ ] **Dashboard additions:**
  - World map showing attack origins (colored markers)
  - "Top Source Countries" table with flag icons
  - "Unusual Source Countries" alert widget
- [ ] **Log viewer additions:**
  - Country flag icon next to external IPs
  - Country column (toggleable)
  - Filter by country
- [ ] **Device detail additions:**
  - Traffic by country breakdown
  - Country distribution chart
- [ ] Country flag CSS sprites or emoji flags

**Verification:**
- [ ] World map shows attack markers at correct locations
- [ ] Country flags display correctly
- [ ] Country filter returns correct results
- [ ] Internal IPs don't show country data
- [ ] Performance: Map renders with 1000+ markers

---

#### Task 4.4.3: DNS Reverse Lookup Service
**Description:** Resolve IPs to hostnames for context.

**Subtasks:**
- [ ] Create `fastapi_app/services/enrichment/dns_service.py`
- [ ] Async DNS resolver (using `aiodns`)
- [ ] Reverse DNS lookup with timeout (2 seconds)
- [ ] Cache results (1-hour TTL, 50,000 entry limit)
- [ ] Show hostname next to IPs in log viewer
- [ ] Batch resolution for dashboard tables

**Verification:**
- [ ] Known IPs resolve to correct hostnames
- [ ] Timeout prevents hanging on unresolvable IPs
- [ ] Cache serves repeated lookups instantly
- [ ] Hostnames display in log viewer

---

## 4.5 Firewall Policy Intelligence

### Description
Analyze firewall policies using log data to identify unused rules, optimization opportunities, and compliance gaps.

### Tasks

#### Task 4.5.1: Rule Usage Analysis
**Description:** Track which firewall rules are used based on log data.

**Subtasks:**
- [ ] Create `fastapi_app/services/policy_intelligence.py`
- [ ] **Rule hit tracking:**
  - Aggregate log entries by `policyname` per device
  - Track: hit count, last hit, first hit, unique sources, unique destinations
  - Store in ClickHouse materialized view
- [ ] **Rule analysis:**
  - Unused rules: No hits in last 30/60/90 days
  - Shadow rules: Rules that are never matched because earlier rules catch traffic
  - Overly permissive: Rules with "any" source/destination that could be tightened
  - High-deny rules: Rules generating most denied traffic
- [ ] **Recommendations:**
  - "Remove unused rule X (no hits in 90 days)"
  - "Tighten rule Y (only 3 unique sources, but allows any)"
  - "Reorder rule Z (shadowed by rule W)"

**Verification:**
- [ ] Hit counts match actual log data per policy
- [ ] Unused rules correctly identified (verified against logs)
- [ ] Recommendations are actionable and accurate
- [ ] Analysis runs in < 60 seconds for 1000 rules

---

#### Task 4.5.2: Communication Matrix Compliance Check
**Description:** Compare actual traffic against communication matrix to find violations.

**Subtasks:**
- [ ] Create `fastapi_app/services/compliance_checker.py`
- [ ] For each project's communication matrix:
  - Query actual traffic between source and destination
  - Identify allowed traffic NOT in matrix (unauthorized flows)
  - Identify matrix entries with zero traffic (unused rules)
  - Identify denied traffic that matches matrix entries (misconfiguration)
- [ ] Generate compliance report:
  - Compliant flows (in matrix, allowed in logs)
  - Unauthorized flows (not in matrix, allowed in logs)
  - Missing flows (in matrix, not seen in logs)
  - Blocked flows (in matrix, denied in logs)
- [ ] Schedule compliance checks (daily)
- [ ] Alert on unauthorized flows

**Verification:**
- [ ] Compliant flows correctly identified
- [ ] Unauthorized flows detected and reported
- [ ] Missing flows reported for investigation
- [ ] Blocked flows flag misconfiguration
- [ ] Scheduled check runs daily
- [ ] Alerts generate for critical violations

---

#### Task 4.5.3: Policy Intelligence UI
**Description:** UI for viewing policy analysis results.

**Subtasks:**
- [ ] Create `fastapi_app/templates/policy/policy_analysis.html`
  - Rule usage table: policy name, hit count, last hit, status (active/stale/unused)
  - Recommendations list with action buttons
  - Compliance status per project
  - Compliance detail: compliant/unauthorized/missing/blocked flows
  - Export analysis as PDF report
- [ ] Add to device detail page: "Policy Analysis" tab
- [ ] Add to project detail page: "Compliance Check" button

**Verification:**
- [ ] Rule usage table shows correct data
- [ ] Recommendations display with appropriate actions
- [ ] Compliance check results are accurate
- [ ] Export generates complete report

---

## 4.6 API & Integration Hub

### Tasks

#### Task 4.6.1: REST API v2 (Comprehensive)
**Description:** Full-featured API for all platform capabilities.

**Subtasks:**
- [ ] Create `/api/v2/` prefix for new API version
- [ ] Consistent response format:
  ```json
  {
    "status": "success",
    "data": {...},
    "meta": {"total": 100, "page": 1, "per_page": 20},
    "timestamp": "2026-02-08T12:00:00Z"
  }
  ```
- [ ] OpenAPI 3.0 documentation with examples
- [ ] Rate limiting per API key
- [ ] Webhook registration API:
  - `POST /api/v2/webhooks/` - Register webhook
  - Events: alert.created, incident.created, device.status_changed, playbook.completed
- [ ] Bulk operations:
  - `POST /api/v2/logs/search` - Advanced search with NQL
  - `POST /api/v2/devices/bulk-update` - Bulk device operations
  - `POST /api/v2/edl/bulk-import` - Bulk EDL import
- [ ] Streaming API (Server-Sent Events):
  - `GET /api/v2/stream/alerts` - Real-time alert stream
  - `GET /api/v2/stream/logs` - Real-time log stream

**Verification:**
- [ ] All endpoints return consistent response format
- [ ] OpenAPI docs are complete and accurate
- [ ] Rate limiting enforces limits correctly
- [ ] Webhooks fire on correct events
- [ ] Bulk operations handle large datasets
- [ ] SSE streams deliver real-time data
- [ ] Authentication required for all endpoints

---

#### Task 4.6.2: Syslog Forwarding
**Description:** Forward received logs to other SIEM platforms.

**Subtasks:**
- [ ] Create `fastapi_app/services/log_forwarder.py`
- [ ] Forward logs via:
  - UDP syslog (RFC3164/5424)
  - TCP syslog with TLS
  - CEF format
  - JSON over HTTP(S)
- [ ] Configurable destinations (multiple)
- [ ] Filter which logs to forward (by device, severity, action)
- [ ] Buffer and retry on failure
- [ ] Forward statistics (count, errors, lag)

**Verification:**
- [ ] Logs forward to UDP destination
- [ ] Logs forward to TCP/TLS destination
- [ ] CEF format is valid
- [ ] Filters work correctly
- [ ] Buffer handles destination outage
- [ ] Statistics track accurately

---

## Phase 4 Completion Criteria

- [ ] Behavioral baselines calculate for all devices
- [ ] Anomaly detection triggers on traffic spikes
- [ ] Entity risk scores calculate for all active IPs
- [ ] At least 2 new firewall parsers work (Cisco + 1 other)
- [ ] Auto-detection correctly identifies firewall vendor
- [ ] Network topology map renders with real data
- [ ] Zone traffic matrix shows cross-zone flows
- [ ] GeoIP enrichment adds country data to logs
- [ ] World map visualization works on dashboard
- [ ] Rule usage analysis identifies unused policies
- [ ] Communication matrix compliance check runs
- [ ] API v2 is documented and functional
- [ ] All verification tests pass
