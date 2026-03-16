# Verification Master Plan

**Purpose:** This document defines the complete testing and verification strategy for all improvement phases. Each section maps to tasks in the phase documents and provides specific, measurable test cases.

---

## 1. Testing Strategy Overview

### Test Categories

| Category | Description | Tools |
|----------|-------------|-------|
| Unit Tests | Individual function/method testing | pytest, pytest-asyncio |
| Integration Tests | Component interaction testing | pytest, httpx, TestClient |
| API Tests | REST API endpoint testing | httpx, pytest, curl |
| UI Tests | Frontend functionality testing | Playwright, manual verification |
| Performance Tests | Load and stress testing | locust, ab (Apache Bench) |
| Security Tests | Auth, RBAC, injection testing | manual, OWASP ZAP |
| End-to-End Tests | Full workflow testing | Playwright, manual |

### Test Environment Setup

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx pytest-cov locust

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=fastapi_app --cov-report=html

# Run specific phase tests
pytest tests/phase1/ -v
pytest tests/phase2/ -v
```

### Test Directory Structure
```
tests/
  conftest.py                    # Shared fixtures
  phase1/
    test_auth.py                 # Authentication tests
    test_rbac.py                 # RBAC permission tests
    test_alert_engine.py         # Alert rule evaluation
    test_notifications.py        # Notification delivery
    test_audit_log.py            # Audit logging
    test_api_keys.py             # API key management
  phase2/
    test_threat_intel.py         # Threat intel integration
    test_ioc_matcher.py          # IOC matching
    test_correlation.py          # Correlation engine
    test_nql_parser.py           # Query language parser
    test_saved_searches.py       # Saved search functionality
  phase3/
    test_playbook_engine.py      # Playbook execution
    test_incident_mgmt.py        # Incident lifecycle
    test_report_generation.py    # Report creation
  phase4/
    test_baseline_engine.py      # ML baselines
    test_risk_scoring.py         # Risk score calculation
    test_parsers_extended.py     # New firewall parsers
    test_geoip.py                # GeoIP enrichment
    test_topology.py             # Network topology
  quick_wins/
    test_log_export.py           # Export functionality
    test_device_health.py        # Health checks
    test_cisco_parser.py         # Cisco ASA parser
```

---

## 2. Phase 1 Verification Plan

### 2.1 Authentication Testing

#### VP-1.1.1: User Registration & Login
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Login with valid credentials | POST `/auth/login` with valid username/password | 200 OK, session cookie set | |
| 2 | Login with wrong password | POST `/auth/login` with wrong password | 401 Unauthorized, "Invalid credentials" message | |
| 3 | Login with non-existent user | POST `/auth/login` with unknown username | 401 Unauthorized, same error as wrong password (no user enumeration) | |
| 4 | Access protected page without login | GET `/dashboard/` without session | 302 Redirect to `/auth/login` | |
| 5 | Access protected API without login | GET `/api/devices/` without session | 401 Unauthorized JSON response | |
| 6 | Logout | POST `/auth/logout` | Session invalidated, redirect to login | |
| 7 | Reuse session after logout | GET `/dashboard/` with old session cookie | 302 Redirect to `/auth/login` | |
| 8 | Session expiry | Wait for session timeout, then access page | 302 Redirect to `/auth/login` | |
| 9 | Account lockout | 5 failed login attempts | Account locked, "Account locked" message | |
| 10 | Account unlock | Wait 15 minutes after lockout | Login succeeds | |
| 11 | Password hash verification | Query DB for user record | password_hash is bcrypt hash (starts with `$2b$`) | |
| 12 | Default admin exists | Fresh install, check DB | admin user exists with ADMIN role | |
| 13 | Concurrent sessions | Login from 2 browsers | Both sessions work independently | |

#### VP-1.1.2: RBAC Permission Tests
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Admin accesses user management | Login as ADMIN, GET `/api/users/` | 200 OK with user list | |
| 2 | Analyst accesses user management | Login as ANALYST, GET `/api/users/` | 403 Forbidden | |
| 3 | Viewer accesses user management | Login as VIEWER, GET `/api/users/` | 403 Forbidden | |
| 4 | Analyst approves device | Login as ANALYST, POST `/api/devices/1/approve` | 200 OK (allowed) | |
| 5 | Viewer approves device | Login as VIEWER, POST `/api/devices/1/approve` | 403 Forbidden | |
| 6 | Viewer views dashboard | Login as VIEWER, GET `/dashboard/` | 200 OK | |
| 7 | Admin changes system settings | Login as ADMIN, POST `/api/system/storage-settings/` | 200 OK | |
| 8 | Analyst changes system settings | Login as ANALYST, POST `/api/system/storage-settings/` | 403 Forbidden | |
| 9 | Nav bar items by role | Login as each role, check nav HTML | Only permitted items visible | |
| 10 | Direct URL bypass | Login as VIEWER, navigate to `/system/` directly | 403 Forbidden page | |

### 2.2 Alert Engine Testing

#### VP-1.3.1: Alert Rule Evaluation
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Threshold rule triggers | Insert 150 deny logs from same IP in 5 min, rule threshold=100 | Alert created with severity matching rule | |
| 2 | Threshold rule doesn't trigger | Insert 50 deny logs from same IP in 5 min, rule threshold=100 | No alert created | |
| 3 | Pattern rule - all conditions | Insert 20 deny logs to port 22 from same IP | Alert created (brute force pattern) | |
| 4 | Pattern rule - partial match | Insert 20 deny logs to port 80 (rule requires port 22) | No alert created | |
| 5 | Absence rule triggers | Approved device sends no logs for 15 min, rule timeout=10 | Alert created "Device offline" | |
| 6 | Absence rule - device sending | Device sent log 2 min ago, rule timeout=10 | No alert created | |
| 7 | Cooldown enforcement | Trigger same rule twice within 15 min cooldown | Only 1 alert created | |
| 8 | Cooldown expired | Trigger rule, wait 16 min, trigger again | 2 alerts created | |
| 9 | Disabled rule | Disable rule, trigger conditions | No alert created | |
| 10 | Multiple rules match | Same logs match 2 different rules | 2 separate alerts created | |
| 11 | Rule with group_by | 3 IPs each with 50 denies, threshold=100 | No alert (each IP under threshold) | |
| 12 | Engine error recovery | Rule with invalid config | Engine logs error, continues with other rules | |

#### VP-1.3.2: Notification Testing
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Email notification | Trigger alert with email channel | Email received with alert details | |
| 2 | Email HTML format | Check received email | Proper HTML formatting, severity badge, link | |
| 3 | Telegram notification | Trigger alert with Telegram channel | Message in Telegram chat with details | |
| 4 | Webhook notification | Trigger alert with webhook channel | POST received at webhook URL with JSON | |
| 5 | Rate limiting | Trigger 15 alerts in 1 minute | Only 10 notifications sent (rate limit) | |
| 6 | Test notification | Click "Test" button for email channel | Test email received | |
| 7 | Failed notification | Configure invalid SMTP, trigger alert | Error logged, alert still created | |
| 8 | Multiple channels | Rule linked to email + telegram | Both notifications sent | |

### 2.3 Audit Log Testing

#### VP-1.4.1: Audit Trail
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Login audit | User logs in | Audit entry: action=login, user=X, ip=Y | |
| 2 | Failed login audit | Failed login attempt | Audit entry: action=login_failed, user=X | |
| 3 | Device approve audit | Admin approves device | Audit entry: action=approve, resource=device:IP | |
| 4 | Settings change audit | Admin changes storage settings | Audit entry with before/after values | |
| 5 | Audit immutability | Try to delete audit logs via SQL | Operation blocked or not available to users | |
| 6 | Audit viewer filters | Filter by user, action, date | Correct results returned | |
| 7 | Audit CSV export | Export filtered audit data | CSV contains all matching entries | |

### 2.4 API Key Testing

#### VP-1.5.1: API Key Management
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Create API key | POST `/api/keys/` | 201 Created, full key shown once | |
| 2 | Use valid API key | GET `/api/devices/` with `X-API-Key` header | 200 OK with data | |
| 3 | Use invalid key | GET `/api/devices/` with wrong key | 401 Unauthorized | |
| 4 | Use expired key | Create key with past expiry, use it | 401 Unauthorized | |
| 5 | Revoke key | DELETE `/api/keys/{id}`, then use key | 401 Unauthorized | |
| 6 | Rate limiting | Send 120 requests in 1 minute | Last 20 return 429 Too Many Requests | |
| 7 | Key permissions | Create read-only key, try POST request | 403 Forbidden | |
| 8 | List keys | GET `/api/keys/` | Shows key prefix, not full key | |

---

## 3. Phase 2 Verification Plan

### 3.1 Threat Intelligence Testing

#### VP-2.1.1: Feed Ingestion
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | CSV feed import | Configure CSV feed URL, trigger fetch | IOCs loaded into database | |
| 2 | STIX/TAXII feed | Configure TAXII server, trigger fetch | STIX indicators converted to IOCs | |
| 3 | Manual IOC add | Add single IP IOC via UI | IOC saved with correct type and severity | |
| 4 | Bulk IOC import | Upload CSV with 1000 IOCs | All IOCs imported, duplicates handled | |
| 5 | IOC deduplication | Import same IOC from 2 feeds | Single IOC entry (merged) | |
| 6 | IOC expiration | Add IOC with past expiry | IOC marked inactive | |
| 7 | Scheduled update | Wait for feed update interval | Feed re-fetched, new IOCs added | |
| 8 | Feed failure handling | Configure invalid URL | Error logged, other feeds unaffected | |

#### VP-2.1.2: IOC Matching
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | IP match - source | Add malicious IP to IOCs, send log with that srcip | Match recorded in ioc_matches | |
| 2 | IP match - destination | Add malicious IP, send log with that dstip | Match recorded | |
| 3 | No match | Send log with clean IPs | No match recorded | |
| 4 | Expired IOC no match | Add expired IOC, send matching log | No match (IOC inactive) | |
| 5 | Match creates alert | IOC match occurs | Alert created with threat context | |
| 6 | Auto-block triggers | High-confidence match | IP added to auto-block EDL | |
| 7 | Performance | 50K IOCs loaded, 10K logs/sec | Matching adds < 5% latency | |
| 8 | Cache refresh | Add new IOC, wait 5 min | New IOC detected in next batch | |

### 3.2 Correlation Engine Testing

#### VP-2.2.1: Multi-Stage Correlation
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Two-stage match | Stage 1: 10 denies, Stage 2: allow from same IP | Correlation alert created | |
| 2 | Stage 1 only | 10 denies but no allow follows | No correlation alert | |
| 3 | Variable substitution | Stage 2 uses $stage1.srcip | Correct IP carried between stages | |
| 4 | Time window expired | Stage 2 event occurs after window | No correlation | |
| 5 | Multi-firewall | Same srcip denied on 3 firewalls | Cross-device correlation alert | |
| 6 | Alert includes chain | Correlation triggers | Alert details show all matching events | |

### 3.3 NQL Parser Testing

#### VP-2.4.1: Query Language
| # | Test Case | Input | Expected SQL/Result | Status |
|---|-----------|-------|---------------------|--------|
| 1 | Simple field match | `srcip:10.0.0.1` | WHERE srcip = '10.0.0.1' | |
| 2 | CIDR filter | `srcip:10.0.0.0/8` | WHERE isIPAddressInRange(srcip, '10.0.0.0/8') | |
| 3 | Comparison | `dstport:>1024` | WHERE dstport > 1024 | |
| 4 | AND operator | `srcip:10.0.0.1 AND action:deny` | WHERE srcip = '10.0.0.1' AND action = 'deny' | |
| 5 | OR operator | `srcip:10.0.0.1 OR srcip:10.0.0.2` | WHERE srcip IN ('10.0.0.1', '10.0.0.2') | |
| 6 | Negation | `NOT action:allow` | WHERE action != 'allow' | |
| 7 | Parentheses | `(a:1 OR a:2) AND b:3` | WHERE (a IN ('1','2')) AND b = '3' | |
| 8 | Pipeline stats | `action:deny \| stats count by srcip` | GROUP BY srcip count | |
| 9 | Pipeline where | `\| where count > 100` | HAVING count > 100 | |
| 10 | Pipeline sort | `\| sort -count` | ORDER BY count DESC | |
| 11 | Text search | `"connection refused"` | WHERE message LIKE '%connection refused%' | |
| 12 | Invalid syntax | `srcip:` | Error: "Expected value after ':'" | |
| 13 | Wildcard | `srcip:192.168.*` | WHERE srcip LIKE '192.168.%' | |

---

## 4. Phase 3 Verification Plan

### 4.1 Playbook Engine Testing

#### VP-3.1.1: Playbook Execution
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Linear playbook | Execute 3-step playbook (enrich → alert → notify) | All 3 steps complete, history records all | |
| 2 | Condition branch - true | Condition: ioc_match == true (IOC exists) | Takes on_true path | |
| 3 | Condition branch - false | Condition: ioc_match == true (no IOC) | Takes on_false path | |
| 4 | Error handling | Step fails (SSH timeout) | on_failure path taken, error logged | |
| 5 | Approval gate | Step has requires_approval=true | Execution pauses, approval notification sent | |
| 6 | Approval granted | Approve pending execution | Execution resumes from paused step | |
| 7 | Approval denied | Deny pending execution | Execution cancelled, status=cancelled | |
| 8 | EDL action | Step: add_to_edl | IP added to specified EDL list | |
| 9 | Alert trigger | Playbook triggered by alert rule | Playbook receives alert data as input | |
| 10 | Manual trigger | Click "Execute" button on playbook | Playbook runs with manual input | |
| 11 | Dry run | Click "Test" button | Steps simulated without actual actions | |
| 12 | Variable substitution | $alert.srcip in step params | Correct IP value substituted | |
| 13 | Step timeout | Step takes > 30s | Step fails with timeout error | |
| 14 | Concurrent execution | 2 alerts trigger same playbook simultaneously | Both executions run independently | |

### 4.2 Incident Management Testing

#### VP-3.2.1: Incident Lifecycle
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Create incident | POST `/api/incidents/` with required fields | 201 Created with correct data | |
| 2 | Create from alert | Click "Create Incident" on alert | Incident pre-populated with alert data | |
| 3 | Status: new → investigating | Change status | Status updated, acknowledged_at set | |
| 4 | Status: investigating → containment | Change status | Status updated, containment_at set | |
| 5 | Status: → resolved | Resolve with notes | resolved_at set, resolution_notes saved | |
| 6 | Status: → closed | Close incident | closed_at set | |
| 7 | Invalid status transition | Try new → resolved (skip steps) | Allowed (flexible flow) or error (strict) | |
| 8 | Add comment | POST comment to incident | Comment appears in timeline | |
| 9 | Add evidence | Upload file/log snapshot | Evidence attached and viewable | |
| 10 | Assign user | Assign to analyst | assigned_to updated, notification sent | |
| 11 | SLA: time_to_acknowledge | Create then acknowledge incident | Correct seconds calculated | |
| 12 | SLA: time_to_resolve | Create then resolve incident | Correct seconds calculated | |
| 13 | MTTR calculation | Resolve 5 incidents | Average MTTR calculates correctly | |
| 14 | Timeline order | Multiple actions on incident | Timeline shows chronological order | |

### 4.3 Report Generation Testing

#### VP-3.3.1: Reports
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | HTML report | Generate daily summary | HTML renders with data and charts | |
| 2 | PDF report | Generate PDF from template | PDF file valid, readable, correct data | |
| 3 | CSV export | Export report data as CSV | CSV has correct columns and values | |
| 4 | Empty data report | Generate report for period with no data | Report generates without error, shows "No data" | |
| 5 | Scheduled report | Configure daily schedule | Report auto-generates at scheduled time | |
| 6 | Email delivery | Schedule with email recipients | Email sent with report attachment | |
| 7 | Report archive | Generate 3 reports | All 3 available in archive for download | |
| 8 | Custom template | Create custom report with 4 sections | Report includes all configured sections | |
| 9 | Large data report | Generate monthly report (millions of logs) | Completes within 60 seconds | |

---

## 5. Phase 4 Verification Plan

### 5.1 ML/Baseline Testing

#### VP-4.1.1: Behavioral Baselines
| # | Test Case | Steps | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Baseline calculation | Run baseline on 4 weeks of data | Baselines created per device, hour, day | |
| 2 | Weekday vs weekend | Compare baselines | Business hours show higher mean EPS | |
| 3 | Anomaly detection | Inject 5x normal traffic | Anomaly alert triggered (Z-score > 3) | |
| 4 | Normal traffic | Send normal volume traffic | No anomaly alert | |
| 5 | Baseline update | Run recalculation with new week | Baselines shift to include new data | |
| 6 | New device | Device with < 1 week data | Baseline skipped (insufficient data) | |

### 5.2 Extended Parser Testing

#### VP-4.2.1: Cisco ASA Parser
| # | Test Case | Input Log | Expected Parsed Fields | Status |
|---|-----------|-----------|----------------------|--------|
| 1 | Denied connection | `%ASA-4-106023: Deny tcp src inside:10.0.0.1/1234 dst outside:8.8.8.8/80` | action=deny, srcip=10.0.0.1, dstip=8.8.8.8, dstport=80, proto=tcp | |
| 2 | Permitted connection | `%ASA-6-302013: Built outbound TCP...` | action=allow, session info extracted | |
| 3 | Session teardown | `%ASA-6-302014: Teardown TCP...` | session duration, bytes transferred | |
| 4 | Unknown message ID | `%ASA-5-999999: Unknown message` | Falls back to generic parsing | |
| 5 | Malformed log | `incomplete ASA log` | No crash, returns partial or generic parse | |

#### VP-4.2.2: Auto-Detection
| # | Test Case | Log Sample | Expected Parser | Status |
|---|-----------|-----------|-----------------|--------|
| 1 | Fortinet log | `logid=0001 devname=FGT-1` | FORTINET | |
| 2 | Palo Alto log | `1,2024/01/01,TRAFFIC,...` | PALOALTO | |
| 3 | Cisco ASA log | `%ASA-4-106023: Deny...` | CISCO | |
| 4 | Unknown format | Random syslog text | GENERIC | |
| 5 | New device auto-assign | Send first log from new device | Parser auto-detected and saved | |

### 5.3 GeoIP Testing

#### VP-4.4.1: GeoIP Enrichment
| # | Test Case | Input | Expected Result | Status |
|---|-----------|-------|-----------------|--------|
| 1 | Known public IP | 8.8.8.8 | Country: US, City: Mountain View, ASN: Google | |
| 2 | Private IP | 192.168.1.1 | "Private/Internal" (no lookup) | |
| 3 | Invalid IP | 999.999.999.999 | Graceful handling, no crash | |
| 4 | Cache hit | Same IP queried twice | Second query returns from cache (< 0.1ms) | |
| 5 | Dashboard display | View dashboard with external IPs | Country flags/codes appear | |

---

## 6. Performance Benchmarks

### Baseline Performance (Must Not Regress)

| Metric | Target | How to Test |
|--------|--------|-------------|
| Log ingestion rate | > 100,000 logs/min | `locust` load test against syslog collector |
| Dashboard load time | < 3 seconds | Browser DevTools, `curl -w '%{time_total}'` |
| Log search (simple) | < 2 seconds | API call with timing for 1M row table |
| Log search (complex NQL) | < 5 seconds | API call with aggregation pipeline |
| Alert evaluation cycle | < 5 seconds | Time the evaluation loop with 50 rules |
| IOC matching per log | < 1 ms | Benchmark with 50K IOCs loaded |
| Playbook execution (10 steps) | < 30 seconds | Execute and time from trigger to completion |
| Report generation | < 60 seconds | Generate monthly report with 10M logs |
| API response (simple) | < 200 ms | `ab -n 100 -c 10 http://localhost:8002/api/health` |
| Baseline calculation (4 weeks) | < 5 minutes | Time the calculation job |

### Load Test Scenarios

```python
# locust load test example
from locust import HttpUser, task, between

class ZentrycUser(HttpUser):
    wait_time = between(1, 3)

    @task(10)
    def view_dashboard(self):
        self.client.get("/dashboard/")

    @task(5)
    def search_logs(self):
        self.client.get("/api/logs/search?action=deny&limit=50")

    @task(3)
    def view_alerts(self):
        self.client.get("/api/alerts/")

    @task(1)
    def device_list(self):
        self.client.get("/api/devices/")
```

---

## 7. Security Testing Checklist

| # | Test | Method | Pass Criteria |
|---|------|--------|---------------|
| 1 | SQL Injection | Enter `'; DROP TABLE--` in search fields | No SQL error, input sanitized |
| 2 | XSS (Reflected) | Enter `<script>alert(1)</script>` in search | Script not executed, HTML escaped |
| 3 | XSS (Stored) | Enter script in device hostname | Script not executed on display |
| 4 | CSRF | Submit form without CSRF token | Request rejected |
| 5 | Auth bypass | Access API without session/key | 401 returned |
| 6 | Privilege escalation | VIEWER tries admin endpoints | 403 returned |
| 7 | Session fixation | Set known session ID before login | New session ID issued on login |
| 8 | Password in logs | Check all log files | No plaintext passwords in any log |
| 9 | API key exposure | Check responses and logs | Full API key never in response (only prefix) |
| 10 | Rate limiting | 200 requests in 30 seconds | Rate limit triggered (429) |
| 11 | Directory traversal | `GET /../../etc/passwd` | 404 or 400, not file contents |
| 12 | SSH credential exposure | View device credentials page | Passwords shown as `****`, not plaintext |

---

## 8. Regression Test Checklist

Run these after every phase deployment to ensure existing features still work:

| # | Feature | Test | Status |
|---|---------|------|--------|
| 1 | Dashboard loads | GET `/dashboard/` returns 200 with data | |
| 2 | Log viewer works | GET `/logs/` returns 200 with logs | |
| 3 | Log search works | Search with srcip filter returns results | |
| 4 | Device list loads | GET `/devices/` shows all devices | |
| 5 | Device approve works | Approve a pending device | |
| 6 | EDL list works | GET `/edl/` shows lists | |
| 7 | EDL feed works | GET `/edl/feed/ip/` returns IPs | |
| 8 | Projects load | GET `/projects/` shows projects | |
| 9 | Policy builder works | Generate CLI from communication matrix | |
| 10 | System monitor loads | GET `/system/` shows disk stats | |
| 11 | Syslog collector running | Check port 514 is listening | |
| 12 | ClickHouse responsive | Query syslogs table returns data | |
| 13 | PostgreSQL responsive | Query devices table returns data | |
| 14 | Scheduler running | Check APScheduler jobs are scheduled | |
| 15 | Static files served | CSS/JS files load without 404 | |

---

## 9. Deployment Verification

After each phase deployment, run this checklist:

- [ ] All systemd services start without errors
- [ ] Database migrations applied successfully
- [ ] No errors in `journalctl -u zentryc-web -n 100`
- [ ] No errors in `journalctl -u zentryc-syslog -n 100`
- [ ] Dashboard loads within 3 seconds
- [ ] Syslog collector receiving logs (check log count increasing)
- [ ] Disk usage under 80%
- [ ] All regression tests pass
- [ ] New feature verification tests pass
- [ ] Performance benchmarks within acceptable range
