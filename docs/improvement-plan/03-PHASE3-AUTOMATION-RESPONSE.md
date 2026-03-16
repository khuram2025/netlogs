# Phase 3: Automation & Response (SOAR)

**Timeline:** 6-8 weeks
**Priority:** High
**Dependencies:** Phase 1 (Alerting), Phase 2 (Threat Intel, Correlation)

---

## 3.1 Playbook Engine

### Description
Build a visual playbook engine that automates incident response workflows. Playbooks define a sequence of actions (notifications, enrichment, blocking, ticketing) triggered by alerts or manual invocation. This is the core SOAR capability that transforms Zentryc from detection-only to detection-and-response.

### Tasks

#### Task 3.1.1: Playbook Database Model
**Description:** Create models for playbooks, steps, and execution history.

**Subtasks:**
- [ ] Create `fastapi_app/models/playbook.py`

**Schema:**
```sql
-- Playbook Definitions
CREATE TABLE playbooks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    category VARCHAR(50),           -- incident_response, threat_mitigation, enrichment, notification
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Trigger configuration
    trigger_type VARCHAR(30) NOT NULL,  -- alert, manual, scheduled, webhook
    trigger_config JSONB,
    /*
    Alert trigger:     {"alert_rule_ids": [1, 2], "min_severity": "high"}
    Scheduled trigger: {"cron": "0 */6 * * *"}
    Webhook trigger:   {"path": "/playbooks/webhook/abc123"}
    Manual trigger:    {}
    */

    -- Steps (ordered list)
    steps JSONB NOT NULL,
    /*
    [
      {
        "id": "step1",
        "name": "Enrich Source IP",
        "type": "enrichment",
        "action": "geoip_lookup",
        "params": {"ip_field": "srcip"},
        "on_success": "step2",
        "on_failure": "step_notify_error"
      },
      {
        "id": "step2",
        "name": "Check Threat Intel",
        "type": "enrichment",
        "action": "ioc_lookup",
        "params": {"value_field": "srcip"},
        "on_success": "step3_condition",
        "on_failure": "step_notify_error"
      },
      {
        "id": "step3_condition",
        "name": "Is Known Threat?",
        "type": "condition",
        "condition": {"field": "step2.ioc_match", "operator": "==", "value": true},
        "on_true": "step4_block",
        "on_false": "step5_alert_only"
      },
      {
        "id": "step4_block",
        "name": "Block on Firewall",
        "type": "action",
        "action": "add_to_edl",
        "params": {"edl_name": "auto-block", "value_field": "srcip", "expiry_hours": 24},
        "on_success": "step6_notify",
        "on_failure": "step_notify_error",
        "requires_approval": false
      },
      {
        "id": "step5_alert_only",
        "name": "Create Low Priority Alert",
        "type": "action",
        "action": "create_alert",
        "params": {"severity": "medium", "title": "Suspicious IP - Not in Threat DB"},
        "on_success": "step6_notify"
      },
      {
        "id": "step6_notify",
        "name": "Notify Team",
        "type": "notification",
        "action": "send_notification",
        "params": {"channel_ids": [1, 2], "template": "threat_blocked"},
        "on_success": "end"
      },
      {
        "id": "step_notify_error",
        "name": "Notify Error",
        "type": "notification",
        "action": "send_notification",
        "params": {"channel_ids": [1], "template": "playbook_error"},
        "on_success": "end"
      }
    ]
    */

    -- Statistics
    run_count INTEGER DEFAULT 0,
    last_run_at TIMESTAMP WITH TIME ZONE,
    avg_duration_seconds FLOAT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,

    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Playbook Execution History
CREATE TABLE playbook_executions (
    id SERIAL PRIMARY KEY,
    playbook_id INTEGER REFERENCES playbooks(id),
    trigger_source VARCHAR(100),     -- alert:123, manual:user_1, schedule, webhook
    status VARCHAR(20) NOT NULL,     -- running, completed, failed, cancelled, awaiting_approval

    -- Input context (alert data, webhook payload, etc.)
    input_data JSONB,

    -- Step execution log
    step_results JSONB DEFAULT '[]',
    /*
    [
      {"step_id": "step1", "status": "completed", "started_at": "...", "completed_at": "...", "output": {...}},
      {"step_id": "step2", "status": "completed", "started_at": "...", "completed_at": "...", "output": {...}},
      {"step_id": "step4_block", "status": "failed", "started_at": "...", "completed_at": "...", "error": "SSH timeout"}
    ]
    */

    -- Approval tracking
    pending_approval_step VARCHAR(100),
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP WITH TIME ZONE,

    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds FLOAT,
    error_message TEXT,

    executed_by INTEGER REFERENCES users(id)
);
```

**Verification:**
- [ ] Playbook model saves with valid JSON steps
- [ ] Execution history records all step results
- [ ] Step navigation (on_success, on_failure, on_true, on_false) is valid
- [ ] Trigger configuration validates correctly per trigger type
- [ ] Statistics fields update on each execution

---

#### Task 3.1.2: Playbook Execution Engine
**Description:** Execute playbook steps sequentially with condition evaluation and error handling.

**Subtasks:**
- [ ] Create `fastapi_app/services/playbook_engine.py`
- [ ] **Step types and actions:**

  **Enrichment Steps:**
  - `geoip_lookup`: Look up IP geolocation (using GeoIP database)
  - `ioc_lookup`: Check IP/domain against IOC database
  - `device_lookup`: Get device info from PostgreSQL
  - `whois_lookup`: WHOIS query for IP/domain
  - `dns_lookup`: Reverse DNS resolution
  - `log_context`: Fetch related logs from ClickHouse (same srcip, last 1h)

  **Action Steps:**
  - `add_to_edl`: Add IP/domain to specified EDL list
  - `remove_from_edl`: Remove from EDL list
  - `create_alert`: Create alert with specified severity
  - `create_incident`: Create incident ticket
  - `update_incident`: Update incident status/notes
  - `ssh_command`: Execute command on firewall via SSH (requires approval)
  - `block_ip_firewall`: SSH to firewall and add block rule (requires approval)

  **Notification Steps:**
  - `send_notification`: Send via configured notification channel
  - `send_email`: Send email with template
  - `send_webhook`: POST to webhook URL

  **Condition Steps:**
  - `condition`: Evaluate field comparison (==, !=, >, <, in, not_in, contains)
  - `time_condition`: Check time of day, day of week
  - `threshold_condition`: Check if metric exceeds threshold

  **Control Steps:**
  - `wait`: Wait for specified duration
  - `require_approval`: Pause until human approves
  - `end`: End playbook execution

- [ ] Step execution with timeout (default 30s per step)
- [ ] Variable substitution: `$alert.srcip`, `$step1.output.country`
- [ ] Error handling: Continue on failure vs. abort
- [ ] Approval gate: Pause execution, notify approver, resume on approval
- [ ] Concurrent step execution (parallel branches)
- [ ] Execution logging for every step

**Verification:**
- [ ] All enrichment steps return data correctly
- [ ] Action steps modify data (EDL, alerts, incidents) correctly
- [ ] Condition steps branch correctly based on data
- [ ] Variable substitution works between steps
- [ ] Timeout prevents stuck steps
- [ ] Approval gate pauses execution and resumes on approval
- [ ] Failed steps trigger on_failure path
- [ ] Complete execution recorded in history
- [ ] SSH command step requires approval flag
- [ ] Performance: 10-step playbook completes in < 30 seconds

---

#### Task 3.1.3: Pre-built Playbooks
**Description:** Ship ready-to-use playbooks for common firewall security scenarios.

**Playbooks to Create:**

- [ ] **Brute Force Response**
  ```
  Trigger: Alert rule "Brute Force Detection"
  1. Enrich source IP (GeoIP + IOC lookup)
  2. Check if IP is in IOC database
  3. If known threat: Auto-block on EDL (24h expiry)
  4. If unknown: Create medium alert for analyst review
  5. Fetch last 1 hour of logs from this IP
  6. Notify team via email + Telegram
  ```

- [ ] **Port Scan Response**
  ```
  Trigger: Alert rule "Port Scan Detection"
  1. Enrich source IP (GeoIP + WHOIS)
  2. Count unique ports targeted
  3. If > 50 ports: Block on EDL (48h expiry)
  4. If 10-50 ports: Create alert for review
  5. Notify team
  ```

- [ ] **Device Offline Response**
  ```
  Trigger: Alert rule "Device Offline"
  1. Attempt SSH health check to device
  2. If SSH fails: Create critical alert
  3. If SSH succeeds but no logs: Create medium alert
  4. Notify network operations team
  ```

- [ ] **Threat Intel Match Response**
  ```
  Trigger: IOC match with confidence > 70
  1. Get full IOC details
  2. Fetch all recent logs involving matched IP
  3. If outbound traffic: Create critical incident
  4. If inbound denied: Create low alert
  5. Add to auto-block EDL
  6. Notify SOC team
  ```

- [ ] **Communication Matrix Violation**
  ```
  Trigger: Manual or scheduled (hourly)
  1. Query allowed traffic not in communication matrix
  2. For each violation: Create low alert
  3. Generate summary report
  4. Notify project owner
  ```

**Verification:**
- [ ] Each playbook executes end-to-end without errors
- [ ] Playbooks trigger from their associated alert rules
- [ ] Block actions add correct entries to EDL
- [ ] Notifications send with correct content
- [ ] Playbooks can be cloned and customized
- [ ] Execution history shows all steps with timing

---

#### Task 3.1.4: Playbook UI
**Description:** UI for creating, editing, monitoring, and executing playbooks.

**Subtasks:**
- [ ] Create `fastapi_app/templates/playbooks/playbook_list.html`
  - List all playbooks with status, trigger type, run count
  - Enable/disable toggle
  - Quick stats: last run, success rate
  - Filter by category, trigger type
- [ ] Create `fastapi_app/templates/playbooks/playbook_editor.html`
  - Visual step editor (form-based, step cards)
  - Step type selector
  - Step configuration form per type
  - Connection lines between steps (on_success, on_failure)
  - Condition branching visualization
  - Test/dry-run button
  - Save and enable
- [ ] Create `fastapi_app/templates/playbooks/playbook_detail.html`
  - Playbook overview with statistics
  - Step flow diagram
  - Execution history table
  - Execution detail: step-by-step results with timing
  - Manual trigger button
- [ ] Create `fastapi_app/templates/playbooks/pending_approvals.html`
  - List playbook executions awaiting approval
  - Context display (what triggered, what will happen)
  - Approve/Deny buttons
  - Approval notifications
- [ ] Add "Playbooks" to navigation menu
- [ ] Add approval badge to nav (count of pending approvals)

**API Endpoints:**
- `GET /api/playbooks/` - List playbooks
- `POST /api/playbooks/` - Create playbook
- `PUT /api/playbooks/{id}` - Update playbook
- `DELETE /api/playbooks/{id}` - Delete playbook
- `POST /api/playbooks/{id}/toggle` - Enable/disable
- `POST /api/playbooks/{id}/execute` - Manual trigger
- `POST /api/playbooks/{id}/test` - Dry run
- `GET /api/playbooks/{id}/executions` - Execution history
- `GET /api/playbook-executions/{id}` - Execution detail
- `POST /api/playbook-executions/{id}/approve` - Approve step
- `POST /api/playbook-executions/{id}/deny` - Deny step

**Verification:**
- [ ] Playbook list shows all playbooks with correct status
- [ ] Step editor allows adding/removing/reordering steps
- [ ] Each step type has appropriate configuration form
- [ ] Test/dry-run simulates without executing actions
- [ ] Manual trigger executes playbook with results
- [ ] Execution history shows all past runs
- [ ] Pending approvals page shows waiting executions
- [ ] Approve/deny works and continues/cancels execution

---

## 3.2 Incident/Case Management

### Description
Full incident lifecycle management from detection through investigation to resolution.

### Tasks

#### Task 3.2.1: Incident Database Model
**Description:** Create models for incidents with full lifecycle tracking.

**Schema:**
```sql
CREATE TABLE incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,       -- critical, high, medium, low
    status VARCHAR(30) NOT NULL DEFAULT 'new',
    -- Status flow: new -> investigating -> containment -> eradication -> recovery -> closed
    -- Also: false_positive
    category VARCHAR(50),                 -- brute_force, malware, data_breach, unauthorized_access, policy_violation, other

    -- Assignment
    assigned_to INTEGER REFERENCES users(id),
    escalated_to INTEGER REFERENCES users(id),

    -- Related data
    related_alert_ids INTEGER[],
    related_device_ips VARCHAR(50)[],
    affected_ips VARCHAR(50)[],

    -- SLA tracking
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    containment_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,

    -- Time metrics (seconds)
    time_to_detect INTEGER,
    time_to_acknowledge INTEGER,
    time_to_contain INTEGER,
    time_to_resolve INTEGER,

    -- Resolution
    resolution_type VARCHAR(50),          -- blocked, patched, false_positive, accepted_risk, escalated
    resolution_notes TEXT,
    lessons_learned TEXT,

    -- Metadata
    tags VARCHAR(50)[],
    mitre_tactics VARCHAR(100)[],
    mitre_techniques VARCHAR(100)[],

    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Incident comments/timeline
CREATE TABLE incident_comments (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    comment_type VARCHAR(30) DEFAULT 'comment',  -- comment, status_change, assignment, action, evidence
    content TEXT NOT NULL,
    attachments JSONB,            -- File names, evidence references
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Incident evidence (log snapshots, screenshots)
CREATE TABLE incident_evidence (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    evidence_type VARCHAR(30),    -- log_snapshot, screenshot, config, packet_capture
    title VARCHAR(200),
    description TEXT,
    data JSONB,                   -- Log data, configuration snapshots
    file_path VARCHAR(500),       -- For uploaded files
    added_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Verification:**
- [ ] Incident creates with all required fields
- [ ] Status transitions follow correct flow
- [ ] SLA timestamps auto-calculate on status change
- [ ] Comments cascade delete with incident
- [ ] Evidence can be attached and retrieved
- [ ] Time metrics calculate correctly

---

#### Task 3.2.2: Incident Management UI
**Description:** Full incident management interface.

**Subtasks:**
- [ ] Create `fastapi_app/templates/incidents/incident_list.html`
  - Incident list with filters: severity, status, assignee, date range
  - Summary cards: Open, Investigating, Containment, Resolved
  - SLA indicators (red/yellow/green based on response time)
  - Quick assign/escalate actions
  - Create incident button
- [ ] Create `fastapi_app/templates/incidents/incident_detail.html`
  - Incident header: title, severity badge, status badge, assignment
  - Status change buttons (flow-based)
  - Timeline view: chronological comments, status changes, actions
  - Related alerts section (linked alerts with details)
  - Related logs section (matching log data from ClickHouse)
  - Evidence section (attached files, log snapshots)
  - Add comment form
  - Add evidence form
  - Resolution form (type, notes, lessons learned)
  - Actions: Assign, Escalate, Add to EDL, Run Playbook
- [ ] Create `fastapi_app/templates/incidents/incident_form.html`
  - Create/edit incident form
  - Title, description, severity, category
  - Related alert IDs
  - Affected IPs
  - MITRE mapping
  - Tags
- [ ] Add "Incidents" to navigation menu with count badge

**API Endpoints:**
- `GET /api/incidents/` - List with filters
- `POST /api/incidents/` - Create incident
- `GET /api/incidents/{id}` - Detail
- `PUT /api/incidents/{id}` - Update
- `POST /api/incidents/{id}/status` - Change status
- `POST /api/incidents/{id}/assign` - Assign to user
- `POST /api/incidents/{id}/escalate` - Escalate
- `POST /api/incidents/{id}/comments` - Add comment
- `POST /api/incidents/{id}/evidence` - Add evidence
- `POST /api/incidents/{id}/resolve` - Resolve with notes
- `GET /api/incidents/stats` - Incident statistics (MTTR, MTTA, etc.)

**Verification:**
- [ ] Create incident with all fields
- [ ] Status transitions work correctly
- [ ] Timeline shows all activities chronologically
- [ ] Comments display with user and timestamp
- [ ] Related alerts link correctly
- [ ] Evidence upload and display works
- [ ] Resolution form captures notes and lessons
- [ ] SLA indicators show correct colors
- [ ] Statistics calculate MTTR, MTTA correctly
- [ ] Incident can be created from alert (pre-populated)

---

## 3.3 Automated Reporting

### Description
Generate and distribute scheduled reports for operations, management, and compliance.

### Tasks

#### Task 3.3.1: Report Templates
**Description:** Create report templates with configurable content.

**Subtasks:**
- [ ] Create `fastapi_app/models/report.py`:
  ```sql
  CREATE TABLE report_templates (
      id SERIAL PRIMARY KEY,
      name VARCHAR(200) NOT NULL,
      description TEXT,
      report_type VARCHAR(50) NOT NULL,    -- executive, operational, compliance, device, custom
      template_config JSONB NOT NULL,
      /*
      {
        "sections": [
          {"type": "summary", "title": "Executive Summary", "metrics": ["total_events", "critical_alerts", "incidents"]},
          {"type": "chart", "title": "Traffic Trend", "chart_type": "line", "data_source": "traffic_timeline", "time_range": "7d"},
          {"type": "table", "title": "Top Threats", "data_source": "top_denied_ips", "limit": 10},
          {"type": "compliance", "title": "PCI DSS Status", "framework": "pci_dss"}
        ],
        "time_range": "7d",
        "devices": ["all"]
      }
      */
      is_scheduled BOOLEAN DEFAULT FALSE,
      schedule_cron VARCHAR(50),
      schedule_format VARCHAR(10) DEFAULT 'pdf',  -- pdf, html, csv
      email_recipients TEXT[],
      last_generated_at TIMESTAMP WITH TIME ZONE,
      created_by INTEGER REFERENCES users(id),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );
  ```

**Pre-built Templates:**
- [ ] **Daily Executive Summary**
  - Total events, alerts, incidents in last 24h
  - Top 5 threats (denied sources)
  - Device health summary
  - Trend comparison vs. previous day
- [ ] **Weekly Operations Report**
  - Event volume trend (7 days)
  - Alert breakdown by severity and category
  - Incident metrics (opened, closed, MTTR)
  - Top source/destination IPs
  - Policy builder usage
  - Storage utilization
- [ ] **Monthly Compliance Report**
  - Log retention compliance
  - Alert rule coverage
  - Incident response times vs. SLA
  - Device availability
  - Configuration changes audit
- [ ] **Device Health Report**
  - Per-device: log volume, last seen, storage used
  - Stale device warnings
  - Routing table changes
  - Zone configuration changes

**Verification:**
- [ ] All pre-built templates generate correct content
- [ ] Custom template saves and generates correctly
- [ ] Time range filtering works
- [ ] Device filtering works
- [ ] Charts render correctly in reports

---

#### Task 3.3.2: Report Generation Service
**Description:** Generate reports in PDF and HTML formats.

**Subtasks:**
- [ ] Create `fastapi_app/services/report_service.py`
- [ ] Add `weasyprint` (PDF) or `reportlab` to requirements
- [ ] HTML report generation with inline CSS (email-friendly)
- [ ] PDF report generation with charts and tables
- [ ] CSV export for data tables
- [ ] Section renderers:
  - Summary metrics with trend arrows
  - Chart rendering (save Chart.js output as image)
  - Data tables with formatting
  - Compliance checklists
- [ ] Scheduled generation via APScheduler
- [ ] Email distribution of generated reports
- [ ] Report archive (keep last 90 days)

**Verification:**
- [ ] HTML report generates with correct data and formatting
- [ ] PDF report generates without errors
- [ ] Charts render correctly in PDF
- [ ] CSV export contains all data
- [ ] Scheduled reports generate and send on time
- [ ] Email delivery works with attachments
- [ ] Report archive stores and retrieves past reports
- [ ] Large reports (30 days of data) generate within 60 seconds

---

#### Task 3.3.3: Report UI
**Description:** UI for managing and viewing reports.

**Subtasks:**
- [ ] Create `fastapi_app/templates/reports/report_list.html`
  - List report templates
  - Schedule configuration
  - Generate on demand button
  - Download past reports
- [ ] Create `fastapi_app/templates/reports/report_viewer.html`
  - Render HTML report in browser
  - Download as PDF button
  - Print button
  - Share link
- [ ] Create `fastapi_app/templates/reports/report_editor.html`
  - Create/edit report template
  - Section builder (add/remove/reorder sections)
  - Preview button
  - Schedule configuration (cron, recipients)
- [ ] Add "Reports" to navigation menu

**Verification:**
- [ ] Report list shows all templates with schedule status
- [ ] Generate button creates report and shows in viewer
- [ ] PDF download works
- [ ] Report editor allows section customization
- [ ] Schedule saves and executes correctly
- [ ] Past reports are accessible for download

---

## Phase 3 Completion Criteria

- [ ] At least 5 pre-built playbooks are functional
- [ ] Playbook editor allows creating custom playbooks
- [ ] Playbooks trigger automatically from alerts
- [ ] Approval gates pause execution correctly
- [ ] Auto-block via EDL works from playbook actions
- [ ] Incidents can be created, investigated, and resolved
- [ ] Incident timeline shows full activity history
- [ ] SLA metrics calculate correctly (MTTR, MTTA)
- [ ] At least 4 report templates generate correctly
- [ ] Scheduled reports send via email
- [ ] All verification tests pass
