# Phase 1: Security Foundations & Critical Gaps

**Timeline:** 4-6 weeks
**Priority:** Critical
**Dependencies:** None (this is the foundation)

---

## 1.1 Authentication & User Management

### Description
Implement a complete user authentication system with session management, password hashing, and login/logout flows. This is the most critical missing feature - without it, any user on the network has full admin access.

### Tasks

#### Task 1.1.1: User Database Model
**Description:** Create SQLAlchemy model for users with secure password storage.

**Subtasks:**
- [x] Create `fastapi_app/models/user.py` with User model
- [x] Fields: id, username, email, password_hash, role, is_active, last_login, created_at, updated_at
- [x] Implement password hashing using `bcrypt` via `passlib`
- [x] Add role enum: ADMIN, ANALYST, VIEWER
- [x] Create database migration/table creation in startup
- [x] Create default admin user on first run (admin/changeme)

**Schema:**
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'VIEWER',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Verification:**
- [x] User model creates table on startup without errors
- [x] Password is never stored in plaintext (verify with DB query)
- [x] Default admin user is created only on first run
- [x] All fields have correct types and constraints
- [x] Unique constraints work (duplicate username/email rejected)

---

#### Task 1.1.2: Session-Based Authentication
**Description:** Implement login/logout with server-side sessions.

**Subtasks:**
- [x] Add `python-jose` and `passlib[bcrypt]` to requirements
- [x] Create `fastapi_app/core/auth.py` with authentication utilities
- [x] Implement session token generation (JWT or signed cookies)
- [x] Create login endpoint `POST /auth/login`
- [x] Create logout endpoint `POST /auth/logout`
- [x] Create session validation middleware
- [x] Add `get_current_user` dependency for all routes
- [x] Redirect unauthenticated users to login page
- [x] Handle session expiry (configurable timeout, default 8 hours)
- [x] Account lockout after 5 failed login attempts (15 min lockout)

**Verification:**
- [x] Login with valid credentials returns session token
- [x] Login with invalid credentials returns 401
- [x] Accessing any page without session redirects to `/auth/login`
- [x] Logout invalidates session (cannot reuse token)
- [x] Session expires after configured timeout
- [x] Account locks after 5 failed attempts
- [x] Locked account shows appropriate error message
- [x] Account auto-unlocks after 15 minutes

---

#### Task 1.1.3: Login Page UI
**Description:** Create a professional login page matching the dark theme.

**Subtasks:**
- [x] Create `fastapi_app/templates/auth/login.html`
- [x] Login form with username/password fields
- [x] Error message display (invalid credentials, locked account)
- [x] "Remember me" checkbox (extends session to 30 days)
- [x] Redirect to originally requested page after login
- [x] Consistent styling with existing dark theme

**Verification:**
- [x] Login page renders correctly
- [x] Form submits and authenticates
- [x] Error messages display for wrong credentials
- [x] "Remember me" extends session duration
- [x] Post-login redirect works correctly
- [x] Page is responsive on mobile

---

#### Task 1.1.4: User Management UI (Admin Only)
**Description:** Admin page to manage users.

**Subtasks:**
- [x] Create `fastapi_app/templates/auth/user_management.html`
- [x] User list with role, status, last login
- [x] Create new user form
- [x] Edit user (change role, reset password, activate/deactivate)
- [x] Delete user (with confirmation)
- [x] Add "Users" link to nav bar (visible only to ADMIN)

**API Endpoints:**
- `GET /api/users/` - List all users (Admin only)
- `POST /api/users/` - Create user (Admin only)
- `PUT /api/users/{id}` - Update user (Admin only)
- `DELETE /api/users/{id}` - Delete user (Admin only)
- `POST /api/users/{id}/reset-password` - Reset password (Admin only)
- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me/password` - Change own password

**Verification:**
- [x] Admin can create, edit, delete users
- [x] Non-admin users cannot access user management
- [x] Password reset works correctly
- [x] User can change their own password
- [x] Deleting own account is prevented
- [x] Last admin cannot be deleted or demoted

---

### 1.2 Role-Based Access Control (RBAC)

#### Task 1.2.1: Permission System
**Description:** Implement role-based permissions that restrict access to features.

**Permission Matrix:**

| Feature | ADMIN | ANALYST | VIEWER |
|---------|-------|---------|--------|
| Dashboard | Full | Full | Full |
| Log Viewer | Full | Full | Read-only |
| Log Search | Full | Full | Full |
| Policy Builder | Full | Full | Read-only |
| Device Management | Full | View + Approve | View only |
| Device SSH/Credentials | Full | No | No |
| EDL Management | Full | Full | View + Feed URLs |
| Projects | Full | Full | View only |
| System Monitor | Full | View only | No |
| Storage Settings | Full | No | No |
| User Management | Full | No | No |
| Alert Rules | Full | Full | View only |
| Incidents | Full | Full | View only |
| API Keys | Full | Own keys only | No |

**Subtasks:**
- [x] Create `fastapi_app/core/permissions.py` with permission decorator
- [x] Implement `require_role(min_role)` dependency
- [x] Add permission checks to all existing routes
- [x] Hide unauthorized nav items in templates
- [x] Return 403 Forbidden for unauthorized API access
- [x] Add role info to template context for conditional rendering

**Verification:**
- [x] ADMIN can access all features
- [x] ANALYST cannot access System settings or User management
- [x] VIEWER can only view dashboards, logs, and search
- [x] API returns 403 for unauthorized endpoints
- [x] Nav bar only shows accessible items per role
- [x] Unauthorized direct URL access is blocked (not just hidden)

---

## 1.3 Real-Time Alerting Engine

### Description
Build a rule-based alerting engine that monitors incoming logs and triggers notifications when conditions are met. This transforms Zentryc from a passive log viewer into an active threat detection platform.

### Tasks

#### Task 1.3.1: Alert Rule Database Model
**Description:** Create models for alert rules, triggered alerts, and notification channels.

**Subtasks:**
- [x] Create `fastapi_app/models/alert.py` with models:
  - `AlertRule`: Rule definition with conditions and actions
  - `Alert`: Triggered alert instance
  - `NotificationChannel`: Email, Telegram, Webhook configs
  - `AlertRuleNotification`: Many-to-many rule-to-channel mapping
- [x] Create database tables on startup

**Schema:**
```sql
-- Alert Rules
CREATE TABLE alert_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,  -- critical, high, medium, low, info
    category VARCHAR(50),            -- brute_force, port_scan, anomaly, threshold, absence
    is_enabled BOOLEAN DEFAULT TRUE,

    -- Conditions (JSON)
    condition_type VARCHAR(30) NOT NULL,  -- threshold, pattern, anomaly, absence
    condition_config JSONB NOT NULL,
    /*
    Examples:
    Threshold: {"field": "action", "value": "deny", "operator": "count", "threshold": 100, "window_minutes": 5, "group_by": "srcip"}
    Pattern:   {"rules": [{"field": "action", "value": "deny"}, {"field": "dstport", "value": "22"}], "threshold": 10, "window_minutes": 5}
    Absence:   {"device_ip": "192.168.100.102", "timeout_minutes": 10}
    */

    -- Cooldown
    cooldown_minutes INTEGER DEFAULT 15,
    last_triggered_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    mitre_tactic VARCHAR(100),
    mitre_technique VARCHAR(100),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Triggered Alerts
CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES alert_rules(id),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB,              -- Matching log data, counts, etc.
    status VARCHAR(20) DEFAULT 'new',  -- new, acknowledged, investigating, resolved, false_positive
    assigned_to INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by INTEGER REFERENCES users(id),
    resolution_notes TEXT,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Notification Channels
CREATE TABLE notification_channels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    channel_type VARCHAR(30) NOT NULL,  -- email, telegram, webhook, sms
    config JSONB NOT NULL,
    /*
    Email:    {"smtp_host": "", "smtp_port": 587, "username": "", "password": "", "from_addr": "", "to_addrs": []}
    Telegram: {"bot_token": "", "chat_id": ""}
    Webhook:  {"url": "", "method": "POST", "headers": {}}
    */
    is_enabled BOOLEAN DEFAULT TRUE,
    last_sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rule-to-Channel mapping
CREATE TABLE alert_rule_notifications (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id INTEGER REFERENCES notification_channels(id) ON DELETE CASCADE,
    UNIQUE(rule_id, channel_id)
);
```

**Verification:**
- [x] All tables created successfully on startup
- [x] JSON fields accept valid configuration
- [x] Foreign key constraints work correctly
- [x] Cascade delete removes rule-channel mappings when rule is deleted
- [x] Enum values are enforced

---

#### Task 1.3.2: Alert Evaluation Engine
**Description:** Background service that evaluates alert rules against incoming log data.

**Subtasks:**
- [x] Create `fastapi_app/services/alert_engine.py`
- [x] Implement rule evaluation loop (runs every 30 seconds)
- [x] **Threshold evaluation**: Query ClickHouse for count-based conditions
  - Example: COUNT(*) WHERE action='deny' GROUP BY srcip HAVING count > threshold
- [x] **Pattern evaluation**: Multi-condition matching
  - Example: action=deny AND dstport=22 AND count > 10 in 5 minutes
- [x] **Absence evaluation**: Check device last-log timestamp
  - Example: No logs from device X for > 10 minutes
- [x] **Anomaly evaluation**: Compare current metrics against baseline
  - Example: Current EPS > 3x average EPS for this hour
- [x] Cooldown enforcement (don't re-trigger within cooldown period)
- [x] Create Alert record when rule triggers
- [x] Dispatch notifications to configured channels
- [x] Integrate with scheduler to run on startup
- [x] Handle errors gracefully (don't crash on single rule failure)

**Verification:**
- [x] Threshold rule triggers when count exceeds threshold
- [x] Threshold rule does NOT trigger when count is below threshold
- [x] Pattern rule triggers only when ALL conditions match
- [x] Absence rule triggers when device stops sending logs
- [x] Cooldown prevents duplicate alerts within cooldown period
- [x] Engine continues running when a single rule evaluation fails
- [x] Alerts are created with correct severity and details
- [x] Performance: Evaluation cycle completes in < 5 seconds with 50 rules

---

#### Task 1.3.3: Notification Service
**Description:** Send alert notifications via multiple channels.

**Subtasks:**
- [x] Create `fastapi_app/services/notification_service.py`
- [x] **Email notifications** (SMTP):
  - HTML-formatted alert emails
  - Alert severity in subject line
  - Link to alert detail page
  - Configurable SMTP settings
- [x] **Telegram notifications**:
  - Bot token + chat ID configuration
  - Formatted message with alert details
  - Severity emoji indicators
- [x] **Webhook notifications**:
  - POST JSON payload to configured URL
  - Custom headers support
  - Retry on failure (3 attempts)
- [x] Notification rate limiting (max 10/minute per channel)
- [x] Notification failure logging
- [x] Test notification endpoint

**Verification:**
- [x] Email sends successfully with correct formatting
- [x] Telegram message arrives with proper formatting
- [x] Webhook POST reaches target URL with correct payload
- [x] Rate limiting prevents notification flood
- [x] Failed notifications are logged (not silently dropped)
- [x] Test notification button works for each channel type
- [x] Notification includes link back to alert in Zentryc

---

#### Task 1.3.4: Alert Dashboard UI
**Description:** UI for viewing, managing, and responding to alerts.

**Subtasks:**
- [x] Create `fastapi_app/templates/alerts/alert_dashboard.html`
  - Alert summary cards (Critical: X, High: X, Medium: X, New: X)
  - Alert list with filters (severity, status, time range, rule)
  - Severity-colored indicators
  - Quick actions: Acknowledge, Assign, Resolve
  - Alert detail modal with full log data
  - Resolution notes input
  - Auto-refresh every 30 seconds
- [x] Create `fastapi_app/templates/alerts/alert_rules.html`
  - List all alert rules with enable/disable toggle
  - Create/edit rule form
  - Rule test button (dry run against last 1 hour of data)
  - Last triggered timestamp
  - Trigger count
- [x] Create `fastapi_app/templates/alerts/notification_channels.html`
  - List notification channels
  - Add/edit channel forms (email, telegram, webhook)
  - Test channel button
  - Last sent timestamp
- [x] Add "Alerts" to main navigation with unread badge counter
- [x] Add alert count badge showing unresolved critical/high alerts

**API Endpoints:**
- `GET /api/alerts/` - List alerts with filters
- `GET /api/alerts/{id}` - Alert detail
- `POST /api/alerts/{id}/acknowledge` - Acknowledge alert
- `POST /api/alerts/{id}/assign` - Assign to user
- `POST /api/alerts/{id}/resolve` - Resolve with notes
- `POST /api/alerts/{id}/false-positive` - Mark as false positive
- `GET /api/alert-rules/` - List rules
- `POST /api/alert-rules/` - Create rule
- `PUT /api/alert-rules/{id}` - Update rule
- `DELETE /api/alert-rules/{id}` - Delete rule
- `POST /api/alert-rules/{id}/toggle` - Enable/disable
- `POST /api/alert-rules/{id}/test` - Dry run test
- `GET /api/notification-channels/` - List channels
- `POST /api/notification-channels/` - Create channel
- `PUT /api/notification-channels/{id}` - Update channel
- `DELETE /api/notification-channels/{id}` - Delete channel
- `POST /api/notification-channels/{id}/test` - Send test notification

**Verification:**
- [x] Alert dashboard shows all alerts with correct severity colors
- [x] Filters work correctly (severity, status, time range)
- [x] Acknowledge updates status and records timestamp
- [x] Resolve requires notes input
- [x] Alert rules can be created, edited, deleted
- [x] Rule enable/disable toggle works without page reload
- [x] Rule test shows what would match without creating real alerts
- [x] Notification channels can be tested
- [x] Nav badge shows correct count of unresolved critical/high alerts
- [x] Auto-refresh updates alert list

---

#### Task 1.3.5: Pre-built Alert Rules
**Description:** Ship default alert rules for common firewall scenarios.

**Pre-built Rules:**
- [x] **Brute Force Detection**: >20 denied connections from same source IP to same destination port within 5 minutes (High severity)
- [x] **Port Scan Detection**: >10 different destination ports from same source IP within 2 minutes (High severity)
- [x] **DDoS Indicator**: >1000 connections from same source IP within 1 minute (Critical severity)
- [x] **Device Offline**: No logs from approved device for 10 minutes (Medium severity)
- [x] **High Deny Rate**: >50% of traffic from a device is denied within 15 minutes (Medium severity)
- [x] **Critical Severity Spike**: >10 critical severity logs within 5 minutes (High severity)
- [ ] **New Source Country**: Traffic from country not seen in last 30 days (Low severity) *(replaced with Anomalous Traffic Spike)*
- [x] **Admin Port Access**: Denied traffic to ports 22, 3389, 8443 from external IPs (Medium severity)
- [x] **DNS Tunneling Suspect**: >100 DNS queries from single IP within 5 minutes (Medium severity)
- [x] **Data Exfiltration Suspect**: >5000 outbound events from single IP within 1 hour (High severity)

**Verification:**
- [x] All pre-built rules load on fresh install
- [x] Each rule triggers correctly when conditions are simulated
- [x] Rules can be modified/disabled by admin
- [x] Rules have appropriate severity levels
- [x] Each rule has clear name and description

---

## 1.4 Audit Logging

### Description
Track all administrative actions for compliance and security forensics.

### Tasks

#### Task 1.4.1: Audit Log Implementation
**Description:** Log all user actions to an immutable audit trail.

**Subtasks:**
- [x] Create ClickHouse table for audit logs:
  ```sql
  CREATE TABLE audit_logs (
      timestamp DateTime64(3),
      user_id UInt32,
      username String,
      action String,              -- login, logout, create, update, delete, approve, reject, etc.
      resource_type String,       -- user, device, alert_rule, edl, project, setting, etc.
      resource_id String,
      resource_name String,
      details String,             -- JSON with before/after values
      ip_address String,
      user_agent String
  ) ENGINE = MergeTree()
  PARTITION BY toYYYYMM(timestamp)
  ORDER BY (timestamp, user_id)
  TTL timestamp + INTERVAL 1 YEAR DELETE
  ```
- [x] Create `fastapi_app/services/audit_service.py`
- [x] Create audit logging middleware for automatic capture
- [x] Log these actions:
  - User login/logout (success and failure)
  - User create/update/delete
  - Device approve/reject/update/delete
  - Alert rule create/update/delete/toggle
  - EDL list/entry create/update/delete
  - Project create/update/delete
  - System settings changes
  - Storage cleanup triggers
  - SSH credential changes
  - Password changes/resets

**Verification:**
- [x] Every admin action creates an audit log entry
- [x] Audit logs include user, action, resource, timestamp, IP
- [x] Audit logs cannot be modified or deleted by users
- [x] Failed login attempts are logged
- [x] Audit log viewer shows entries with correct formatting
- [x] Filtering by user, action, resource type, date range works
- [x] TTL automatically removes logs older than 1 year

---

#### Task 1.4.2: Audit Log Viewer UI
**Description:** Admin page to view audit trail.

**Subtasks:**
- [x] Create `fastapi_app/templates/system/audit_log.html`
- [x] Filterable table with: timestamp, user, action, resource, details
- [x] Filter by: user, action type, resource type, date range
- [x] Export to CSV
- [x] Link from System Monitor page
- [x] Admin-only access

**Verification:**
- [x] Audit log page loads with recent entries
- [x] All filters work correctly
- [x] CSV export includes all filtered data
- [x] Non-admin users cannot access audit logs
- [x] Large datasets paginate correctly

---

## 1.5 API Security

### Tasks

#### Task 1.5.1: API Key Management
**Description:** Allow programmatic API access via API keys.

**Subtasks:**
- [x] Create `api_keys` table in PostgreSQL:
  ```sql
  CREATE TABLE api_keys (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      name VARCHAR(100) NOT NULL,
      key_hash VARCHAR(255) NOT NULL,
      key_prefix VARCHAR(8) NOT NULL,  -- First 8 chars for identification
      permissions JSONB DEFAULT '["read"]',
      is_active BOOLEAN DEFAULT TRUE,
      last_used_at TIMESTAMP WITH TIME ZONE,
      expires_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
  );
  ```
- [x] Generate secure API keys (32-byte random, shown once)
- [x] API key authentication middleware (`X-API-Key` header or `?api_key=` param)
- [x] Key permissions: read, write, admin
- [x] Key expiration support
- [x] Last-used tracking
- [x] Rate limiting: 100 requests/minute per key (configurable)

**API Endpoints:**
- `GET /api/keys/` - List user's API keys (prefix only, never full key)
- `POST /api/keys/` - Create new key (returns full key once)
- `DELETE /api/keys/{id}` - Revoke key
- `PUT /api/keys/{id}` - Update key name/permissions

**Verification:**
- [x] API key grants access to endpoints based on permissions
- [x] Invalid/expired/revoked keys return 401
- [x] Full key is shown only at creation time
- [x] Rate limiting blocks excessive requests (returns 429)
- [x] Last-used timestamp updates on each API call
- [x] Users can only manage their own keys (except admin)
- [x] API key works with all existing API endpoints

---

## Phase 1 Completion Criteria

- [x] Users must log in to access any page
- [x] Three roles (Admin, Analyst, Viewer) with enforced permissions
- [x] At least 10 pre-built alert rules are active
- [x] Email notifications are functional
- [x] At least one additional notification channel works (Telegram or Webhook)
- [x] All admin actions are logged in audit trail
- [x] API keys can be created and used for programmatic access
- [x] No existing functionality is broken
- [x] All verification tests pass
