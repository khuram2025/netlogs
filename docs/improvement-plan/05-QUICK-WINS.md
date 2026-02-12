# Quick Wins - High Impact, Low Effort

**Timeline:** 1-2 weeks each (independent of phases)
**Priority:** Ongoing - implement between major phases

These items are self-contained improvements that deliver visible value quickly without requiring the architectural work of the main phases.

---

## QW-01: Favicon Fix

### Description
Fix the 404 error on `/favicon.ico` that appears in browser console on every page load.

### Tasks
- [ ] Create or obtain a NetLogs favicon (shield/lock icon in dark theme colors)
- [ ] Save as `fastapi_app/static/favicon.ico` (16x16 and 32x32)
- [ ] Add `<link rel="icon" href="/static/favicon.ico">` to base template
- [ ] Add SVG favicon for modern browsers

### Verification
- [ ] No 404 error in browser console for favicon
- [ ] Favicon displays in browser tab
- [ ] Favicon displays in bookmarks

---

## QW-02: Log Export (CSV/JSON)

### Description
Allow users to export filtered log results for offline analysis or sharing.

### Tasks
- [ ] Add "Export" dropdown button to log viewer toolbar
- [ ] Export options: CSV, JSON, plain text
- [ ] Export current filtered results (respect all active filters)
- [ ] Limit export to 50,000 rows (prevent memory issues)
- [ ] Show row count warning if results exceed limit
- [ ] Streaming download for large exports
- [ ] Add API endpoint: `GET /api/logs/export?format=csv&...filters`

### Verification
- [ ] CSV export contains correct columns and data
- [ ] JSON export is valid JSON with all fields
- [ ] Filters are applied to exported data
- [ ] Large exports (50K rows) download without timeout
- [ ] Export filename includes date and filter summary
- [ ] Button is visible and accessible in log viewer

---

## QW-03: GeoIP on Dashboard

### Description
Add country information to the Top Source IPs table on the dashboard.

### Tasks
- [ ] Add `geoip2` to requirements
- [ ] Download GeoLite2-Country database (free)
- [ ] Create simple GeoIP lookup utility
- [ ] Add country column to "Top Source IPs" table on dashboard
- [ ] Add country flag emoji or 2-letter code
- [ ] Skip lookup for private IPs (show "Internal")
- [ ] Cache results in memory

### Verification
- [ ] External IPs show correct country
- [ ] Internal IPs show "Internal" (not errors)
- [ ] Country column displays in table
- [ ] Performance: Lookup doesn't slow dashboard load (< 100ms for 10 IPs)

---

## QW-04: Email Notifications for Critical Alerts

### Description
Simple email notification when critical events occur (bridge to Phase 1 alerting).

### Tasks
- [ ] Add SMTP configuration to `.env`:
  ```
  SMTP_HOST=
  SMTP_PORT=587
  SMTP_USER=
  SMTP_PASSWORD=
  SMTP_FROM=netlogs@company.com
  ALERT_EMAIL_TO=security-team@company.com
  ```
- [ ] Create `fastapi_app/services/email_service.py`
- [ ] Send email when:
  - Device goes offline (no logs for 10 min)
  - Disk usage exceeds 85%
  - Emergency cleanup triggered
- [ ] HTML email template with NetLogs branding
- [ ] Rate limit: Max 1 email per event type per 15 minutes
- [ ] Add email configuration section to System page

### Verification
- [ ] Email sends when device goes offline
- [ ] Email sends when disk exceeds threshold
- [ ] Rate limiting prevents email flood
- [ ] HTML email renders correctly in major email clients
- [ ] Invalid SMTP config shows error (doesn't crash app)

---

## QW-05: Device Health Check

### Description
Periodic ping/SSH check to verify device connectivity beyond log reception.

### Tasks
- [ ] Add scheduled task (every 5 minutes) to check device health
- [ ] Health check methods:
  - Check last log timestamp (already available)
  - TCP port check to device IP (configurable port)
  - Optional: SSH connection test (if credentials configured)
- [ ] Add health status to device model:
  - `HEALTHY`: Receiving logs + reachable
  - `WARNING`: Reachable but no recent logs (> 5 min)
  - `CRITICAL`: Not reachable
  - `UNKNOWN`: Not yet checked
- [ ] Update device list page with health indicators (colored dots)
- [ ] Add health history (last 24h uptime percentage)

### Verification
- [ ] Healthy devices show green indicator
- [ ] Devices with no recent logs show yellow warning
- [ ] Unreachable devices show red critical
- [ ] Health check doesn't overwhelm network (rate limited)
- [ ] Health history tracks correctly over 24 hours

---

## QW-06: Saved Search Queries (Simple)

### Description
Let users save and quickly reload their frequently used search filters.

### Tasks
- [ ] Add "Save Search" button to log viewer
- [ ] Store saved searches in browser localStorage (no backend needed for MVP)
- [ ] Save: name, all current filter values, time range
- [ ] "Saved Searches" dropdown in log viewer toolbar
- [ ] Load search: Populate all filters from saved data
- [ ] Delete saved search
- [ ] Limit: 20 saved searches per browser
- [ ] Import/export saved searches as JSON

### Verification
- [ ] Save button captures all active filters
- [ ] Loading saved search restores all filters correctly
- [ ] Dropdown shows all saved searches
- [ ] Delete removes search from list
- [ ] Searches persist across browser sessions
- [ ] Works in Chrome, Firefox, Edge

---

## QW-07: Dashboard Auto-Refresh Controls

### Description
Let users control the auto-refresh interval on the dashboard.

### Tasks
- [ ] Add refresh interval selector to dashboard header
- [ ] Options: Off, 15s, 30s, 60s (default), 5m
- [ ] Save preference in localStorage
- [ ] Show countdown to next refresh
- [ ] Manual refresh button
- [ ] Pause auto-refresh when browser tab is inactive

### Verification
- [ ] Interval selector changes refresh rate
- [ ] Preference persists across page reloads
- [ ] Countdown timer shows correctly
- [ ] Manual refresh updates data immediately
- [ ] Tab-inactive pause works (check with background tab)

---

## QW-08: Session Flow Tracer Enhancement

### Description
Enhance the existing `/api/logs/session-flow` endpoint with a visual UI.

### Tasks
- [ ] Create `fastapi_app/templates/logs/session_flow.html`
- [ ] Input: Source IP, Destination IP, Time range
- [ ] Visual flow diagram:
  - Show traffic path through multiple firewalls
  - Arrow direction indicating flow
  - Each hop shows: device, action, policy, timestamp
  - Color: green (allowed), red (denied)
- [ ] Link from log viewer: "Trace Session" button for selected log entry
- [ ] Export flow as image or text

### Verification
- [ ] Session flow traces across multiple firewalls
- [ ] Visual diagram renders correctly
- [ ] Allowed and denied hops show different colors
- [ ] Link from log viewer populates search correctly
- [ ] Works with logs that traverse 2+ firewalls

---

## QW-09: Dark/Light Theme Toggle

### Description
Add theme preference toggle for users who prefer a light background.

### Tasks
- [ ] Create light theme CSS variables (override dark theme)
- [ ] Add theme toggle button in navigation bar (sun/moon icon)
- [ ] Save preference in localStorage
- [ ] Apply theme on page load (before render to prevent flash)
- [ ] Ensure all pages work in both themes
- [ ] Charts adapt to theme (Chart.js colors)

### Verification
- [ ] Toggle switches between dark and light themes
- [ ] All pages render correctly in both themes
- [ ] Charts are readable in both themes
- [ ] Preference persists across sessions
- [ ] No flash of wrong theme on page load

---

## QW-10: Cisco ASA Parser (Quick Version)

### Description
Add basic Cisco ASA log parsing to support the most common firewall vendor.

### Tasks
- [ ] Add Cisco ASA parser class to `fastapi_app/services/parsers.py`
- [ ] Parse common ASA message IDs:
  - 106001, 106006, 106007, 106015: Denied traffic
  - 106023: Permitted traffic
  - 302013/302014: Session create/teardown
  - 305011/305012: NAT translation
  - 710003, 710005: Permitted/denied TCP connections
- [ ] Extract fields: srcip, dstip, srcport, dstport, protocol, action, interface_in, interface_out
- [ ] Add "CISCO" option to parser dropdown in device settings
- [ ] Auto-detect `%ASA-` prefix for new devices

### Verification
- [ ] Sample ASA denied traffic logs parse correctly
- [ ] Sample ASA session teardown logs parse correctly
- [ ] Action field maps correctly (deny/permit/drop)
- [ ] Interface names extracted correctly
- [ ] Unknown ASA messages fall back to generic parsing
- [ ] Parser dropdown shows Cisco option

---

## QW-11: Bulk Device Operations

### Description
Allow approving/rejecting multiple pending devices at once.

### Tasks
- [ ] Add checkboxes to device list table
- [ ] "Select All" checkbox in header
- [ ] Bulk action bar: "Approve Selected" / "Reject Selected" buttons
- [ ] Confirmation dialog with count
- [ ] API endpoint: `POST /api/devices/bulk-update` with body `{ids: [...], action: "approve"}`
- [ ] Success/error feedback

### Verification
- [ ] Checkboxes appear on device rows
- [ ] Select all selects only visible/filtered devices
- [ ] Bulk approve changes status for all selected
- [ ] Bulk reject changes status for all selected
- [ ] Confirmation shows count of affected devices
- [ ] Error handling for partially failed operations

---

## QW-12: Log Viewer Keyboard Shortcuts

### Description
Add keyboard shortcuts for efficient log investigation.

### Tasks
- [ ] `S` - Focus search box
- [ ] `R` - Refresh results
- [ ] `J/K` - Next/previous log entry
- [ ] `Enter` - Expand selected log details
- [ ] `Escape` - Collapse log details / clear search
- [ ] `Left/Right arrows` - Previous/next page
- [ ] `?` - Show keyboard shortcuts help
- [ ] Add shortcuts help modal

### Verification
- [ ] All shortcuts work correctly
- [ ] Shortcuts don't interfere with typing in input fields
- [ ] Help modal shows all available shortcuts
- [ ] Shortcuts work across browsers

---

## Quick Wins Priority Order

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| 1 | QW-01: Favicon | 30 min | Professionalism |
| 2 | QW-02: Log Export | 1 day | High user value |
| 3 | QW-04: Email Notifications | 2 days | Critical for monitoring |
| 4 | QW-06: Saved Searches | 1 day | Productivity |
| 5 | QW-10: Cisco Parser | 2-3 days | Market coverage |
| 6 | QW-03: GeoIP Dashboard | 1-2 days | Security context |
| 7 | QW-05: Device Health | 2 days | Operational awareness |
| 8 | QW-11: Bulk Device Ops | 1 day | Efficiency |
| 9 | QW-07: Refresh Controls | 4 hours | UX improvement |
| 10 | QW-12: Keyboard Shortcuts | 1 day | Power user productivity |
| 11 | QW-08: Session Flow UI | 2 days | Investigation tool |
| 12 | QW-09: Theme Toggle | 1-2 days | User preference |
