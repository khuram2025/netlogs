# ZenShield 0.4.3

This release moves historical analytics processing out of application startup.
It addresses an upgrade failure path on appliances with large existing log
datasets, while preserving the original logs, live ingestion and recoverable
update workflow.

## What changes

- Policy, implicit-deny, flow and FortiGate threat history loads in bounded
  background batches after the application becomes healthy.
- Interrupted batches can be replayed without adding duplicate counts. New
  events and late arrivals are collected separately from the frozen history.
- Database restarts preserve the source boundary and progress. Failed batches
  retry automatically with backoff instead of silently skipping history.
- **System > Storage Monitor > Historical analytics processing** shows progress
  and retry status. Historical analytics are partial while catch-up is running;
  original events remain available in Log Explorer.
- Backup-space estimates count shared snapshot files once. Backups and recovery
  retain the snapshot, history and progress ledger together.
- Sanitized update diagnostics recognize ClickHouse memory and query-time limits.
- All storage, DNS, licensing, merged upstream analytics and update-confirmation
  improvements from 0.4.2 remain included.

## Investigation

The affected appliance reported migration version 1, 30,343,398 syslog events,
6,156,829,833 compressed bytes and 81,772,140,294 uncompressed bytes. The failure
trace reaches the pending ClickHouse migration's `upgrade()` call. Migration 2
previously performed full-history GROUP BY operations during web startup.
The earlier successful rehearsal copied schema but did not copy these events.

The exact original database exception was not retained after rollback. Large
historical aggregation is the leading explanation, rather than a confirmed
specific error code. The affected remote appliance must still confirm its own
successful upgrade after this release becomes available.

## Installation

Use **System > Updates** on an existing registered appliance. Allow its backup,
installation and health validation to complete. The old 0.3.4 interface may
require its existing confirmation once; after upgrading, the dialog uses
**Install now** without a typed phrase.

Do not run the fresh Ubuntu installer over an existing appliance to bypass
the updater. Do not power off the appliance during installation or recovery.

For a new Ubuntu Server installation:

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | sudo bash
```

See [historical analytics operation](ANALYTICS-HISTORY.md) for processing,
retention, resource limits and recovery details. This is an OTA/native-installer
release; previously published OVF artifacts are separate downloads.
