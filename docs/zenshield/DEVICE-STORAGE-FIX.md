# Devices storage estimate correction — 16 September 2026

The 24-hour estimate previously filtered event timestamps. A source sending
delayed records could have recent receipts and a rising lifetime log count,
but no storage estimate. The affected installation had 25,004 recent DNS
receipts and zero events whose event timestamp fell in the same window.

The estimate now counts syslog `ingest_time` and Windows DNS `received_at`.
It multiplies those counts by the corresponding table's average uncompressed
bytes per physical row. Syslog virtual domains aggregate under the registered
sender IP; Windows DNS uses FINAL to avoid counting delivery duplicates.
Metadata is scoped to the current database. The table shows the window's log
count, explicitly labels an empty window, and distinguishes failed/partial
queries from zero usage. Query limits bound receipt-window scans.

This is an estimate of recently received data, not allocated filesystem space
or a forecast. Actual compressed capacity remains in Storage Overview.

## Validation and deployment

- `scripts/test-device-storage.py`: real isolated ClickHouse fixtures passed
  delayed-event, virtual-domain, stale/future receipt, duplicate, mixed-source,
  byte-calculation, partial-failure and template-state checks.
- `scripts/test-device-storage-http.py`: authenticated HTTPS passed on the
  disposable appliance and the primary appliance. The primary rendered
  23,911 receipts and 13.4 MB; its page request took 0.089 seconds locally.
- Chromium verified the primary table with zero JavaScript errors and no
  horizontal overflow at 1600px. All six primary containers were healthy.

The primary's original image identity matched the accepted 0.4.3 build.
The application-only fix is deployed as
`zenshield:0.4.3-device-storage-20260916`, with the previous compose override
retained for rollback. No database migration or event deletion was required.
The immutable public 0.4.3 OTA package and native installer are unchanged;
these source changes must be included in the next signed release.

The disposable VM's pre-existing failed startup recovery was restored after
recreating its missing database/cache containers with their existing volumes.
Its recovery and appliance units started successfully, and it was shut down
after validation. The primary remains running.
