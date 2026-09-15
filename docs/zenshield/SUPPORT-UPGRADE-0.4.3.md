# Upgrade an older appliance when its updater stops before installation

The affected appliance's 15 September 2026, 09:48 UTC attempt reported
**`du failed (exit 1)`**. In the old 0.3.4 updater, this disk-size scan runs
before writers stop, before a new backup begins and before candidate code is
installed. No new rollback is required when the attempt stops there, which
explains the absence of a recovery label for this failure.

This differs from the earlier support retry that reached ClickHouse migration
startup. The old updater can fail its live disk scan when ClickHouse replaces
files during background merges. Its discarded stderr means that this specific
underlying filesystem error is not established. This report does not establish
corruption of the existing events, and reinstalling or deleting data is not
the appropriate response.

Fixes inside a candidate release cannot repair an old updater's earlier
preflight checks. A recovery also restores the old updater. The command below
loads the corrected updater from the **verified, signed 0.4.3 package first**,
then performs a normal backed-up installation of that same release.

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/diagnostics/support-upgrade-0.4.3-v1.py | sudo python3 -
```

This is a real upgrade. Services pause during backup and installation. Keep
the appliance powered on and do not start another update at the same time.
The worker runs under systemd and continues if SSH disconnects. Existing
backups, signatures, free-space checks and recovery remain enabled.

The helper verifies that its updater modules came from the verified release.
Its live size estimate uses the corrected file walk, tolerating only vanished
children while retaining errors for missing roots and denied access. The strict
`du` scan runs only after all six data-writing services are confirmed stopped.
The report distinguishes the two scans. Unique attempt directories preserve
backups from earlier attempts instead of colliding with them.

Expected successful output includes `result: success`, `installed_version:
0.4.3`, and a committed transaction. If it fails, share the final JSON instead
of repeatedly retrying. It includes the operation, static error categories,
known ClickHouse error names/codes and allowed source locations, without
returning raw logs, credentials or event records. A private copy is retained
under `/var/lib/zenshield-updater/support/`.

After a successful upgrade, use **System > Updates** for subsequent releases.
Historical analytics can continue processing after services become healthy;
see **System > Storage Monitor > Historical analytics processing**.

## Validation

The exact public command was run against the disposable appliance after
restoring its real 0.3.4 release. Backups from earlier 0.4.3 and 0.3.4 tests
remained present. The signed worker reported `verified_0.4.3_release`, five
live roots scanned by the corrected file walk, five strict scans after all
writers were verified stopped, no failures, and a committed 0.4.3 installation.
The helper's signature and diagnostic-redaction tests also passed. The
0.4.3 application had separately passed two 30.3-million-event migration tests;
this support-command test used the disposable appliance's empty baseline.

Helper SHA-256: `37d692be35e7f54eac7a28f06cc8bc281a48d67273237cd15bd85eec4f08e910`.
The immutable 0.4.3 package and its signing key are unchanged.

On 15 September 2026, the user also confirmed that the support upgrade worked
on the affected remote appliance. This is user-reported confirmation; the
workstation did not directly access that appliance. Fresh native installations
now start on 0.4.3 and do not need this helper.
