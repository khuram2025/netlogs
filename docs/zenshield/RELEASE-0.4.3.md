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

## Release identity

- Build commit: `a6ad646963261b8a46f999d9d448fdd520713cd8`.
- Image: `zenshield:0.4.3`, ID `sha256:e479e7ee9ee3bd866cf8f5c0a820895455f3501577b26182c2045ec7b54169fc`.
- Signed package: 562,780,738 bytes; SHA-256 `afda84a0654dbf65f24fce8a0ad89647cc02211436b09e5f61d92e8c3c02a083`.
- Native bootstrap: `bootstrap-230fef0ba0a66ad8.tar.gz`; SHA-256 `230fef0ba0a66ad84cf0d834c2b149c38ef322ec11328794e04ec364d7d51be8`.

## Populated upgrade tests

Two isolated six-service upgrades from the real 0.3.4 image passed with
30,343,398 synthetic historical events each, using the pinned appliance
dependencies and a 6 GiB ClickHouse container limit. One fixture used wide,
repeated event payloads; the other used a distinct source IPv4 address per
event to exercise high-cardinality flow analytics. Synthetic compression is
not representative of the affected appliance's compressed data size.

Both retained all original events and added 100 live, late-arriving events
while history was pending. Final totals matched exactly: 30,343,498 raw events
and flow hits, 20,229,032 policy hits, 5,057,233 implicit-deny hits, and
3,034,440 FortiGate threat events. Both replayed an interruption after atomic
batch publication and before checkpointing. The high-cardinality fixture also
restarted ClickHouse while history remained pending, then finished correctly.

The high-cardinality run recorded a peak backfill query memory use of
189,777,487 bytes, at most 250,000 written rows per batch, and 492 completed
batch queries including replay. These figures describe this fixture, not a
performance guarantee for every appliance. Eleven recovery/confirmation/
diagnostic tests, 22 OTA/package tests, four connection-readiness tests and
the Chromium Updates-dialog regression also passed.

## Live OTA acceptance

The disposable appliance downloaded the signed package from Zentryc and
successfully upgraded through its existing 0.3.4 updater to 0.4.3. The local
primary independently downloaded and upgraded from 0.4.2 to 0.4.3. Both passed
six-service health, exact image identity, PostgreSQL and ClickHouse schema,
registration identity, credential-key preservation and licence synchronization
checks.

Authenticated HTTP checks passed for the Updates dialog, CSRF protection,
stale-action rejection and Storage Monitor rendering. Storage checks passed
for real host filesystem reporting, protected-disk and shrink rejection,
invalid quota rejection and a completed rescan with a non-replayable token.
The disposable appliance rebooted and passed those checks again; all four
empty-history jobs completed successfully.

The primary retained its 53,093 baseline DNS events and one syslog event.
After installation it reported 53,397 DNS events, with a receipt timestamp
later than update completion, confirming continued real DNS ingestion.

The original remote appliance was not directly accessible from this
workstation. Its result remains separate from these local canary results.

## Publication

The public installer passed shell syntax, bootstrap checksum and Ed25519
signature verification. A complete public OTA package download matched the
release checksum and passed signed inventory verification. The full 100%
rollout was enabled after both local canaries succeeded. Zentryc confirmed
that the affected 0.3.4 appliance is eligible for 0.4.3; its own installation
has not yet been reported. Automatic-update preferences were preserved.

Source and acceptance documentation are synchronized to GitHub `main`, and
`zenshield-v0.4.3` identifies the immutable runtime build commit.
