# ZenShield 0.4.2

This release improves update recovery and simplifies installation from **System > Updates**. It includes the consolidated application, storage expansion fixes, Windows DNS agent, and upstream analytics from 0.4.1.

## Changes

- Each update attempt has a separate verified backup. A retry after successful recovery no longer collides with the previous attempt's backup directory.
- Update history associates recovery with the current attempt. A failure before installation starts cannot inherit an older attempt's “recovery verified” status.
- Select **Install update**, review the offered version, and select **Install now**. The GUI no longer requires typing an INSTALL phrase. Cancel does not start an update; stale release selections are rejected.
- Update failures identify the operation, failed service, and relevant categories such as a memory kill or disk-space error, when available. Raw logs, environment values, and credentials are not included in these summaries.
- Before schema changes, the updater allows a bounded wait for transient PostgreSQL or ClickHouse connection failures. Authentication and SQL errors stop immediately. Migration statements are not retried by this readiness loop.

## Installing

On a registered appliance, open **System > Updates**, select **Check for updates**, and install **0.4.2**. Allow the appliance to complete its backup, installation, validation, and any recovery without powering it off. After success, confirm the version and service health.

An appliance still running an older UI may require its existing typed confirmation once to install 0.4.2. Subsequent updates use the new confirmation dialog. Existing console commands remain compatible.

For a new Ubuntu Server installation, use the published installer:

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | sudo bash
```

The installer verifies the pinned bootstrap and the signed appliance release. Existing installations should use the appliance updater to preserve its verified backup and recovery workflow.

## Investigation and validation scope

The reported 0.3.4 → 0.4.1 failure contained only a generic Docker exit status. Its original detailed output was not retained by the old updater, so the first failure's exact cause is unconfirmed. A later retry did reveal the backup-directory collision fixed here. An isolated rehearsal using copies of the affected appliance's PostgreSQL data, ClickHouse schema and migration ledger, and credential keys passed candidate application startup without an OOM kill. That rehearsal did not copy all ClickHouse event data or execute the original host update transaction.

Regression checks cover verified file backup/recovery followed by a same-release retry, per-attempt recovery history, signed package validation, database readiness failures, and browser confirmation behavior. The release acceptance record documents live upgrade and publication results separately.

This is an OTA and native-installer release. Previously published OVF downloads are separate artifacts.

## Release identity

- Source/image build commit: `1bc1ea1e59d90c09e26ae037e9f2f5c22ff077e7`.
- Image: `zenshield:0.4.2`, ID `sha256:44bd9cdd2b58335f40efb853a3028880afd6f677c964e452852708d6aa158f5d`.
- Signed package: `ZenShield-0.4.2.zup`, 562,771,546 bytes.
- Package SHA-256: `27bd50a68ff0c4b8594a1c7bcd56e90231eea692015563bfcb2db5e2749fff51`.
- Native bootstrap SHA-256: `385590f6606183962b50077811e22cea655ade51c59a6db47877291da0aebbdb`.

The source tag identifies the runtime build commit. Later documentation and acceptance-test commits do not change that runtime.

## Acceptance results

- Nine recovery/confirmation/diagnostic tests, 22 OTA/package checks, and four connection-readiness checks passed. Recovery testing performs real filesystem copies and checksum verification with a simulated Docker failure, then successfully retries the same release while retaining both backups.
- The final 0.4.2 image passed a complete six-service 0.3.4 upgrade using isolated native Docker volumes and the pinned appliance dependencies. Candidate schema verification, healthy service startup, and legacy credential-key rotation passed.
- Chromium verified the real Updates template: no typed phrase, version-labelled confirmation, cancellation without a request, one correctly formed confirmed request, visible failure details, and no JavaScript errors.
- Both local appliances downloaded and installed the signed release from Zentryc through their existing 0.4.1 updater. All six services became healthy. Registration identities, licence synchronization, persistent credential keys, and schema checks passed.
- Both appliances passed authenticated live Updates HTTP checks, CSRF enforcement, and rejection of stale or invalid installation requests. Storage checks covered host filesystem reporting, protected-disk and shrink rejection, quota validation, rescan completion, and one-use confirmation tokens.
- The test appliance rebooted and passed the health, Updates, and storage checks again.
- The primary retained its existing 48,344 DNS events and one syslog record. After the update, it reported 48,744 DNS events, with new receipt timestamps later than update completion. This verifies continued real DNS ingestion after the upgrade.
- The public installer passed shell syntax, pinned bootstrap checksum, and Ed25519 signature checks. A complete public package download matched the release checksum and passed signed-inventory validation.
- Full rollout is enabled for eligible appliances. The server confirms that the affected appliance still on 0.3.4 is offered 0.4.2. Installation follows the appliance's existing manual or automatic-update policy; no policy was forced on remote appliances.

The affected remote appliance's actual installation has not been performed from this workstation. Its successful rehearsal is separate from these two local OTA acceptance runs.

## Downloads

- [Release portal](https://zentryc.com/ota/zenai/releases/)
- [Signed OTA package](https://zentryc.com/downloads/zenshield/0.4.2/ZenShield-0.4.2.zup)
- [Public release notes](https://zentryc.com/downloads/zenshield/0.4.2/Release-Notes.md)
- [Ubuntu installer](https://zentryc.com/downloads/zenshield/install.sh)
