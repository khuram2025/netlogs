# Investigating a recovered 0.3.4 → 0.4.2 failure

The 0.4.2 OTA rollout is paused after the affected remote appliance again reported a generic Docker error, followed by a retry collision. Its successful application rehearsal did not reproduce the complete host update transaction. The exact first Docker failure remains unconfirmed.

The running 0.3.4 updater cannot use fixes that are only installed later by a successful 0.4.2 transaction. The support command below first verifies the existing signed 0.4.2 package, loads its updater into a private staging directory, then performs one supervised upgrade attempt. It uses a new backup directory and captures sanitized Docker failure details before recovery recreates the candidate containers. It does not change automatic-update policy or remove historical backups.

This is a real installation attempt. Services pause during backup and installation. Keep the appliance powered on. The worker runs under systemd so an SSH disconnect does not terminate the installation.

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/diagnostics/support-upgrade-0.4.2-v2.py | sudo python3 -
```

Share the final JSON report. It identifies the failing operation and available static error categories or source locations, without raw logs, credentials or customer events. The same report is retained beneath `/var/lib/zenshield-updater/support/` in a private attempt directory. If disconnected, find the newest `report.json` there after reconnecting. Do not start another update while the support worker is active.

The package is pinned by SHA-256 and checked against the appliance's installed Ed25519 release key. The systemd worker script is also signature-verified. Existing backup, recovery, schema and health checks remain enabled. A failed attempt retains both its diagnostic report and backup; the appliance's normal recovery workflow restores the previous version when verification succeeds.

Validation includes local 0.3.4 startup with pre-existing release backup directories and a controlled candidate failure to exercise diagnostic capture before real rollback. This does not establish the cause of the remote appliance's first failure.
