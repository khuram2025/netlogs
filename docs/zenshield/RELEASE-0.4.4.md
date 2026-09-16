# ZenShield 0.4.4

Corrects the Devices page's 24-hour storage estimate for delayed logs.

- Uses appliance receipt time for syslog and Windows DNS instead of the
  source's event timestamp. Delayed events now contribute to the day received.
- Combines firewall virtual domains under the registered sender IP and
  deduplicates Windows DNS delivery retries.
- Shows the received count beside the estimated uncompressed size.
- Distinguishes an empty window from unavailable or partial query results.
- Scopes metadata to the current database and bounds query execution.

The estimate is recently received event count multiplied by average
uncompressed bytes per event for each log table. It is not allocated disk
capacity or a forecast. Storage Overview continues to show physical totals.

## Installation and upgrades

Fresh Ubuntu Server 24.04 amd64 installations use the signed native installer
and start directly on 0.4.4:

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | sudo bash
```

Existing appliances must first be on **0.4.3**. This retains the corrected
updater and historical analytics migration as the tested upgrade baseline.
For an older appliance whose updater stops before installation, follow the
[0.4.3 bridge instructions](https://zentryc.com/downloads/zenshield/0.4.3/SUPPORT-UPGRADE-0.4.3.md).
That helper accepts 0.3.3, 0.3.4, 0.4.0, 0.4.1 and 0.4.2. Older versions need
a supported intermediate upgrade; do not reinstall an initialized appliance.

Use **System > Updates > Install update**, then confirm **Install now**.
The GUI does not require typing a phrase. Automatic update preferences and
maintenance windows remain under the appliance administrator's control.

No new database migration, credential reset or event deletion is required.
The existing 0.3.1 OVF remains a separate legacy artifact.

## Validation

The storage fix passed real ClickHouse tests for delayed events, virtual
domains, duplicate delivery, mixed sources, receipt windows, byte estimates,
partial query failures and rendered empty/unavailable states. The local
application hotfix passed authenticated HTTPS and Chromium verification,
including comparison of the displayed estimate with received log counts.
Signed release upgrade acceptance is recorded separately after rollout testing.
