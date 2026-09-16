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

Signed 0.4.3 to 0.4.4 upgrades passed on both the disposable appliance and the
primary appliance. All six containers were healthy, and the disposable
appliance also passed a reboot check. Registration identity, licence,
persistent credential key, PostgreSQL revision and ClickHouse schema version
8 were preserved. The primary retained all 80,231 DNS records and its syslog
record; the received-window check displayed 21,056 receipts and 11.8 MB.
No new source traffic was claimed by this check.

Updater tests (22), native installer resource/download tests (31), password
prompt tests (11), and compatible-release selection tests (6) passed.
A package file permission problem caught during canary download was corrected
before installation; both subsequent signed upgrades succeeded.

The server selects the newest compatible release, so older supported clients
are offered the 0.4.3 bridge before 0.4.4. This selection preserves the
separate ZenPlus update flow. The release is published at 100% rollout;
appliance automatic-update preferences and maintenance windows still apply.

## Release identity

- Runtime source commit: `a31abf81aa4d4809fae160bd5b0bcf9399a2144b`.
- Signed package: `ZenShield-0.4.4.zup` (562,883,308 bytes).
- Package SHA-256: `1ec126d45fd361790529700095f6d7ef6af34a10ef11a05cd0cf9d061e2f8f7d`.
- Application image: `zenshield:0.4.4`.
- Image SHA-256: `3d3f1cedad7840d8ca362c688112e71a060c9af76bfb241c473451a86a5233f7`.
- Native bootstrap: `bootstrap-ebc98275f1253286.tar.gz`.
- Bootstrap SHA-256: `ebc98275f1253286cdfede8cfc9fdb5cf593ef16b1c11568ef280ef1e5f63de3`.
