# ZenShield installation and command manual

Fresh-install baseline: **ZenShield 0.4.4** (16 September 2026). Online guide: https://zentryc.com/zenshield/installation/

## Supported host

Use a dedicated Ubuntu Server 24.04 LTS amd64 / x86-64 server or full VM with
systemd. Recommended sizing is 4 logical CPUs, approximately 16 GiB RAM and a
100 GiB system filesystem with 30 GiB free. These are recommendations, not
installation minimums: CPU, memory and storage checks only warn and installation
continues automatically, including with `--check`. No override flag is needed.
Small hosts may install slowly or lack resources to start all services; actual
out-of-memory or disk-full errors still require more resources. Size production
hosts for event volume and retention. Internet access, working DNS, accurate time,
sudo access and an interactive terminal are required.
Other Ubuntu releases and ARM are not supported by this installation recipe.

## Install

The public installer installs the signed 0.4.4 OTA release directly. A fresh
installation does not need an intermediate release or the legacy support helper.

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | sudo bash
```

If curl is missing:

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates
```

To inspect the launcher and check compatibility first:

```bash
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh -o zenshield-install.sh
less zenshield-install.sh
sudo bash zenshield-install.sh --check
sudo bash zenshield-install.sh
```

The HTTPS launcher verifies the bootstrap signature and checksum. Installation
verifies the signed OTA release and its application image identity; dependency
images are pinned by digest. The installer preserves the current network and
existing Ubuntu administrator, and does not format extra disks or upgrade Ubuntu.

Choose a hostname, timezone, GUI password and console password. Passwords must
contain at least 5 characters and at most 72 UTF-8 bytes, with matching
confirmation and no apostrophes, backslashes, NUL or line breaks. Input is hidden:
no characters or asterisks appear while typing. Spaces are allowed; a longer
passphrase is useful. The wizard identifies the reason for a rejected entry.
No uppercase, number or symbol is required. There is no shared default password. Registration is automatic after setup and grants a 30-day unrestricted trial.
Publisher account credentials are never required.

Wait for six healthy services, then open the displayed HTTPS address. Verify
the unique certificate fingerprint before trusting it. Sign in as `admin`.
Use an organization-issued TLS certificate for deployment.

To resume interrupted setup:

```bash
sudo zenshield-setup
```

Rerunning the installer preserves initialized secrets and data. For future
application versions, use the updater rather than reinstalling.

## Verify the installation

Run `sudo zenshield`, then:

```text
show version
show services
show ip interface brief
show storage
show updates
```

Confirm version **0.4.4**, healthy services, the expected management address and
storage capacity. Open **System > Licences** to confirm registration and trial
status, then send a test event from an approved device and check **Logs**.
The [0.4.4 release notes](https://zentryc.com/downloads/zenshield/0.4.4/Release-Notes.md)
describe the release and its validation.

## CLI commands

Run `sudo zenshield` from the existing administrator account, or sign in at the
VM console as `zenadmin` with the console password chosen during setup.

| Command | Purpose |
| --- | --- |
| `help` | List commands |
| `show version` | Installed version |
| `show ip interface brief` | Interfaces and IP addresses |
| `show ip route` | Routing table |
| `show dns` | DNS configuration |
| `show services` | Service health |
| `show storage` | Disks, pools and capacity |
| `show updates` | Registration and update status |
| `ping <IP-or-hostname>` | Connectivity test |
| `setup` | Guided configuration |
| `password gui` | Change the GUI password |
| `password console` | Change the console / expert password |
| `expert` | Authenticated Linux maintenance |

Network changes can be made under System > Network or with:

```text
configure terminal
network
commit
confirm <token-shown-after-commit>
end
```

Follow the prompts, verify connectivity and confirm within 120 seconds. Without
confirmation, the watchdog restores the previous network. `rollback` restores
it immediately. Keep console access available when changing a remote address.

## Start collecting logs

1. Send syslog to the appliance address on UDP 514 over a trusted network.
2. Review the discovered source in Devices and approve the intended device.
3. Send fresh events and check Logs. Events from pending sources are discarded.

If immediate approval refresh is needed, use `service restart syslog`.

## Storage

The native install uses Docker data volumes on the system filesystem initially.
Attach a blank data disk, then use System > Storage to review and confirm an
initialization plan. The appliance pauses services, copies and verifies data,
and retains the original volumes for recovery.

A large physical system disk can still contain a small root filesystem. Use
**Rescan attached and expanded disks**, then **Grow system filesystem** for a
supported layout. Never initialize the operating-system disk as a blank data disk.
See the [storage manual](https://zentryc.com/downloads/zenshield/ZenShield-Storage.md)
for supported layouts, recovery and expansion commands.

The GUI supports adding blank disks, rescanning enlarged virtual disks and
growing ClickHouse or application volumes. Keep all pool disks attached.
Shrinking or removing allocated disks requires an offline migration. A storage
pool does not provide redundancy. Back up every appliance disk and test recovery.

## Future updates

The tested upgrade baseline for 0.4.4 is **0.4.3**. Older appliances receive
0.4.3 as an intermediate release first; if that older updater fails, use the
signed support instructions below. Fresh installs start directly on 0.4.4.

Use System > Updates or these CLI commands:

```text
update check
show updates
update install
```

In the GUI, choose **Install update**, review the offered version, and choose
**Install now** or **Cancel**. No typed confirmation phrase is required in the
0.4.4 GUI. The CLI still requires the exact `INSTALL X.Y.Z` confirmation for the
offered version. An older unregistered appliance can use `update register` with
a dedicated token before upgrading. Updates verify
compatibility, signatures and checksums, and back up datastores before switching
images. Allow enough free space for a full backup and a maintenance window.
Automatic installation defaults to off. Offers depend on rollout eligibility.

### Existing appliances with a failed legacy upgrade

An existing 0.3.4 appliance that reports `du failed (exit 1)` before installing
0.4.3 needs the corrected updater loaded before retrying. Follow the
[signed support upgrade instructions](https://zentryc.com/downloads/zenshield/0.4.3/SUPPORT-UPGRADE-0.4.3.md).
This is an upgrade with service downtime and retained backups; do not reinstall
or delete existing data. The helper accepts versions 0.3.3, 0.3.4, 0.4.0, 0.4.1
and 0.4.2. It is not needed on a fresh 0.4.4 installation.

After upgrading a populated appliance, historical analytics may continue in
the background. View **System > Storage Monitor > Historical analytics
processing**. Fresh installations have no existing history to backfill.

## Troubleshooting

If an older password prompt repeats a generic message, press Ctrl+C and rerun
the public installer command above. It refreshes the wizard on an appliance with
unfinished setup, preserving existing data. Enter a new unique password of at
least 5 characters, then repeat it at `Confirm password:`. Do not share passwords in
support messages. `sudo zenshield-setup` alone uses the already installed wizard.

During installation, Ubuntu may restart its network and DNS services. The OTA
release download retries temporary DNS, connection, timeout and transient HTTP
failures up to six attempts, waiting 5, 10, 20, 30 and 30 seconds between attempts.
Partial downloads are discarded; complete checksum-verified downloads are reused.
If DNS remains unavailable, inspect the existing configuration before rerunning
the same installer:

```bash
getent hosts zentryc.com
resolvectl status
```

Confirm working DNS and outbound HTTPS. The installer preserves your configured
DNS servers and continues to enforce TLS, release signatures and checksums.

```bash
sudo systemctl status zenshield-agent zensheild
sudo journalctl -u zensheild -u zenshield-agent --since "15 minutes ago"
sudo zenshield-setup
sudo zenshield-update check
```

The `zensheild` service spelling is retained for compatibility. Allow services
to finish starting after a reboot before testing HTTPS. Resolve the reported
problem before retrying setup or updates; do not delete active updater backups.

Support and registration: https://zentryc.com/contact/

## Licences and subscription management

Each new installation automatically registers a unique appliance identity with
Zentryc after setup and receives a 30-day trial: all features, unlimited devices
and events. If connectivity is unavailable, registration retries automatically.
Open **System > Licences** to view the plan, allowance, registration ID, expiry,
last synchronization and any registration or verification error.

Fleet administrators can find it at https://zentryc.com/ota/fleet/?tab=appliances
and its trial at https://zentryc.com/ota/fleet/?tab=subscriptions.
Open the subscription, choose **Edit Subscription**, and extend it using
**Extend by days**, change Trial to Subscription, or adjust the plan and unlimited
allowance. Save Changes. Settings synchronize within five minutes while online;
the appliance's **Refresh licence** button applies them immediately.

To transfer to another subscription, reassign the appliance in fleet or generate
a single-use registration code in the target subscription and enter it in
**System > Licences**. The target must be an active ZenShield subscription with
an available appliance slot. Never enter publisher credentials on the appliance.

Registration proves possession of a device key using a single-use challenge.
Signed licences are bound to that appliance. Re-registration preserves trial
history; deleting keys does not restart the same virtual hardware's trial.
Back up the full appliance identity. Independent clones need unique virtual
hardware identities; do not clone an initialized appliance as a distribution image.

Expiry and suspension are reported in the Licences tab; collection and existing
data remain available in this release. Offline licence expiry is calculated
locally; synchronization older than 24 hours is marked stale. Restore DNS,
accurate time and outbound HTTPS to zentryc.com to reconnect.

## Existing VMware OVF download

The published **0.3.1 OVF is a legacy, unchanged image**, not the 0.4.4 baseline.
For a new deployment, create an Ubuntu Server 24.04 LTS VM and use the native
installer above to start directly on 0.4.4 with the current setup, storage,
licensing and updater features. The legacy image retains its original 16-byte
password minimum. The 0.4.3 support helper does not accept version 0.3.1.
See the online installation guide for the legacy OVF download and checksum.
