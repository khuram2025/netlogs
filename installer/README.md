# ZenShield installation and command manual

Native release: 0.3.2. Online guide: https://zentryc.com/zenshield/installation/

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
No uppercase, number or symbol is required. There is no shared default password. Optionally enter a dedicated appliance
registration token; publisher account credentials are never required.

Wait for six healthy services, then open the displayed HTTPS address. Verify
the unique certificate fingerprint before trusting it. Sign in as `admin`.
Use an organization-issued TLS certificate for deployment.

To resume interrupted setup:

```bash
sudo zenshield-setup
```

Rerunning the installer preserves initialized secrets and data. For future
application versions, use the updater rather than reinstalling.

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

The GUI supports adding blank disks, rescanning enlarged virtual disks and
growing ClickHouse or application volumes. Keep all pool disks attached.
Shrinking or removing allocated disks requires an offline migration. A storage
pool does not provide redundancy. Back up every appliance disk and test recovery.

## Future updates

Use System > Updates or these CLI commands:

```text
update register
update check
show updates
update install
```

Enter a dedicated registration token when prompted. Installation requires the
exact `INSTALL X.Y.Z` confirmation for the offered version. Updates verify
compatibility, signatures and checksums, and back up datastores before switching
images. Allow enough free space for a full backup and a maintenance window.
Automatic installation defaults to off. Offers depend on rollout eligibility.

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
