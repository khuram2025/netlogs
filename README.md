# ZenShield

ZenShield combines network log collection, DNS analytics, threat intelligence, correlation, reporting and appliance management.

The full application and appliance source now live in this repository. See [the 0.4.1 release and acceptance record](docs/zenshield/RELEASE-0.4.1.md), [integration record](docs/zenshield/INTEGRATION-0.4.0.md), [installation guide](appliance/INSTALLATION.md), [storage guide](appliance/STORAGE.md), and [build guide](docs/zenshield/BUILD.md).

## Install on Ubuntu Server

Run the signed installer on Ubuntu Server 24.04 amd64:

```sh
curl -fsS -A zenshield-installer/1 https://zentryc.com/downloads/zenshield/install.sh | sudo bash
```

The installer verifies the bootstrap and signed release, then starts console setup. Resource recommendations produce warnings; actual installation, backup and migration operations still need sufficient free space to complete safely. Existing administrator and network access are preserved.

## Application and appliance interfaces

- `/system/`: network, expandable storage, licences, signed updates and access settings.
- `/system/storage-monitor/`: host/data capacity, retention settings and display/source timezones.
- `/devices/`: source enrollment and last-received status.
- `/threats/url-dns/?tab=dns`: Windows DNS workspace and resolved IPs.
- `/threats/url-dns/?tab=url`: Web Activity and firewall DNS analytics.

Upstream developer documentation remains in `docs/`, `DEPLOY.md`, `deploy/` and `agent/`. The appliance uses `appliance/` and `installer/`. Do not install the standalone `deploy/updater` service inside a ZenShield appliance; its host updater already manages signed releases and rollback.
