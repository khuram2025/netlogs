# ZenShield 0.3.4 storage release acceptance

Date: 2026-09-14. Product channel: `zenai` (existing ZenShield compatibility identifier).

Release ID: `0a049982-f9d7-4568-b4b2-cca85dcba15a`.

Package SHA-256: `22c7658c8a404014f839242c1b10b7bf5eae26bb24933cfcc01f4603af6630ee`.

Image: `zenshield:0.3.4`, ID `sha256:325ebc201e4c1bd0835d390707aec09c504f80fa6e27f02ac6696e5d1d71755b`.

Signed source commit: `1f1ec69d8f7833d522b4c170fde25c7f1f378561`.

## Findings and fixes

- The screenshots show a partitioned 300 GiB system disk and a much smaller filesystem. Formatting this disk as a new data volume would destroy the installation. A reviewed system growth action now handles supported Ubuntu root partition/LVM layouts without formatting the system disk.
- Disk discovery was disabled until a managed pool existed. Rescanning now discovers newly attached disks before initialization and refreshes expanded managed PV capacity.
- The monitor used container filesystem statistics and depended on an absent `/hostfs` mount. It now reads restricted host-agent metrics, identifies the actual ClickHouse filesystem, and lists real host mounts without exposing the host root to the web container.
- Pool initialization used a fixed 16 GiB threshold and allocation percentages without checking existing data size. Allocation now accounts for source data, filesystem overhead and copy headroom before creating the pool.
- Staged initialization now records volume-group and logical-volume identities. Retry preserves recognized ext4 filesystems and refuses changed identities.
- Migration now checks capacity before stopping services, journals the prior data configuration, disables container automatic restart during the transition, retains original volumes, verifies copies, and restores the previous configuration if startup fails.
- An interrupted LV/filesystem growth can retry the filesystem resize at the same logical-volume size.
- Missing pool members, wrong mounts, system-disk initialization, shrinking, stale plans and plan replay are rejected.
- Quota settings reject invalid numeric values and inconsistent thresholds. The UI explains that quota is not allocated disk capacity. The cleanup command uses the actual data filesystem and installed appliance paths.
- Console commands expose rescan, system growth, data-volume growth and migration retry with explicit confirmation.

## Final acceptance evidence

Testing used the explicitly marked disposable Ubuntu VM at 192.168.18.137 with newly created test disks. The primary appliance's disk layout was preserved.

| Scenario | Result |
| --- | --- |
| Ubuntu linear LVM root, 4 GiB filesystem on an 8 GiB partition of a 24 GiB disk | Partition, PV, LV and ext4 expanded; file checksum retained |
| Plain ext4 root with a later-numbered boot partition | Correct physical final partition expanded; data retained |
| Initialize pool and migrate application stores | Verified copy, original data retained, services healthy |
| Add a second data disk | Allocatable pool capacity increased |
| Expand an existing virtual data disk | Rescan exposed added capacity; 48 GiB pool represented |
| Extend ClickHouse filesystem | Online growth successful |
| Interrupted filesystem resize | Retry at current LV size completed successfully |
| Interrupted filesystem creation | Journaled initialization resumed; repeated retry did not reformat data |
| Changed staged-pool identity | Rejected without modifying retained files |
| Injected migration startup failure | Original configuration and services restored; subsequent retry succeeded |
| Reboot after storage changes and signed OTA update | Managed mounts and test checksum retained; six services healthy |
| GUI/API checks on test and primary appliances | Host mounts/capacity rendered, protected disk/shrink/CSRF/invalid quota requests rejected, confirmed rescan completed, replay rejected |
| DNS regression | 40 integration checks passed against the release image |
| OTA contract regression | 19 signature, inventory, target, transport and policy tests passed |
| Public installer regression | 29 resource/download tests and 11 password tests passed; signed public bootstrap verified; tampering rejected |

The disposable VM's real root was automatically expanded by cloud-init after increasing its virtual disk. A separate real partition test verified the new plain-ext4 growth operation, including non-sequential partition numbers.

## OTA and publication

- Disposable appliance: installed the signed package through Zentryc OTA from 0.3.3 to 0.3.4; server recorded success.
- Primary appliance at 192.168.18.129: installed through Zentryc OTA from 0.3.1 to 0.3.4; server recorded success and all six containers were healthy.
- Primary DNS event count increased from 20,575 before deployment to 20,639 after verification; syslog count remained 1. Fresh Windows DNS events arrived after the update.
- Full rollout ID: `7563696b-628d-4722-910b-70643c9034a5`, stage `full`, 100%, no target-group restriction. Existing automatic-update preferences and maintenance windows were retained.
- The remote appliance `HQPR-DNSLOGS01`, currently on 0.3.3 at verification time, was confirmed eligible for 0.3.4. Its installation was not remotely forced or claimed complete.
- A final server-side eligibility correction prevents legacy non-semantic versions from receiving signed ZenShield releases. Six invalid-version cases, the valid remote offer and unchanged ZenPlus-channel behavior were checked before deploying the correction.
- Public package was downloaded and its full SHA-256 verified. Public launcher, bootstrap signature and storage manual match reviewed files.

## Use on the remote appliance

Install 0.3.4 from **System → Updates**. Then open **System → Storage**, rescan disks, and use **Grow system filesystem** for the existing expanded system disk. A separate pool requires a separate blank disk; an existing OS disk remains protected.

See [the public storage guide](https://zentryc.com/downloads/zenshield/ZenShield-Storage.md).

## Scope and limits

Real filesystem expansion tests covered ext4 and standard Ubuntu linear LVM. NVMe rescanning and the XFS branch were implemented but were not exercised on physical NVMe or XFS hardware in this environment. Encrypted, RAID, thin and multi-PV root layouts are refused for automatic growth. Disk removal and shrinking are unsupported. Migration still requires enough actual space to retain and verify data; resource warnings cannot create missing capacity.

The remote screenshot appliance was not accessed directly, at the user's instruction. Its eligibility is verified; its eventual update and disk expansion depend on its local update policy or administrator action. This release updates the native installer and OTA package; the existing downloadable OVF export was not rebuilt as part of this storage update.
