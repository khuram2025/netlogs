# ZenShield 0.4.1 acceptance — 14 September 2026

This release consolidates every upstream branch identified in [the integration record](INTEGRATION-0.4.0.md), the deployed appliance application, and both commits from the original local appliance repository. ZenShield's signed updater and Windows DNS agent remain authoritative; upstream Web Activity and firewall DNS analytics are additional views.

## Release identity

- Source/image build commit: `ba593b9e180722c6328a0db3301274c2ece1a59b`.
- Image: `zenshield:0.4.1`, ID `sha256:096f681625707513e523d062f6d06c0abc393f1da0e2d33957be901508810340`.
- Signed package: `ZenShield-0.4.1.zup`, 562,765,731 bytes.
- Package SHA-256: `bfc8b512e478e35cc55c1f1db97dbcc404fd7827e0a8fabd5ee0d70a2da22503`.
- Native bootstrap SHA-256: `a54c5cf1a699559a9d7f351575449161a86e954537a0a2c59966265349ade9ac`.

The source tag points to the build commit. Later documentation commits on main record acceptance without changing the released runtime.

## Corrections found during acceptance

The merged PDF runtime increased the package above the former 500 MiB limit. The native installer and ZenShield portal now accept signed packages up to 2 GiB. Hash/signature validation, redirect restrictions and actual free-space checks remain in place.

The 0.4.0 test canary safely stopped before replacing services when ClickHouse removed temporary merge files during `du`. Its rollout was aborted. Version 0.4.1 tolerates vanished child entries during live size estimation, rejects missing roots and permission errors, and strictly rechecks backup space after stopping writers. The complete cold backup is still copied and checksum-verified before applying changes.

## Verification

- The consolidated runtime passed 154 upstream correlation/NQL tests. The subsequent 0.4.1 runtime change is its version identifier; the other corrections affect host backup sizing and the native installer.
- The final 0.4.1 image passed 53 existing-database upgrade checks and 49 fresh-database checks, including credential/event preservation, real collector writes, approval, schema migrations, analytics, compliance uploads and PDF generation.
- Both paths passed 40 authenticated Windows DNS checks. Fresh-database Chromium checks covered Web Activity, Windows DNS and Log Explorer without JavaScript errors or desktop page overflow.
- The final native bootstrap passed 31 resource/download/recovery tests and 11 password-prompt tests. Host OTA/package tests passed 22 checks, including live merge-file disappearance, missing roots and permission errors.
- The disposable appliance and primary appliance both downloaded and installed the release through Zentryc's signed OTA flow from 0.3.4. All six services became healthy; registration, licences, persistent private credential keys and stored events were preserved.
- Storage HTTP checks passed on both: system-growth controls, host mounts, ClickHouse filesystem usage, protected-disk/shrink/CSRF rejection, quota validation, confirmed rescanning and one-use confirmation tokens.
- The disposable appliance rebooted successfully and passed the storage and health checks again. The primary continued receiving real Windows DNS events after its upgrade.

Full rollout offers the release to eligible appliances; installation follows each appliance's configured automatic-update policy or manual confirmation. The existing OVF is a separate artifact and was not rebuilt for this source consolidation.

## Downloads

- [Signed OTA package](https://zentryc.com/downloads/zenshield/0.4.1/ZenShield-0.4.1.zup)
- [Release notes](https://zentryc.com/downloads/zenshield/0.4.1/Release-Notes.md)
- [Ubuntu installer](https://zentryc.com/downloads/zenshield/install.sh)
- [Storage guide](../../appliance/STORAGE.md)
