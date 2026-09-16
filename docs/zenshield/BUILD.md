# Build and release ZenShield

Use an Ubuntu 24.04 amd64 build/test host with Docker. Build from the consolidated repository; do not apply `scripts/patch-upstream.py` to this already-integrated tree. That script is retained only for the original historical application baseline.

The current published fresh-install baseline is **0.4.4**. Its package and runtime tag are immutable. For a future release, set `VERSION` to a new, unpublished version and update the source version files before building; do not overwrite 0.4.4.

## DNS agent bundle

The appliance embeds the public agent bundle, never an enrolled agent configuration. With the .NET 10 SDK and Python available:

```sh
dotnet restore appliance/dns-agent/ZenShield.DnsAgent.csproj --locked-mode
dotnet publish appliance/dns-agent/ZenShield.DnsAgent.csproj -c Release -r win-x64 --self-contained true --no-restore -o /tmp/zenshield-dns-agent
python3 scripts/package-dns-agent.py /tmp/zenshield-dns-agent
```

The published 1.0.0 agent can also be obtained through an administrator session in Devices on an existing appliance. Keep its public bundle under `appliance/dns-agent-release/`. Never put source tokens or server credentials there.

## Image and checks

```sh
docker build --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" --build-arg ZENSHIELD_VERSION="${VERSION:?Set a new unpublished version}" -t "zenshield:$VERSION" .
python3 scripts/test-ota.py
python3 scripts/test-native-resources.py
python3 scripts/test-native-passwords.py
```

`appliance/requirements.lock` pins and hashes the Linux Python wheels. Docker builds the frontend from `package-lock.json` and includes the PDF browser. Record the base-image digests and resulting image ID with the release. Published image tags and release packages are immutable.

Run `scripts/run-merged-integration.py IMAGE fresh` and `... IMAGE upgrade` only on a designated disposable appliance test host containing `/root/ZENSHIELD-NATIVE-INSTALL-TEST`. These create isolated fixture databases and verify schema adoption, stored credentials, pages, filters, DNS ingestion, compliance proofs and PDF export. Run the upstream `tests/` suite in the image's runtime with pytest/pytest-asyncio installed in a disposable test layer.

## Signed OTA and installer

Use the existing independent release key from a private location:

```sh
python3 scripts/build-ota.py --version "${VERSION:?Set a new unpublished version}" --min-version "${MIN_VERSION:?Set the tested upgrade baseline}" --product-id zenai --private-key /secure/release.key --public-key appliance/ota-release.pub --output "/releases/ZenShield-$VERSION.zup" --source-commit "$(git rev-parse HEAD)" --include-control --changelog "Describe the changes in this release"
python3 scripts/build-native-installer.py --prior-version "$MIN_VERSION" --release-package "/releases/ZenShield-$VERSION.zup" --private-key /secure/release.key --output-dir /releases/installer
```

The internal product ID remains `zenai` for compatibility with registered ZenShield appliances. Never include the private signing key, `cred.md`, runtime environments, enrolled agent configuration or test/customer data in artifacts.

Publish first to the local test appliance's canary group. Verify the signed download, actual upgrade, storage/identity/data preservation, licences, DNS ingestion and reboot. Admit the local primary appliance only after the test appliance passes, then promote to full rollout. Update the public installer only after acceptance. A full rollout makes the update available; each remote appliance still follows its configured installation policy.

## Future source changes

Fetch all branches and compare ancestry before merging. Merge upstream and local work in a `codex/` integration branch, resolve overlaps explicitly, and test the complete source build. Push main normally after re-fetching; never force-push over other developers' work. Tag appliance releases with `zenshield-vVERSION` to distinguish them from the upstream legacy build workflow.
