# Zentryc Appliance v3.1 — TODO

Companion to `INSTALLATION_PLAN.md`. Phased checklist; check off as you ship.

Legend: **[P0]**=foundations · **[P1]**=update server · **[P2]**=installer · **[P3]**=upgrade CLI · **[P4]**=UX · **[P5]**=docs · **[P6]**=hardening

---

## P0 — Locked image build pipeline

- [ ] Write `docker/web.Dockerfile` — multi-stage: builder compiles to `.pyc` with `python -OO -m compileall`, final stage is `gcr.io/distroless/python3`, copies only `__pycache__/` → `app/`, no source.
- [ ] Write `docker/syslog.Dockerfile` — same pattern; add `CAP_NET_BIND_SERVICE` docs.
- [ ] Write `docker/nginx.Dockerfile` — prebuild Vite assets (`npm ci && npm run build`), copy into `nginx:alpine`; drop default configs.
- [ ] Verify: `docker run --rm zentryc/web:test sh -c 'find / -name "*.py"'` returns **zero** (no `/bin/sh` means run with `ctr`/`crictl` instead for the test).
- [ ] Add `PYTHONDONTWRITEBYTECODE=1` + read-only rootfs + `USER 10001` to all Zentryc images.
- [ ] Add CI job (`.github/workflows/build-images.yml`): build → push → `cosign sign` → update manifest → publish.
- [ ] Generate and securely store **cosign** keypair; commit public key to repo, private key to CI secret.
- [ ] Generate and securely store **GPG** keypair for manifest signing; publish public key at `downloads.zentryc.io/zentryc.asc`.

## P1 — Update server (runs on YOUR remote host)

- [ ] Pick final domain (`updates.zentryc.io` / `registry.zentryc.io` / `downloads.zentryc.io` — or your choice) and point DNS.
- [ ] Provision Ubuntu 22.04 host; open 80/443 only.
- [ ] Install nginx + certbot; issue Let's Encrypt certs for all three subdomains.
- [ ] Deploy Docker Registry v2 container with htpasswd auth (see §6.2 of plan).
- [ ] Create **push-capable** account (`zentryc-publisher`) for CI; create **pull-only** account (`zentryc-appliance`) embedded in installer.
- [ ] Deploy nginx vhosts for `downloads.*` and `updates.*` (static file serving).
- [ ] Write and deploy `tools/make-manifest.sh` on build machine (reads just-pushed digests, emits `manifest.json`).
- [ ] Write backup cron on update server: nightly rsync of `/srv/registry` + `/var/www` off-box.
- [ ] Set up Cloudflare (or equivalent CDN) in front of `downloads.*` for installer high-availability.
- [ ] Publish first real `manifest.json` pointing at v3.1.0 image digests; verify with `gpg --verify`.
- [ ] Document registry TLS and auth settings in `deploy/appliance/update-server/README.md`.

## P2 — New one-line installer (`install.sh` v3.1)

- [ ] Rewrite `install.sh` to match §4.2 of plan (14 stages).
- [ ] Implement pre-flight: RAM/disk/OS/port 514/internet reachability checks.
- [ ] Implement **self-verification**: re-download `install.sh.sig`, verify against pinned GPG key before executing the rest.
- [ ] Fetch + verify `manifest.json` with `gpg --verify`.
- [ ] Install Docker CE + compose plugin from Docker's APT repo (pinned version).
- [ ] Do `docker login registry.zentryc.io` with embedded pull-only credential.
- [ ] `docker pull` every digest from the manifest; `cosign verify` each Zentryc image.
- [ ] Generate `/etc/zentryc/secrets.env` (Postgres pw, ClickHouse pw, Redis pw, `SECRET_KEY`, self-signed cert).
- [ ] Seed admin: `docker run --rm zentryc/web:VERSION python -m fastapi_app.cli.seed_admin --username admin --password admin123 --force-change`.
- [ ] Install `zentryc.service` systemd unit; `systemctl enable --now`.
- [ ] Install `/etc/sudoers.d/zentryc` (restricted sudo for future operator user).
- [ ] UFW rules: 22/tcp, 80/tcp, 443/tcp, 514/udp; deny everything else.
- [ ] Kernel tuning: `/etc/sysctl.d/99-zentryc.conf` (UDP buffer 26 MB, `net.core.rmem_max`, `fs.file-max`).
- [ ] Idempotency: if `/opt/zentryc/.installed` exists, hand off to `zentryc-upgrade` instead.
- [ ] Print summary banner with URL / admin creds / syslog port / CLI cheatsheet.
- [ ] End-to-end test: fresh Multipass VM → `curl | sudo bash` → login works.

## P3 — Upgrade CLI (`zentryc-upgrade` v2)

- [ ] Rewrite `/usr/local/bin/zentryc-upgrade` around the manifest model (see §7.1 of plan).
- [ ] Fetch + GPG-verify manifest; compare `latest` to `.current_version`.
- [ ] Free-space check (≥ 5 GB) before pulling anything.
- [ ] Pre-upgrade snapshot: `pg_dump` + ClickHouse `BACKUP` → `/var/lib/zentryc/backups/pre-<OLD>-to-<NEW>/`.
- [ ] Pull images by digest; `cosign verify` each.
- [ ] Write `docker-compose.<NEW>.yml`, update `current` symlink.
- [ ] Run DB migrations in one-shot container; capture exit code.
- [ ] `docker compose up -d`; poll `/api/health` for 60 s.
- [ ] On failure: restore old symlink, restore DB snapshot if migrations ran, bring old stack back up, exit non-zero with diagnostic output.
- [ ] Support `--rollback` (previous version), `--version X.Y.Z` (pin), `--check` (report only), `--bundle /path/to/*.tar.gz` (air-gapped).
- [ ] Write `zentryc-autoupdate.service` + `.timer` (opt-in via `/etc/zentryc/autoupdate.enabled`).
- [ ] Prune images older than two successful versions after each upgrade.

## P4 — First-boot UX & CLI

- [ ] Add `seed_admin` CLI command: creates/updates `admin` user with `must_change_password=True`.
- [ ] Wire `must_change_password` check in FastAPI middleware → redirects to `/setup` for anything except `/setup`, `/login`, `/static/*`.
- [ ] Build `/setup` wizard pages (password change, admin email, timezone confirm).
- [ ] Enforce password strength on first change: min 12 chars, zxcvbn ≥ 3.
- [ ] Add `zentryc reset-admin` CLI (re-arms the force-change flow).
- [ ] Write `/usr/local/bin/zentryc` wrapper with subcommands: `status`, `logs`, `restart`, `backup`, `restore`, `version`, `support-bundle`, `reset-admin`.
- [ ] Print a banner on `/etc/motd` showing version + `zentryc --help`.

## P5 — Documentation & release

- [ ] Install guide (`docs/install.md`): the one-liner, prereqs, firewall notes, air-gapped path.
- [ ] Update-server SOP (`docs/update-server-runbook.md`): how to bring up your server, rotate keys, ship a release.
- [ ] Release process (`docs/release-sop.md`): tag → CI → cosign → manifest → publish → smoke test on staging appliance.
- [ ] Admin guide (`docs/admin.md`): CLI reference, backup/restore, troubleshooting.
- [ ] Upgrade guide (`docs/upgrade.md`): online, offline, rollback.
- [ ] Record a 3-minute install video for the website.
- [ ] Customer-facing changelog template.
- [ ] Update `Doc/SYSTEM_ASSESSMENT.md` to reference the new install path as canonical; keep bare-metal doc as "alternative".

## P6 — Hardening (post-v3.1)

- [ ] Evaluate `pyarmor` (or Cython compile) for `fastapi_app/correlation/`, `fastapi_app/detection/`, `fastapi_app/iocs/`.
- [ ] Replace self-signed cert flow with a `zentryc tls --domain x.y` helper using Let's Encrypt (HTTP-01 + nginx).
- [ ] Per-appliance registry credentials (mTLS) instead of shared pull account.
- [ ] Publish revocation list in manifest for compromised credentials.
- [ ] Optional SSO (OIDC) for admin login.
- [ ] Commission an external pentest against the appliance image.
- [ ] Implement per-release `min_installer_version` guard (reject upgrade if appliance installer is too old).

---

## Cross-cutting QA gates (every phase)

- [ ] Install on fresh Ubuntu 22.04 VM (4 GB, 30 GB disk) → admin/admin123 login works.
- [ ] Install on fresh Ubuntu 24.04 VM → same.
- [ ] Install behind an HTTP proxy (`HTTPS_PROXY=...`) → succeeds.
- [ ] Run installer twice on the same host → second run is a no-op or upgrade, never destructive.
- [ ] Upgrade v3.1.0 → v3.1.1 → `/logs/` still < 200 ms TTFB for 7d range.
- [ ] Forced failure during upgrade (kill migration) → stack rolls back to v3.1.0, data intact.
- [ ] `zentryc support-bundle` output contains no plaintext passwords or keys.
- [ ] `find / -name '*.py' -path '*/fastapi_app/*'` on the **host** returns nothing (only inside the container image layers).
- [ ] `docker exec zentryc-web sh` fails (no shell in image).

---

## Decisions still needed from you

- [ ] Confirm production domains for `updates.*`, `registry.*`, `downloads.*`.
- [ ] Confirm cosign signing strategy: **keyed** (we manage the key) or **keyless** (Fulcio/Rekor public log).
- [ ] Confirm default on auto-updates: **off** (current plan) or **on** with deferral window.
- [ ] Confirm whether v3.1 ships licensing or we defer to v3.2.
- [ ] Assign owners for P0–P5 (suggest: P0/P3 = platform eng, P1 = devops, P2 = platform eng, P4 = full-stack, P5 = tech writer).
