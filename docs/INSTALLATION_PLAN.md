# Zentryc Appliance — Installation & Update Plan

**Document owner:** Product / Platform
**Status:** Revised v1.1 — 2026-04-17  (supersedes the self-hosted registry plan in v1.0)
**Target release:** Zentryc Appliance v3.1 ("One-Line Install")

> **Update (v1.1):** The OTA channel is the existing `zentryc.com` server rather than a
> newly-provisioned private Docker registry. Updates flow via the ZenAI channel
> (`product=zenai`) as documented in `UPDATE_SERVER_HANDOFF.md` and
> `FUTURE_UPDATES_GUIDE.md`. Sections 3.1, 5, 6, 7 of this plan are kept for
> reference but the authoritative install+update path is the ZenAI OTA pipeline.
> The `/system/updates/` UI tab on each appliance is the admin-facing surface.

---

## 1. Product vision

Ship Zentryc as a **self-contained, locked-down SOAR/SIEM appliance** that a customer can stand up with a single command on any fresh Ubuntu 22.04/24.04 server with internet access, and that receives signed updates from **our own remote update server** for the lifetime of the device.

**Success criteria**

1. Fresh Ubuntu server → fully functional Zentryc in **≤ 10 minutes** using **one command**.
2. First-login credentials are **`admin` / `admin123`**, with a forced password change prompt on first use.
3. Customer **cannot read our core Python source** on the appliance filesystem.
4. Running `zentryc-upgrade` pulls the latest signed build from **our update server** with automatic rollback on failure.
5. No manual post-install steps, no external registry accounts, no per-customer secrets to hand out.

---

## 2. Architecture decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| **Install mode** | Docker all-in-one, code baked into signed images | Fastest install, clean uninstall, code lock, reproducible |
| **Code protection** | Bytecode-only images (`.pyc`, source stripped), read-only rootfs containers | No plaintext `.py` on disk, no shell into containers |
| **Syslog performance** | `network_mode: host` for the syslog collector container | Zero NAT overhead; preserves 514/UDP line-rate ingest |
| **Update transport** | Private Docker registry + signed manifest hosted on **our** update server | Full control, offline-capable, signature verified |
| **Update trigger** | `zentryc-upgrade` CLI (manual) + optional daily systemd timer (opt-in) | Customer keeps control, auto-update is a choice |
| **Signing** | Cosign keyless-signed images + GPG-signed manifest | Industry standard, verifiable offline |
| **Default login** | `admin` / `admin123`, force-change on first login | Matches request; safe because of force-change |
| **Credential storage** | Passwords hashed (argon2id) in Postgres, secrets in `/etc/zentryc/secrets.env` (root-only) | Encrypted at rest |

---

## 3. High-level architecture

```
┌─────────────────────── Customer network ────────────────────────┐
│                                                                  │
│   [Firewalls / Switches] ──514/UDP──▶  ┌──────────────────┐     │
│                                         │                  │     │
│   [Admin browser] ──443/TCP──▶          │  Zentryc         │     │
│                                         │  Appliance       │     │
│                                         │  (Ubuntu LTS)    │     │
│                                         └──────┬───────────┘     │
│                                                │                 │
└────────────────────────────────────────────────┼─────────────────┘
                                                 │ HTTPS
                                                 │ (signed manifest + image pulls)
                                                 ▼
                             ┌─────────────────────────────────────┐
                             │   Zentryc Update Server (OURS)      │
                             │                                     │
                             │  • updates.zentryc.io/manifest.json │
                             │    (GPG-signed, versioned)          │
                             │                                     │
                             │  • registry.zentryc.io              │
                             │    (private Docker registry v2,     │
                             │     cosign-signed images)           │
                             │                                     │
                             │  • downloads.zentryc.io             │
                             │    (installer script + public keys) │
                             └─────────────────────────────────────┘
```

### 3.1 On the appliance

| Component | Container | Image tag pattern | Notes |
|---|---|---|---|
| Web / API | `zentryc-web` | `registry.zentryc.io/zentryc/web:v3.1.0` | FastAPI, bytecode-only, read-only rootfs |
| Syslog collector | `zentryc-syslog` | `registry.zentryc.io/zentryc/syslog:v3.1.0` | `network_mode: host`, CAP_NET_BIND_SERVICE |
| PostgreSQL | `zentryc-postgres` | `postgres:16-alpine` (pinned digest) | Volume: `/var/lib/zentryc/postgres` |
| ClickHouse | `zentryc-clickhouse` | `clickhouse/clickhouse-server:24.x` (pinned) | Volume: `/var/lib/zentryc/clickhouse` |
| Redis | `zentryc-redis` | `redis:7-alpine` (pinned) | Volume: `/var/lib/zentryc/redis` |
| PgBouncer | `zentryc-pgbouncer` | `bitnami/pgbouncer:1.x` (pinned) | Internal only |
| Nginx (TLS) | `zentryc-nginx` | `registry.zentryc.io/zentryc/nginx:v3.1.0` | Self-signed cert on first boot |

Only three host-level items:
- `/opt/zentryc/` — compose file, secrets, state markers (owner root:root, 0700)
- `/etc/zentryc/secrets.env` — generated passwords, registry pull key (root:root, 0600)
- `/usr/local/bin/zentryc{,-upgrade,-ctl}` — appliance CLI wrappers
- `zentryc.service` systemd unit — wraps `docker compose up -d` with restart policies

---

## 4. The one-line installer

### 4.1 Customer experience

```bash
curl -fsSL https://downloads.zentryc.io/install.sh | sudo bash
```

That's it. Within ~8 minutes, the customer sees:

```
╔══════════════════════════════════════════════════════════╗
║          Zentryc Appliance v3.1.0 is ready               ║
╠══════════════════════════════════════════════════════════╣
║  Web UI:        https://10.0.0.42                         ║
║  Login:         admin / admin123  ← change on first login ║
║  Syslog input:  10.0.0.42:514/UDP                         ║
║                                                           ║
║  Manage:        sudo zentryc status | logs | restart      ║
║  Update:        sudo zentryc-upgrade                      ║
╚══════════════════════════════════════════════════════════╝
```

### 4.2 What `install.sh` does (14 stages)

| # | Stage | Detail |
|---|---|---|
| 1 | Sanity | root check, Ubuntu 22.04+/24.04, ≥4 GB RAM, ≥30 GB free disk, internet reachable |
| 2 | GPG trust | Fetch and pin Zentryc public signing key from `downloads.zentryc.io/zentryc.asc` |
| 3 | Verify installer | Re-download `install.sh.sig`, verify before proceeding (self-verification) |
| 4 | Base packages | `apt install -y ca-certificates curl gnupg jq ufw cron` |
| 5 | Docker | Install Docker CE + compose plugin via Docker's APT repo (pinned) |
| 6 | Host tuning | `sysctl` UDP buffer 26 MB; file descriptors 1 M; enable `cgroup v2` if absent |
| 7 | Registry login | Use an **embedded, appliance-wide pull-only credential** to `docker login registry.zentryc.io` |
| 8 | Fetch manifest | `curl https://updates.zentryc.io/manifest.json` → verify GPG signature → extract latest stable version |
| 9 | Pull images | `docker pull` every image at pinned digest from the manifest |
| 10 | Cosign verify | `cosign verify` each pulled image against Zentryc public key |
| 11 | Bootstrap config | Generate `/etc/zentryc/secrets.env`: Postgres pw, ClickHouse pw, SECRET_KEY, TLS self-signed cert |
| 12 | Seed admin | Run `zentryc-web migrate && zentryc-web seed-admin --username admin --password admin123 --force-change` |
| 13 | Launch | `systemctl enable --now zentryc.service` (which runs `docker compose up -d`) |
| 14 | Wait & verify | Poll `/api/health` until green (max 180 s); print summary |

Installer is **idempotent**: running it again on an installed host performs an upgrade instead.

### 4.3 Permissions & security at install time

- Script requires `root` (fails early otherwise).
- UFW firewall rules added: `22/tcp`, `80/tcp`, `443/tcp`, `514/udp` — everything else denied inbound.
- Registry pull credential is **pull-only, per-release rotated**, not a human account.
- All secrets written with `umask 077`.
- `/opt/zentryc` mode 0700, owned by root.
- No world-readable `.env` — Docker reads `/etc/zentryc/secrets.env` via `env_file`.

---

## 5. Code-lock strategy (protecting our core IP)

Goal: a customer with full root on the appliance cannot trivially recover our Python source.

| Layer | Technique |
|---|---|
| 1 | **Bytecode-only images**: build stage runs `python -OO -m compileall`, then `find . -name '*.py' -delete` before the final image layer |
| 2 | **Stripped `.pyc`** with `PYTHONDONTWRITEBYTECODE=1` at runtime so nothing is regenerated on disk |
| 3 | **Read-only rootfs** on the `zentryc-web` and `zentryc-syslog` containers (`read_only: true` in compose, `tmpfs` for `/tmp`) |
| 4 | **No shell in final images**: base on `gcr.io/distroless/python3` where possible; otherwise remove `/bin/sh`, `bash`, package manager |
| 5 | **Obfuscated module names** in sensitive modules (optional, post-v3.1): `pyarmor` or `cython` compilation of detection rules and correlation engine |
| 6 | **Encrypted config for licence/detection rules**: customer-visible rules fine, core detection IP encrypted at rest, decrypted in-memory only |
| 7 | **Image signing**: cosign-signed so the customer cannot substitute their own image with injected debug code |

Realistic honesty (document this in internal notes): determined reverse-engineering of `.pyc` with tools like `uncompyle6` is possible. Layers 5–6 raise the bar; they don't make it impossible. The plan below includes a Phase-2 task for `pyarmor` on the IP-sensitive modules.

---

## 6. Update server (YOUR remote server) — what to set up

This is the piece **you** have to stand up. It is three HTTPS services behind one domain (`updates.zentryc.io` — pick your real domain).

### 6.1 Components to deploy on the update server

| Service | Software | Port | Purpose |
|---|---|---|---|
| A | Docker Registry v2 | 443 (behind nginx) | Hosts `zentryc/web`, `zentryc/syslog`, `zentryc/nginx` images |
| B | Static file server (nginx) | 443 | Serves `install.sh`, `install.sh.sig`, `zentryc.asc`, `manifest.json`, `manifest.json.sig` |
| C | (optional) CDN | — | Cloudflare or similar for install.sh / public keys if many appliances |

### 6.2 One-time setup on the update server

```bash
# 1. Reverse proxy + TLS
apt install nginx certbot python3-certbot-nginx
certbot --nginx -d updates.zentryc.io -d registry.zentryc.io -d downloads.zentryc.io

# 2. Docker registry
docker run -d --restart=always --name registry \
  -v /srv/registry:/var/lib/registry \
  -v /srv/registry-auth:/auth \
  -e REGISTRY_AUTH=htpasswd \
  -e REGISTRY_AUTH_HTPASSWD_REALM="Zentryc Registry" \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  -p 127.0.0.1:5000:5000 \
  registry:2

# Create a pull-only account for appliances:
htpasswd -Bbn zentryc-appliance "<long-random-readonly-token>" > /srv/registry-auth/htpasswd

# 3. Static downloads root
mkdir -p /var/www/downloads.zentryc.io /var/www/updates.zentryc.io
# place: install.sh, install.sh.sig, zentryc.asc
# place: manifest.json, manifest.json.sig
```

Nginx vhosts (summary):

- `registry.zentryc.io` → proxy_pass to `127.0.0.1:5000` (Docker registry), HTTPS only
- `downloads.zentryc.io` → static from `/var/www/downloads.zentryc.io/`
- `updates.zentryc.io` → static from `/var/www/updates.zentryc.io/`

### 6.3 Release workflow (what you run to ship a new version)

On your **build machine** (not the update server):

```bash
# 1. Build & tag
export VERSION=v3.1.1
docker build -f docker/web.Dockerfile -t registry.zentryc.io/zentryc/web:$VERSION .
docker build -f docker/syslog.Dockerfile -t registry.zentryc.io/zentryc/syslog:$VERSION .
docker build -f docker/nginx.Dockerfile -t registry.zentryc.io/zentryc/nginx:$VERSION .

# 2. Push
docker login registry.zentryc.io -u zentryc-publisher  # push-capable account
docker push registry.zentryc.io/zentryc/web:$VERSION
docker push registry.zentryc.io/zentryc/syslog:$VERSION
docker push registry.zentryc.io/zentryc/nginx:$VERSION

# 3. Sign with cosign (keyless or keyed)
cosign sign --key cosign.key registry.zentryc.io/zentryc/web:$VERSION
cosign sign --key cosign.key registry.zentryc.io/zentryc/syslog:$VERSION
cosign sign --key cosign.key registry.zentryc.io/zentryc/nginx:$VERSION

# 4. Generate manifest.json with image digests
./tools/make-manifest.sh $VERSION > manifest.json
gpg --detach-sign --armor --output manifest.json.sig manifest.json

# 5. Publish manifest
scp manifest.json manifest.json.sig update-server:/var/www/updates.zentryc.io/
```

### 6.4 `manifest.json` schema

```json
{
  "schema_version": 1,
  "channel": "stable",
  "latest": "v3.1.1",
  "released_at": "2026-05-04T10:00:00Z",
  "min_installer_version": "v3.1.0",
  "images": {
    "web":    "registry.zentryc.io/zentryc/web@sha256:aaaa...",
    "syslog": "registry.zentryc.io/zentryc/syslog@sha256:bbbb...",
    "nginx":  "registry.zentryc.io/zentryc/nginx@sha256:cccc..."
  },
  "services": {
    "postgres":   "postgres:16-alpine@sha256:dddd...",
    "clickhouse": "clickhouse/clickhouse-server:24.8@sha256:eeee...",
    "redis":      "redis:7-alpine@sha256:ffff...",
    "pgbouncer":  "bitnami/pgbouncer:1.22@sha256:gggg..."
  },
  "migrations": ["2026_05_01_add_correlation_index"],
  "release_notes_url": "https://downloads.zentryc.io/release-notes/v3.1.1.html",
  "rollback_to": "v3.1.0"
}
```

Pinning every image by **digest** (not just tag) means the appliance pulls exactly the bytes the signature covers.

---

## 7. Appliance update flow

### 7.1 `zentryc-upgrade` (manual)

```bash
sudo zentryc-upgrade              # upgrade to channel latest
sudo zentryc-upgrade --version v3.1.1
sudo zentryc-upgrade --rollback   # revert to previous successful version
sudo zentryc-upgrade --check      # show available version, don't apply
```

Steps:

1. Fetch `manifest.json` + `.sig`, verify with pinned Zentryc public key.
2. Check `latest` ≠ current installed version; bail with "already current" if equal.
3. `pg_dump` + ClickHouse `BACKUP TABLE` snapshots to `/var/lib/zentryc/backups/pre-<OLD>-to-<NEW>/`.
4. `docker pull` every digest in `manifest.images` + `manifest.services`.
5. `cosign verify` each pulled Zentryc image.
6. Write new compose file to `/opt/zentryc/docker-compose.<NEW>.yml`, symlink `current` → new.
7. Run DB migrations inside a one-shot container: `docker run --rm ...zentryc/web:NEW python -m fastapi_app.migrate`.
8. `docker compose up -d` → watch `/api/health` for 60 s.
9. On success: write `/opt/zentryc/.current_version=NEW`, keep `.previous_version=OLD`.
10. On failure: revert symlink, `docker compose up -d` on old compose, restore DB if migrations ran, alert.

### 7.2 (Optional) automatic updates

A systemd timer `zentryc-autoupdate.timer` running daily at 03:00 that runs `zentryc-upgrade --check && zentryc-upgrade` **only if** the customer opted in via `/etc/zentryc/autoupdate.enabled`. Opt-in, never default.

### 7.3 Air-gapped upgrades

Every release also produces `zentryc-<VERSION>.bundle.tar.gz` (images as `docker save` + manifest + signature). Customer copies it to the appliance and runs:

```bash
sudo zentryc-upgrade --bundle /path/to/zentryc-v3.1.1.bundle.tar.gz
```

Same verification path, just no network fetch.

---

## 8. Appliance CLI surface

Wrapper installed to `/usr/local/bin/zentryc` (and symlinks for convenience):

```
zentryc status                    # service + health summary
zentryc logs [web|syslog|db]      # tail container logs
zentryc restart [service]         # restart one or all
zentryc backup                    # ad-hoc pg+ch snapshot to /var/lib/zentryc/backups
zentryc restore <backup-dir>      # restore from snapshot
zentryc version                   # current version + channel
zentryc support-bundle            # collect redacted diagnostics tarball
zentryc-upgrade [flags]           # upgrade (see §7.1)
zentryc reset-admin               # re-seed admin/admin123 force-change (locked out recovery)
```

A restricted sudoers file (`/etc/sudoers.d/zentryc`) lets a future `zentryc-operator` Unix user run these without a full root shell.

---

## 9. First-boot experience (admin/admin123)

1. Installer seeds: `admin` / `admin123` with `must_change_password = true`, `email = null`.
2. First successful login at `https://<appliance>` redirects to `/setup` wizard:
   - Step 1: **Change password** (required, min 12 chars, zxcvbn score ≥ 3).
   - Step 2: Admin email (for future password reset).
   - Step 3: Timezone confirmation (pre-filled from system).
   - Step 4: Optional: licence key entry (if licensing is introduced).
3. Only after Step 1 completes is the `must_change_password` flag cleared. Attempting to use any other page before then 302s back to `/setup`.
4. `zentryc reset-admin` (CLI) re-arms the same flow if the admin ever gets locked out.

---

## 10. Security & hardening checklist

- [ ] Containers run as non-root UIDs (`USER 10001` in Dockerfiles).
- [ ] `no-new-privileges: true` and `cap_drop: [ALL]` with explicit `cap_add` only where needed (syslog gets `NET_BIND_SERVICE`).
- [ ] Read-only rootfs on all Zentryc containers, `tmpfs` for `/tmp` and `/run`.
- [ ] Network segmentation: internal compose network `zentryc-internal` (no inbound from host) + `zentryc-edge` (only nginx attached).
- [ ] TLS default: self-signed v3.1, Let's Encrypt helper (`zentryc tls --domain x.y`) in v3.2.
- [ ] Argon2id password hashing; bcrypt migration for existing users.
- [ ] Rate limiting on `/login` via Redis (existing).
- [ ] Audit log of every admin action (existing `audit_logs` table).
- [ ] Docker daemon: `userns-remap`, `live-restore: true`, log rotation capped at 100 MB × 5 per container.
- [ ] Disk watchdog already in place (`deploy/zentryc-disk-cleanup.*`); keep, just point at new paths.
- [ ] Fail2ban optional add-on for SSH.
- [ ] Registry pull credentials rotated per release; revocation list cached on each appliance.

---

## 11. Rollout plan (phases)

| Phase | Goal | Exit criteria |
|---|---|---|
| **P0 — Build pipeline** | Bytecode-only Dockerfiles, multi-stage builds, cosign signing wired in CI | `docker run zentryc/web:test` launches, `find /app -name '*.py'` returns zero |
| **P1 — Update server** | Registry + static site + GPG key published on your server | `curl https://updates.zentryc.io/manifest.json` returns a valid signed manifest |
| **P2 — Installer v3.1** | New `install.sh` that does the 14 stages; admin/admin123 seeding | Fresh Ubuntu VM → working Zentryc in one command |
| **P3 — Upgrade CLI** | `zentryc-upgrade` with rollback + air-gapped bundle support | Upgrade v3.1.0 → v3.1.1 works; forced failure triggers rollback cleanly |
| **P4 — First-boot wizard** | Forced password change, email capture | Manual QA on 3 fresh installs |
| **P5 — Docs & signoff** | Public install docs, runbook, SOP for shipping releases | Tech writer + ops signoff |
| **P6 — Hardening (v3.2)** | `pyarmor` on IP modules, Let's Encrypt helper, opt-in auto-update | Pen test report; no P0/P1 findings |

Timeline target: **P0–P5 in 4 weeks**, P6 in the following sprint.

---

## 12. Risks & open questions

| Risk | Mitigation |
|---|---|
| Customer's firewall blocks egress to `registry.zentryc.io` | Document air-gapped bundle flow (§7.3); offer proxy config for `HTTPS_PROXY`. |
| Pull-only registry credential leaked from an appliance | Per-release rotated; revocation list published in manifest; plans for per-appliance mTLS in v3.3. |
| `.pyc` reverse-engineering | Phase-6 `pyarmor` on the high-value modules; the rest is acceptable (web handlers, utilities). |
| Update server outage | Cloudflare in front of static assets; registry replicated to a warm standby; air-gapped path still works. |
| Disk fills during upgrade | Pre-upgrade free-space check (≥ 5 GB); prune old images after successful switch. |
| Migration fails mid-upgrade | DB snapshot taken in step 3 of §7.1 is restored before rolling the containers back. |

**Open questions to confirm before P0:**

1. Is the real update-server domain confirmed? (e.g., `updates.zentryc.io`)
2. Registry host: co-located with updates, or separate? (plan assumes separate subdomain on same box)
3. Licensing: do we need a per-appliance licence key in v3.1, or defer to v3.2?
4. Auto-update default: off (current plan) or on with 7-day deferral window?

---

## 13. Artefacts produced by this plan

When the plan is executed, these files will exist in the repo:

```
net-logs/
├── install.sh                           # REWRITTEN — 14-stage one-liner
├── docker/
│   ├── web.Dockerfile                   # NEW — multi-stage, bytecode-only
│   ├── syslog.Dockerfile                # NEW — same pattern
│   └── nginx.Dockerfile                 # NEW — prebuilt Vite assets + conf
├── deploy/
│   └── appliance/
│       ├── docker-compose.appliance.yml # NEW — production compose
│       ├── zentryc.service              # NEW — systemd wrapper
│       ├── zentryc-autoupdate.timer     # NEW — opt-in
│       ├── zentryc-autoupdate.service   # NEW
│       ├── zentryc                      # NEW — CLI wrapper
│       ├── zentryc-upgrade              # REWRITTEN — manifest-driven
│       └── update-server/
│           ├── nginx.conf               # NEW — reference vhost for your server
│           ├── make-manifest.sh         # NEW — release-tool
│           └── README.md                # NEW — "run these commands on your update server"
└── Doc/
    ├── INSTALLATION_PLAN.md             # this document
    └── TODO.md                          # companion punch list
```

---

## 14. One-page summary for stakeholders

> **One command. Locked code. Your own update server.**
>
> `curl -fsSL https://downloads.zentryc.io/install.sh | sudo bash` turns any fresh Ubuntu LTS box into a production Zentryc appliance in under ten minutes. Login with **admin / admin123** (forced change on first use). All core code ships as signed Docker images with source stripped — customers see binaries, never `.py` files. Updates land via **your** private registry + signed manifest; `zentryc-upgrade` pulls, verifies, migrates, and auto-rolls-back on failure. Air-gapped sites get the same release as a signed tarball. Everything is idempotent, auditable, and reversible.

