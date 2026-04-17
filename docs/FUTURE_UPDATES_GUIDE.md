# ZenAI Future Updates — Build & Push Guide

**Audience:** release engineer shipping any future ZenAI appliance update.
**Last updated:** 2026-04-17
**Related:** `UPDATE_SERVER_HANDOFF.md` (OTA API reference), `INSTALLATION_PLAN.md` (architecture).

This is the cookbook. Every future release follows the **same four steps** — there is no special case.

---

## 0. One-time setup (per release engineer workstation)

Do this once on the machine that will build and push releases.

```bash
# 1. Tools
sudo apt install -y rsync jq curl python3-cryptography

# 2. Secrets
sudo install -d -m 0700 /secure
# Copy the ZenAI Ed25519 private key here (from the vault), mode 0600:
sudo cp /path/to/zentryc-zenai.key /secure/zentryc-zenai.key
sudo chmod 0600 /secure/zentryc-zenai.key

# 3. Public key alongside (for local self-verification during build)
sudo cp /path/to/zentryc-zenai.pub /secure/zentryc-zenai.pub

# 4. Environment (add to ~/.bashrc or a sourced env file)
export ZENTRYC_API=https://zentryc.com/api/v1
export ZENTRYC_PRIVATE_KEY=/secure/zentryc-zenai.key
export ZENAI_PUBLIC_KEY=/secure/zentryc-zenai.pub
export ZENAI_SOURCE_DIR=/path/to/net-logs              # the source tree to ship
export ZENTRYC_ADMIN_EMAIL=<your-zenai-release@email>  # given by OTA admin
```

**Public-key fingerprint** (must match what's baked into appliances under `/opt/zenai/updater/keys/zentryc-zenai.pub`):

```bash
sha256sum /secure/zentryc-zenai.pub
# current: 202c75b46b55dd988dff08b2599a0eb1245d4b695d05a90f54702dc4bf63f1cd
```

If that fingerprint ever changes, every existing appliance will reject your next release until you ship them the new public key in a prior release. **Don't rotate the signing key without a migration plan.**

---

## 1. Build the package

```bash
# Pick a version — bump PATCH for bug fixes, MINOR for features, MAJOR for breaking.
export VERSION=1.0.2

# Optional: write a release note file so the changelog isn't one line.
cat > /tmp/release-notes-$VERSION.md <<'EOF'
- Fixed: N/A
- Added: ...
- Changed: ...

Data safety: no schema migrations. Appliance data preserved.
EOF
export ZENAI_RELEASE_NOTES=/tmp/release-notes-$VERSION.md

# Build
/home/net/Doc/ZENAI/build-zenai-release.sh $VERSION --severity normal
```

Output:

```
/tmp/zenai-update-1.0.2.zup        # the signed package
```

The script:
- rsyncs `$ZENAI_SOURCE_DIR` into a clean staging dir (excludes `venv/`, `node_modules/`, `__pycache__/`, `logs/`, `backups/`, `.env`, `db.sqlite3`)
- writes `manifest.json` with `"product": "zenai"` and the standard apply/rollback `steps[]`
- generates `checksums.sha256` over every file in the archive
- signs `manifest.json` with Ed25519 → `manifest.json.sig` (raw 64 bytes)
- **self-verifies** using `$ZENAI_PUBLIC_KEY` before tarring — aborts if the signature doesn't match
- tars everything into `/tmp/zenai-update-<VERSION>.zup`

### Data-safety invariants built into every release

The default `manifest.json.steps[]` emitted by the build script:

| Step | What it does |
|---|---|
| `stop_services` | Stops `zentryc-web`, `netlogs-web`, `zentryc-syslog`, `netlogs-syslog` (best-effort — missing services don't fail). |
| `backup` | Snapshots only the code tree (`/home/net/net-logs` excluding venv/logs/backups/node_modules/.git) to `/var/lib/zenai/updater/backups/pre-<release-id>/code.tar.gz`. **DB is never snapshotted or touched.** |
| `apply_code` | `rsync --delete` payload → `/home/net/net-logs/` but PRESERVES `.env`, `venv/`, `node_modules/`, `logs/`, `backups/`, `db.sqlite3`, `netedr_env/`. |
| `pip_install` | Optional; only runs if the venv exists. Skips silently on fresh Docker installs. |
| `start_services` | Starts all the app services back up. |
| `health_check` | Hits `http://127.0.0.1:8002/api/health/simple`; retries 6× with backoff. |

On any step failure the agent runs `rollback_steps[]` → `restore_backup` from the code snapshot + restart services. Worst case, the appliance ends up exactly where it was before the update was attempted. **DB content is outside the blast radius by design.**

---

## 2. Quick local inspection (optional but recommended)

```bash
ZUP=/tmp/zenai-update-$VERSION.zup
WORK=$(mktemp -d)
tar -xzf "$ZUP" -C "$WORK"

jq '.version, .product, .steps[].type' "$WORK/manifest.json"
[[ "$(stat -c%s "$WORK/manifest.json.sig")" == 64 ]] && echo "signature size OK"
( cd "$WORK" && sha256sum -c checksums.sha256 --quiet ) && echo "checksums OK"
sha256sum "$ZUP"
rm -rf "$WORK"
```

If any of those fails — don't upload. Re-build.

---

## 3. Push to zentryc.com

### 3.1 Authenticate

```bash
read -rsp "Admin password: " PASS; echo
JWT=$(curl -fsS -X POST "$ZENTRYC_API/admin/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ZENTRYC_ADMIN_EMAIL\",\"password\":\"$PASS\"}" \
  | jq -r .token)
unset PASS
[[ -n "$JWT" && "$JWT" != "null" ]] || { echo "login failed"; exit 1; }
AUTH=(-H "Authorization: Bearer $JWT")
```

JWT expires in 24 h. Never write it to a file.

### 3.2 Upload — **only step that differs from a ZenPlus release is `-F product=zenai`**

```bash
curl -fsS -X POST "$ZENTRYC_API/admin/releases/create" "${AUTH[@]}" \
  -F "file=@/tmp/zenai-update-$VERSION.zup" \
  -F "version=$VERSION" \
  -F "product=zenai" \
  -F "changelog=$(cat $ZENAI_RELEASE_NOTES)" \
  -F "severity=normal" \
  -F "min_version=1.0.0" \
  | tee /tmp/release-$VERSION.json

RELEASE_ID=$(jq -r .id /tmp/release-$VERSION.json)
```

Common errors:

| HTTP | Meaning | Fix |
|---|---|---|
| `400 product must be one of ['ota', 'zenai']` | Typo in the `-F product=` | Use exactly `zenai` (lowercase) |
| `409 release zenai:vX already exists` | Version already uploaded | Bump patch; you can't re-use a version |
| `401/403` | JWT expired or no zenai permission | Re-authenticate; ask OTA admin for zenai release scope |
| `400 Invalid tar.gz` | Archive corrupted | Rebuild |

### 3.3 Publish

```bash
curl -fsS -X POST "$ZENTRYC_API/admin/releases/$RELEASE_ID/publish" "${AUTH[@]}"
```

The release is now visible to the rollout engine but NOT shipping to anyone yet.

### 3.4 Rollout — always canary first

```bash
# Canary → 100% of the "canary" rollout group (typically your internal lab appliances)
curl -fsS -X POST "$ZENTRYC_API/admin/rollouts" "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d "{
    \"release_id\":     \"$RELEASE_ID\",
    \"stage\":          \"canary\",
    \"target_group\":   \"canary\",
    \"target_pct\":     100,
    \"auto_promote\":   false,
    \"promote_after\":  \"24 hours\",
    \"max_failure_pct\": 5
  }" | tee /tmp/rollout-$VERSION.json

ROLLOUT_ID=$(jq -r .id /tmp/rollout-$VERSION.json)
```

Watch it:

```bash
watch -n 30 "curl -fsS '$ZENTRYC_API/admin/rollouts/$ROLLOUT_ID/status' ${AUTH[@]} | jq ."
```

After canary is green (e.g., 24 h with zero failures), promote:

```bash
# Stage 2 — 25% of "stable"
curl -fsS -X PATCH "$ZENTRYC_API/admin/rollouts/$ROLLOUT_ID" "${AUTH[@]}" \
  -H "Content-Type: application/json" -d '{"action":"promote"}'

# Stage 3 — 100%
curl -fsS -X PATCH "$ZENTRYC_API/admin/rollouts/$ROLLOUT_ID" "${AUTH[@]}" \
  -H "Content-Type: application/json" -d '{"action":"promote"}'
```

Abort:

```bash
curl -fsS -X PATCH "$ZENTRYC_API/admin/rollouts/$ROLLOUT_ID" "${AUTH[@]}" \
  -H "Content-Type: application/json" -d '{"action":"abort"}'
```

### 3.5 Confirm in the dashboard

Open `https://zentryc.com/ota/zenai/releases/$RELEASE_ID/`. You should see:

- The release metadata (version, size, SHA-256, severity, changelog)
- Rollout status (appliances targeted / downloading / applying / succeeded / failed / rolled-back)
- Per-appliance history with timestamps

---

## 4. What happens on each appliance

Once the release is published AND a rollout covers the appliance's `rollout_group`:

1. The appliance's `zenai-updater` agent makes its next check-in (≤ 15 min).
2. Server responds with `{"next_action": "update", "release": {...}}`.
3. Agent downloads the `.zup`, verifies size + SHA-256 + Ed25519 signature + inner checksums.
4. Agent runs `manifest.steps[]`. On any failure it runs `rollback_steps[]` and reports `rolled_back`.
5. Agent POSTs `/updates/report` with `status=success` and the new `current_version`.

The appliance admin can also force a sync from the UI:

- Go to `https://<appliance>/system/updates/`
- Click **Sync now** — forces an immediate check-in.
- If a release is offered, click **Apply update** to pull / verify / install it right now instead of waiting for the next 15-min cycle.

---

## 5. Versioning rules

| Component | Version scheme | Tracked where |
|---|---|---|
| OTA release version | SemVer: `MAJOR.MINOR.PATCH` starting at `1.0.0` | `-F version=` in upload; `manifest.json.version` |
| App display version | Independent (currently 3.0.0 from legacy netlogs) | `fastapi_app/__version__.py` |

You can change `fastapi_app/__version__.py` as part of a release to make the new code visible to the user on the `/system/updates/` page, but that's cosmetic — the OTA release version is the authoritative one.

**Rules:**

- Never re-use a version number. Even if a push fails mid-way, bump to the next PATCH.
- Never ship a release with schema-changing DB migrations unless you've coordinated with the customer and explicitly listed the migration in `manifest.migrations[]`.
- Canary ALWAYS before production. Never push straight to the `stable` group.
- Every release must be reproducible: tag the source commit, keep the build log.

---

## 6. Emergency procedures

### A release is shipping but broken — stop it

```bash
# Stop further appliances from picking it up
curl -fsS -X PATCH "$ZENTRYC_API/admin/rollouts/$ROLLOUT_ID" "${AUTH[@]}" \
  -H "Content-Type: application/json" -d '{"action":"abort"}'
```

Already-applied appliances: they're running the new version. Ship a **forward fix** (new patch release) rather than trying to roll them back remotely. Appliances always keep their last-successful-code-tarball in `/var/lib/zenai/updater/backups/pre-<release-id>/` and the local admin can restore it manually if needed:

```bash
# ON THE APPLIANCE, as root:
cd /var/lib/zenai/updater/backups/
ls -t                         # newest first
sudo systemctl stop zentryc-web zentryc-syslog netlogs-web netlogs-syslog
sudo tar -xzf pre-<id>/code.tar.gz -C /home/net/
sudo systemctl start zentryc-web zentryc-syslog netlogs-web netlogs-syslog
```

### The signing key is suspected compromised

1. Generate a new keypair (see `build-zenai-release.sh` header).
2. Ship the new **public** key to every appliance as a tiny release signed with the **old** key (so they accept it). This release's `apply_code` must drop the new pub key into `/opt/zenai/updater/keys/zentryc-zenai.pub`.
3. Wait for 100% of the fleet to apply that release.
4. Retire the old key; all future releases use the new key.

Do this in rehearsal on a lab fleet before attempting it in production.

### An appliance is completely offline and needs a manual update

For air-gapped or firewalled sites:

```bash
# On the release workstation, build as usual then copy the .zup to the appliance.
scp /tmp/zenai-update-$VERSION.zup admin@<appliance>:/tmp/

# On the appliance (admin account with sudo):
sudo -u zenai-updater \
  /opt/zenai/updater/agent once --force \
  # (future enhancement: --bundle flag; for now, drop the file into
  # /var/lib/zenai/updater/staging/ and trigger the agent)
```

---

## 7. Before every push — checklist

- [ ] Source tree is at the expected commit; `git status` is clean.
- [ ] `ZENAI_SOURCE_DIR` points to it.
- [ ] `$VERSION` is newer than any previously uploaded version.
- [ ] Private key path is correct and readable.
- [ ] `ZENAI_PUBLIC_KEY` fingerprint matches what's on appliances (see §0).
- [ ] The build script's **local self-verify** passed (`[build] signature verified locally`).
- [ ] Manifest inspection (§2) looks sane — you recognise the steps and the excludes.
- [ ] You have a rollback plan if canary fails.
- [ ] Someone else knows you're pushing (buddy system).

Once all those are green: §3. Otherwise: don't.

---

## 8. File locations reference

| What | Where |
|---|---|
| Build script | `/home/net/Doc/ZENAI/build-zenai-release.sh` |
| Public key (ship with appliance) | `/home/net/Doc/ZENAI/zentryc-zenai.pub` |
| Private key (vault) | `/home/net/secure/zentryc-zenai.key` (on your build workstation only) |
| Agent source | `/home/net/net-logs/deploy/updater/zenai-updater.py` |
| Agent install script | `/home/net/net-logs/deploy/updater/install-updater.sh` |
| Agent systemd unit | `/home/net/net-logs/deploy/updater/zenai-updater.service` |
| Appliance state file | `/opt/zenai/updater/state.json` (on each appliance) |
| Appliance log | `/opt/zenai/updater/logs/updater.log` |
| Appliance backups | `/var/lib/zenai/updater/backups/` |
| Web UI | `https://<appliance>/system/updates/` |

---

*Questions? OTA admin. Problems during a push? Abort the rollout first, then debug.*
